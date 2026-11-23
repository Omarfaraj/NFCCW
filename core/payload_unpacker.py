"""
core/payload_unpacker.py - Multi-stage payload unpacker & stateful TCP stream reassembler.

Grounded in:
- Tanenbaum (Computer Networks, Ch. 6): TCP sequence-number ordering & duplicate elimination
- Wireshark for Security Professionals (Ch. 7): Follow TCP/SSL Stream & 16-byte Hex/ASCII views
- Grokking Algorithms (Ch. 5 & 11): Hash-map O(1) signature lookup & Bloom-filter style matching
"""

from dataclasses import dataclass, field
import gzip
import json
import re
import struct
from typing import Dict, List, Optional, Tuple
import zlib


# Known protocol / security anomaly signatures for fast hash/token scanning
SIGNATURE_CATALOG: Dict[str, Tuple[str, str]] = {
    "authorization: bearer": ("Auth Token", "high"),
    "authorization: basic": ("Basic Creds", "high"),
    "password=": ("Cleartext Password", "high"),
    "pass=": ("Cleartext Password", "high"),
    "pass ": ("FTP/Cleartext PASS", "high"),
    "union select": ("SQL Injection", "critical"),
    "drop table": ("SQL Injection", "critical"),
    "<script>": ("XSS Payload", "high"),
    "../": ("Path Traversal", "medium"),
    "uid=0(root)": ("Root Shell Output", "critical"),
    "x-auth-session": ("Session Header", "medium"),
}

_PRINTABLE_RUN_RE = re.compile(rb"[\x20-\x7e]{4,}")


def strip_tls_record_header(raw_bytes: bytes) -> Tuple[bytes, bool]:
    """
    Stage A: Strip leading TLS record framing (0x17 0x03 0x01..0x04 <len>) if present.
    Returns (inner_bytes, stripped_flag).
    """
    if (
        len(raw_bytes) >= 5
        and raw_bytes[0] in (0x14, 0x16, 0x17)
        and raw_bytes[1] == 0x03
        and raw_bytes[2] in (0x01, 0x02, 0x03, 0x04)
    ):
        rec_len = (raw_bytes[3] << 8) | raw_bytes[4]
        if rec_len > 0 and len(raw_bytes) >= 5 + min(rec_len, len(raw_bytes) - 5):
            return raw_bytes[5 : 5 + rec_len], True
    return raw_bytes, False


def decompress_payload(data: bytes) -> Tuple[bytes, Optional[str]]:
    """
    Stage B: Auto-detect GZIP (0x1f 0x8b) or Zlib Deflate (0x78 0x9c/0xda/0x01)
    magic bytes and decompress cleanly.
    """
    if data.startswith(b"\x1f\x8b"):
        try:
            return gzip.decompress(data), "gzip"
        except Exception:
            pass
    elif len(data) >= 2 and data[0] == 0x78 and data[1] in (0x01, 0x5E, 0x9C, 0xDA):
        try:
            return zlib.decompress(data), "zlib"
        except Exception:
            pass
    return data, None


def extract_printable_strings(data: bytes, min_len: int = 4) -> List[str]:
    """Stage C: Extract contiguous printable ASCII strings (length >= min_len)."""
    if min_len == 4:
        return [m.group(0).decode("ascii", errors="ignore") for m in _PRINTABLE_RUN_RE.finditer(data)]
    pattern = re.compile(rb"[\x20-\x7e]{" + str(max(1, min_len)).encode("ascii") + rb",}")
    return [m.group(0).decode("ascii", errors="ignore") for m in pattern.finditer(data)]


def detect_signatures(text: str) -> List[Dict[str, str]]:
    """Fast dictionary/hash-based anomaly & credential signature scanner."""
    lower = text.lower()
    hits: List[Dict[str, str]] = []
    seen = set()
    for sig, (label, severity) in SIGNATURE_CATALOG.items():
        if sig in lower and label not in seen:
            seen.add(label)
            hits.append({"signature": sig, "label": label, "severity": severity})
    return hits


def format_hex_dump(raw_bytes: bytes, max_bytes: int = 256) -> str:
    """Generate a Wireshark-style 16-byte aligned Offset | Hex | ASCII dump."""
    hex_lines: List[str] = []
    limit = min(len(raw_bytes), max_bytes)
    for i in range(0, limit, 16):
        chunk = raw_bytes[i : i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        hex_lines.append(f"{i:04x}   {hex_part:<48}  {ascii_part}")
    return "\n".join(hex_lines)


def clean_payload_to_text(raw_bytes: bytes) -> Dict[str, object]:
    """
    Multi-Stage Payload Unpacker Pipeline:
      Stage A: Strip TLS record header if present
      Stage B: Auto-decompress GZIP / Zlib payloads
      Stage C: Normalize UTF-8/ASCII & extract printable strings (len >= 4)
      Stage D: Parse HTTP headers, pretty-print JSON, and scan security signatures
    """
    if not raw_bytes:
        return {
            "tls_stripped": False,
            "is_compressed": False,
            "compression": None,
            "hex_dump": "",
            "filtered_text": "",
            "strings": [],
            "http_headers": [],
            "formatted_json": None,
            "signatures": [],
        }

    # Stage A: Record framing check
    stage_a, tls_stripped = strip_tls_record_header(raw_bytes)

    # Stage B: Compression detection (also checks after HTTP header separator \r\n\r\n)
    decompressed, compression = decompress_payload(stage_a)
    http_headers: List[str] = []
    body_bytes = decompressed

    header_sep = b"\r\n\r\n" if b"\r\n\r\n" in stage_a else (b"\n\n" if b"\n\n" in stage_a else None)
    if compression is None and header_sep is not None:
        head_part, rest_part = stage_a.split(header_sep, 1)
        head_text = head_part.decode("utf-8", errors="ignore")
        if any(head_text.startswith(p) for p in ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "HTTP/")):
            http_headers = [ln.strip() for ln in head_text.splitlines() if ln.strip()]
            rest_decomp, rest_comp = decompress_payload(rest_part)
            if rest_comp:
                compression = rest_comp
                body_bytes = rest_decomp
                decompressed = head_part + b"\n\n" + rest_decomp
            else:
                body_bytes = rest_part
                decompressed = stage_a

    # Stage C: Printable character normalization & strings extraction
    printable_chars = [
        chr(b) if (32 <= b <= 126 or b in (10, 13, 9)) else "."
        for b in decompressed
    ]
    filtered_text = "".join(printable_chars)
    strings = extract_printable_strings(decompressed, min_len=4)

    # Stage D: Pretty-print JSON & detect HTTP/security signatures
    if not http_headers:
        first_line = filtered_text.splitlines()[0] if filtered_text else ""
        if any(first_line.startswith(p) for p in ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "HTTP/")):
            http_headers = [ln for ln in filtered_text.splitlines() if ":" in ln or ln == first_line]

    formatted_json: Optional[str] = None
    for candidate in (body_bytes, decompressed):
        for opener in (b"{", b"["):
            idx = candidate.find(opener)
            if idx != -1:
                try:
                    parsed = json.loads(candidate[idx:].decode("utf-8", errors="ignore"))
                    formatted_json = json.dumps(parsed, indent=2)
                    break
                except Exception:
                    continue
        if formatted_json is not None:
            break

    signatures = detect_signatures(filtered_text)

    return {
        "tls_stripped": tls_stripped,
        "is_compressed": compression is not None,
        "compression": compression,
        "hex_dump": format_hex_dump(raw_bytes),
        "filtered_text": filtered_text,
        "strings": strings,
        "http_headers": http_headers,
        "formatted_json": formatted_json,
        "signatures": signatures,
    }


@dataclass
class StreamSegment:
    seq: int
    payload: bytes
    direction: str = "C2S"
    frame_no: int = 0
    psh: bool = False


@dataclass
class TCPStreamReassembler:
    """
    Stateful per-5-tuple (src_ip, src_port, dst_ip, dst_port, protocol) TCP stream reassembler.
    Orders segments by TCP sequence number, tracks PSH boundaries, and discards duplicate retransmissions.
    """

    streams: Dict[Tuple[str, int, str, int, str], Dict[int, StreamSegment]] = field(default_factory=dict)

    def add_segment(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        seq: int,
        payload: bytes,
        direction: str = "C2S",
        frame_no: int = 0,
        protocol: str = "TCP",
        tcp_flags: int = 0,
    ) -> bool:
        """Adds a segment; returns False if it is a duplicate retransmission."""
        if not payload:
            return False
        key = (src_ip, src_port, dst_ip, dst_port, protocol)
        bucket = self.streams.setdefault(key, {})
        if seq in bucket:
            return False  # Duplicate retransmission discarded
        bucket[seq] = StreamSegment(
            seq=seq,
            payload=payload,
            direction=direction,
            frame_no=frame_no,
            psh=bool(tcp_flags & 0x08),
        )
        return True

    def reassemble(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: str = "TCP",
    ) -> bytes:
        """Stitches all deduplicated segments for a 5-tuple in ascending sequence order."""
        bucket = self.streams.get((src_ip, src_port, dst_ip, dst_port, protocol), {})
        ordered = sorted(bucket.values(), key=lambda s: s.seq)
        return b"".join(seg.payload for seg in ordered)


_HTTP2_FRAME_TYPES: Dict[int, str] = {
    0x00: "DATA",
    0x01: "HEADERS",
    0x02: "PRIORITY",
    0x03: "RST_STREAM",
    0x04: "SETTINGS",
    0x05: "PUSH_PROMISE",
    0x06: "PING",
    0x07: "GOAWAY",
    0x08: "WINDOW_UPDATE",
    0x09: "CONTINUATION",
}


class PacketPayloadCleaner:
    """
    Dynamic protocol-layer slicer & payload unpacker:
    - Computes IPv4 IHL and TCP Data Offset dynamically so TCP options (e.g. RFC 7323 Timestamps
      01 01 08 0a ...) never bleed into application payloads.
    - Parses DNS RFC 1035 length-prefixed labels (e.g. graph.facebook.com).
    - Extracts TLS Client Hello Server Name Indication (SNI) hostnames.
    - Detects HTTP/2 binary framing & connection prefaces.
    - Decompresses GZIP (0x1f 0x8b) and Zlib Deflate (0x78 0x9c/0x01/0xda) streams.
    """

    @staticmethod
    def extract_tcp_payload(raw_ip_packet: bytes) -> Tuple[Dict[str, object], bytes]:
        """Dynamically calculates IPv4 IHL and TCP Data Offset so TCP options never bleed into payload."""
        if len(raw_ip_packet) < 20:
            return {"header_len": 0, "ip_header_len": 0, "options_len": 0}, b""

        ip_header_len = (raw_ip_packet[0] & 0x0F) * 4
        if ip_header_len < 20 or len(raw_ip_packet) < ip_header_len + 20:
            return {"header_len": 0, "ip_header_len": ip_header_len, "options_len": 0}, b""

        tcp_segment = raw_ip_packet[ip_header_len:]
        data_offset_byte = tcp_segment[12]
        tcp_header_len = ((data_offset_byte >> 4) & 0x0F) * 4
        if tcp_header_len < 20:
            tcp_header_len = 20

        src_port, dst_port, seq, ack = struct.unpack("!HHII", tcp_segment[0:12])
        flags = tcp_segment[13]
        options_bytes = tcp_segment[20 : min(tcp_header_len, len(tcp_segment))]
        payload = tcp_segment[tcp_header_len:] if len(tcp_segment) >= tcp_header_len else b""

        metadata: Dict[str, object] = {
            "src_port": src_port,
            "dst_port": dst_port,
            "seq": seq,
            "ack": ack,
            "flags": flags,
            "ip_header_len": ip_header_len,
            "header_len": tcp_header_len,
            "options_len": len(options_bytes),
            "has_timestamps": b"\x08\x0a" in options_bytes,
        }
        return metadata, payload

    @staticmethod
    def decompress_body(data: bytes) -> Tuple[bool, bytes]:
        """Detects and decompresses GZIP or ZLIB Deflate streams."""
        decompressed, alg = decompress_payload(data)
        return alg is not None, decompressed

    @staticmethod
    def parse_tls_record_header(data: bytes) -> Tuple[str, bytes]:
        """Strips the 5-byte TLS record header (Content-Type, Version, Length)."""
        if len(data) >= 5 and data[0] in (20, 21, 22, 23) and data[1] == 0x03 and data[2] in (0x01, 0x02, 0x03, 0x04):
            content_type_map = {
                20: "ChangeCipherSpec",
                21: "Alert",
                22: "Handshake",
                23: "ApplicationData",
            }
            c_type = content_type_map.get(data[0], f"Type({data[0]})")
            (length,) = struct.unpack("!H", data[3:5])
            record_body = data[5 : 5 + length]
            return c_type, record_body
        return "Raw", data

    @staticmethod
    def parse_dns_qname(payload: bytes) -> Optional[str]:
        """Extracts the primary domain name from a DNS wire packet (RFC 1035 length-prefixed labels)."""
        if len(payload) < 13:
            return None
        qdcount = struct.unpack("!H", payload[4:6])[0]
        if qdcount == 0 or qdcount > 16:
            return None
        pos = 12
        labels: List[str] = []
        while pos < len(payload):
            ln = payload[pos]
            if ln == 0:
                break
            if ln >= 64 or pos + 1 + ln > len(payload):
                return None
            label_bytes = payload[pos + 1 : pos + 1 + ln]
            if not all(33 <= b <= 126 for b in label_bytes):
                return None
            labels.append(label_bytes.decode("ascii", errors="ignore"))
            pos += 1 + ln
        return ".".join(labels) if labels else None

    @staticmethod
    def parse_tls_sni(data: bytes) -> Optional[str]:
        """Extracts the SNI server_name hostname from a TLS Client Hello record."""
        if len(data) < 43 or data[0] != 0x16 or data[1] != 0x03 or data[5] != 0x01:
            return None
        try:
            pos = 5 + 4 + 2 + 32  # Record(5) + HS Hdr(4) + Ver(2) + Random(32)
            if pos >= len(data):
                return None
            sid_len = data[pos]
            pos += 1 + sid_len
            if pos + 2 > len(data):
                return None
            cs_len = struct.unpack("!H", data[pos : pos + 2])[0]
            pos += 2 + cs_len
            if pos + 1 > len(data):
                return None
            comp_len = data[pos]
            pos += 1 + comp_len
            if pos + 2 > len(data):
                return None
            ext_total = struct.unpack("!H", data[pos : pos + 2])[0]
            pos += 2
            ext_end = min(len(data), pos + ext_total)
            while pos + 4 <= ext_end:
                ext_type, ext_len = struct.unpack("!HH", data[pos : pos + 4])
                pos += 4
                if ext_type == 0x0000 and pos + 5 <= ext_end:  # server_name extension
                    name_type = data[pos + 2]
                    name_len = struct.unpack("!H", data[pos + 3 : pos + 5])[0]
                    if name_type == 0 and pos + 5 + name_len <= len(data):
                        return data[pos + 5 : pos + 5 + name_len].decode("ascii", errors="ignore")
                pos += ext_len
        except Exception:
            return None
        return None

    @staticmethod
    def parse_http2_frame(data: bytes) -> Optional[str]:
        """Detects HTTP/2 connection preface or binary 9-byte frame headers."""
        if data.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"):
            return "HTTP/2 Connection Preface (PRI * HTTP/2.0)"
        if len(data) >= 9:
            frame_len = (data[0] << 16) | (data[1] << 8) | data[2]
            frame_type = data[3]
            flags = data[4]
            stream_id = struct.unpack("!I", data[5:9])[0] & 0x7FFFFFFF
            if frame_type in _HTTP2_FRAME_TYPES and frame_len <= len(data) - 9 and stream_id < 1_000_000:
                if frame_type in (0x04, 0x06, 0x08) or (frame_type in (0x00, 0x01) and stream_id > 0):
                    return (
                        f"HTTP/2 Binary Frame: {_HTTP2_FRAME_TYPES[frame_type]} "
                        f"(Stream={stream_id}, Flags=0x{flags:02x}, Len={frame_len}B)"
                    )
        return None

    @staticmethod
    def to_human_readable(raw_payload: bytes) -> str:
        """Converts arbitrary raw payload into clean, human-readable text."""
        if not raw_payload:
            return "[Empty Payload]"

        sni = PacketPayloadCleaner.parse_tls_sni(raw_payload)
        if sni:
            return f'TLS Client Hello — SNI Extension: server_name = "{sni}"'

        h2 = PacketPayloadCleaner.parse_http2_frame(raw_payload)
        if h2:
            return h2

        header_end = raw_payload.find(b"\r\n\r\n")
        if header_end != -1:
            headers = raw_payload[:header_end].decode("latin-1", errors="ignore")
            if any(headers.startswith(p) for p in ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "HTTP/")):
                body = raw_payload[header_end + 4 :]
                is_comp, decompressed_body = PacketPayloadCleaner.decompress_body(body)
                try:
                    json_obj = json.loads(decompressed_body.decode("utf-8"))
                    formatted_body = json.dumps(json_obj, indent=2)
                except Exception:
                    formatted_body = "".join(
                        chr(b) if 32 <= b <= 126 or b in (10, 13, 9) else "."
                        for b in decompressed_body
                    )
                return (
                    f"--- HTTP Headers ---\n{headers}\n\n"
                    f"--- Body ({'Decompressed GZIP' if is_comp else 'Plain'}) ---\n{formatted_body}"
                )

        is_comp, clean_data = PacketPayloadCleaner.decompress_body(raw_payload)
        try:
            json_obj = json.loads(clean_data.decode("utf-8"))
            prefix = "[Decompressed GZIP JSON]\n" if is_comp else ""
            return prefix + json.dumps(json_obj, indent=2)
        except Exception:
            pass

        return "".join(
            chr(b) if 32 <= b <= 126 or b in (10, 13, 9) else "."
            for b in clean_data
        )
