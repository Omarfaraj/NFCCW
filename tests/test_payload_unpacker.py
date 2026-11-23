import gzip
import json
import struct
import zlib

from core.payload_unpacker import PacketPayloadCleaner, TCPStreamReassembler, clean_payload_to_text


def test_clean_payload_gzip_and_json_pretty_print():
    obj = {"status": "ok", "user": "admin", "roles": ["netsec", "analyst"]}
    raw_gzip = gzip.compress(json.dumps(obj).encode("utf-8"))

    res = clean_payload_to_text(raw_gzip)
    assert res["is_compressed"] is True
    assert res["compression"] == "gzip"
    assert res["formatted_json"] is not None
    assert json.loads(res["formatted_json"]) == obj
    assert "0000" in res["hex_dump"]


def test_clean_payload_zlib_and_http_gzip_body():
    body = json.dumps({"alert": "none"}).encode("utf-8")
    http_gzip = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n" + gzip.compress(body)

    res = clean_payload_to_text(http_gzip)
    assert res["is_compressed"] is True
    assert res["compression"] == "gzip"
    assert "HTTP/1.1 200 OK" in res["http_headers"]
    assert '"alert": "none"' in res["formatted_json"]

    raw_zlib = zlib.compress(b"GET /health HTTP/1.1\nHost: core.local")
    res_z = clean_payload_to_text(raw_zlib)
    assert res_z["is_compressed"] is True
    assert res_z["compression"] == "zlib"
    assert "GET /health HTTP/1.1" in res_z["filtered_text"]


def test_signature_scanner_and_strings_filter():
    mixed = b"\x00\x01\xffGET /login HTTP/1.1\r\nAuthorization: Bearer secret123\r\nuser=admin&password=hunter2\x00\xfe"
    res = clean_payload_to_text(mixed)

    labels = {hit["label"] for hit in res["signatures"]}
    assert "Auth Token" in labels
    assert "Cleartext Password" in labels
    assert any("Authorization: Bearer secret123" in s for s in res["strings"])


def test_tcp_stream_reassembler_orders_and_deduplicates():
    r = TCPStreamReassembler()
    # Out-of-order + duplicate retransmission
    assert r.add_segment("10.0.0.2", 50000, "10.0.0.1", 443, seq=200, payload=b"World") is True
    assert r.add_segment("10.0.0.2", 50000, "10.0.0.1", 443, seq=100, payload=b"Hello ") is True
    assert r.add_segment("10.0.0.2", 50000, "10.0.0.1", 443, seq=100, payload=b"Hello ") is False  # dup

    stitched = r.reassemble("10.0.0.2", 50000, "10.0.0.1", 443)
    assert stitched == b"Hello World"


def test_tcp_options_offset_strips_timestamps_before_tls_record():
    # Build IPv4 (20B) + TCP (32B with 12B NOP,NOP,Timestamp option) + TLSv1.2 App Data
    tls_record = b"\x17\x03\x03\x00\x05hello"
    tcp_options = b"\x01\x01\x08\x0a\xa2\x47\x32\xf2\x50\x31\x92\x37"  # 12 bytes
    data_offset = (8 << 4)  # 8 * 4 = 32 bytes TCP header
    tcp_hdr = struct.pack("!HHIIBBHHH", 54210, 443, 1000, 2000, data_offset, 0x18, 4096, 0, 0) + tcp_options
    ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp_hdr) + len(tls_record), 1, 0, 64, 6, 0, b"\x0a\x00\x00\x02", b"\x0a\x00\x00\x01")
    raw_ip = ip_hdr + tcp_hdr + tls_record

    meta, payload = PacketPayloadCleaner.extract_tcp_payload(raw_ip)
    assert meta["header_len"] == 32
    assert meta["options_len"] == 12
    assert meta["has_timestamps"] is True
    assert payload == tls_record  # Zero TCP option bleed!

    ctype, body = PacketPayloadCleaner.parse_tls_record_header(payload)
    assert ctype == "ApplicationData"
    assert body == b"hello"


def test_dns_qname_tls_sni_and_http2_detectors():
    # 1. DNS query for graph.facebook.com
    dns_hdr = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    qname = b"\x05graph\x08facebook\x03com\x00" + struct.pack("!HH", 1, 1)
    assert PacketPayloadCleaner.parse_dns_qname(dns_hdr + qname) == "graph.facebook.com"

    # 2. TLS Client Hello with SNI extension for graph.facebook.com
    host = b"graph.facebook.com"
    sni_list = struct.pack("!BH", 0, len(host)) + host
    sni_ext = struct.pack("!HHH", 0x0000, len(sni_list) + 2, len(sni_list)) + sni_list
    ch_body = b"\x03\x03" + (b"\xaa" * 32) + b"\x00" + struct.pack("!HH", 2, 0x009C) + b"\x01\x00" + struct.pack("!H", len(sni_ext)) + sni_ext
    hs = b"\x01" + len(ch_body).to_bytes(3, "big") + ch_body
    tls_ch = b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs
    assert PacketPayloadCleaner.parse_tls_sni(tls_ch) == "graph.facebook.com"
    assert 'server_name = "graph.facebook.com"' in PacketPayloadCleaner.to_human_readable(tls_ch)

    # 3. HTTP/2 preface & binary frame
    assert "HTTP/2 Connection Preface" in PacketPayloadCleaner.to_human_readable(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
    h2_settings = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
    assert "SETTINGS" in PacketPayloadCleaner.parse_http2_frame(h2_settings)

