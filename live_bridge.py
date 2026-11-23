"""
live_bridge.py - Streams live Scapy packets and TCP cwnd telemetry over WebSockets.

Architecture:
- Elephant Flow Filter: requires sustained traffic (min packets + min bytes) before locking,
  preventing rapid lock/unlock thrashing on short-lived HTTPS "mice" connections.
- Pin/Hold Mode: UI can pin/unpin the active flow so idle periods never steal the lock.
- Producer-Consumer Batching: Scapy capture runs on a worker thread into a bounded lock-protected
  deque; an asyncio broadcaster drains and emits coalesced batches every ~60ms (~16 Hz) so the
  event loop and WebSocket heartbeats are never starved under heavy bursts.
"""

import argparse
import asyncio
import base64
from collections import deque
import json
import socket
import threading
import time
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

import websockets
from scapy.all import IP, TCP, UDP, sniff
from core.payload_unpacker import PacketPayloadCleaner

MSS_BYTES = 1460.0
SEQ_MOD = 1 << 32
SEQ_HALF = 1 << 31

# Elephant flow & stability tuning
FLOW_IDLE_TIMEOUT_SEC = 15.0
CANDIDATE_WINDOW_SEC = 3.0
MIN_PACKETS_TO_LOCK = 6
MIN_BYTES_TO_LOCK = 4096

# Producer-consumer & WebSocket tuning
BATCH_INTERVAL_SEC = 0.06  # ~16.6 Hz UI update cadence
MAX_PACKETS_PER_BATCH = 40
PACKET_BUFFER_MAXLEN = 400
CLIENT_QUEUE_MAXSIZE = 32
MAX_CAPTURE_BYTES = 1514
WS_PING_INTERVAL = 20
WS_PING_TIMEOUT = 30

TCP_FIN = 0x01
TCP_RST = 0x04
TCP_ACK = 0x10


def detect_local_ip() -> str:
    """Best-effort detection of the local machine's outbound IPv4 address."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


def inspect_tls_payload(payload_bytes: bytes, src_port: int, dst_port: int) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """Detect TLS record headers in live TCP payloads for Wireshark-style dissection."""
    if (
        len(payload_bytes) >= 5
        and payload_bytes[0] in (0x14, 0x16, 0x17)
        and payload_bytes[1] == 0x03
        and payload_bytes[2] in (0x01, 0x02, 0x03, 0x04)
    ):
        rec_type = payload_bytes[0]
        ver_map = {0x01: "TLSv1", 0x02: "TLSv1.1", 0x03: "TLSv1.2", 0x04: "TLSv1.3"}
        proto_name = ver_map.get(payload_bytes[2], "TLSv1.2")
        if rec_type == 0x17:
            return proto_name, {"mode": "tls", "encrypted": True, "isAppData": True, "live": True}
        hs_type = "Handshake"
        if rec_type == 0x14:
            hs_type = "Finished"
        elif len(payload_bytes) >= 6:
            hs_code = payload_bytes[5]
            hs_type = {1: "ClientHello", 2: "ServerHello", 16: "ClientKeyExchange"}.get(hs_code, "Handshake")
        return proto_name, {"mode": "tls", "encrypted": False, "isHandshake": True, "hsType": hs_type, "live": True}
    if (src_port == 443 or dst_port == 443) and len(payload_bytes) > 0:
        return "TLSv1.2", {"mode": "tls", "encrypted": True, "isAppData": True, "live": True}
    return None, None


def seq_diff(a: int, b: int) -> int:
    """Signed 32-bit modular difference (a - b) handling TCP sequence wraparound."""
    diff = (a - b) % SEQ_MOD
    return diff - SEQ_MOD if diff >= SEQ_HALF else diff


class TCPFlowTracker:
    """
    Locks onto a sustained ("elephant") TCP flow, estimates bytes-in-flight / cwnd (in MSS),
    and classifies congestion behavior (Tahoe-like vs Reno/CUBIC-like).

    - Ignores short-lived "mice" flows by requiring min_packets_to_lock AND min_bytes_to_lock
      within candidate_window_sec before locking.
    - Respects idle_timeout_sec (default 15s) and graceful FIN/RST teardown.
    - Supports manual Pin/Hold mode so the user can keep a flow locked across idle pauses.
    """

    def __init__(
        self,
        idle_timeout_sec: float = FLOW_IDLE_TIMEOUT_SEC,
        min_packets_to_lock: int = MIN_PACKETS_TO_LOCK,
        min_bytes_to_lock: int = MIN_BYTES_TO_LOCK,
        candidate_window_sec: float = CANDIDATE_WINDOW_SEC,
    ):
        self.idle_timeout_sec = idle_timeout_sec
        self.min_packets_to_lock = min_packets_to_lock
        self.min_bytes_to_lock = min_bytes_to_lock
        self.candidate_window_sec = candidate_window_sec
        self.pinned: bool = False
        self.pinned_pair: Optional[Tuple[str, str]] = None
        self.candidate_flows: Dict[Tuple[str, str, int, int], Dict[str, Any]] = {}
        self.reset()

    def reset(self, clear_pin: bool = False) -> None:
        self.target_flow: Optional[Tuple[str, str, int, int]] = None
        self.highest_seq: int = 0
        self.highest_ack: int = 0
        self.has_ack: bool = False
        self.last_ack: Optional[int] = None
        self.dup_ack_count: int = 0
        self.max_recent_cwnd: float = 0.0
        self.last_seen_ts: float = 0.0
        self.algorithm_guess: str = "Analyzing baseline..."
        if clear_pin:
            self.pinned = False
            self.pinned_pair = None

    def set_pinned(self, pinned: bool) -> None:
        self.pinned = bool(pinned)
        if not self.pinned:
            self.pinned_pair = None
        elif self.target_flow is not None:
            self.pinned_pair = (self.target_flow[0], self.target_flow[1])

    def pin_host_pair(self, src_ip: str, dst_ip: str) -> None:
        """Manually pin tracking to a chosen (src_ip, dst_ip) host pair from the UI."""
        self.reset(clear_pin=False)
        self.pinned = True
        self.pinned_pair = (src_ip, dst_ip)
        self.candidate_flows.clear()
        print(f"📌 Pinned flow filter to host pair: {src_ip} <-> {dst_ip}")

    def _prune_candidates(self, now: float) -> None:
        stale = [
            key
            for key, stats in self.candidate_flows.items()
            if (now - stats["last_seen"]) > self.candidate_window_sec
        ]
        for key in stale:
            del self.candidate_flows[key]

    def process_fields(
        self,
        src: str,
        dst: str,
        sport: int,
        dport: int,
        payload_len: int,
        tcp_flags: int,
        seq: int,
        ack: int,
        now: float,
    ) -> Tuple[Optional[float], Optional[str], bool, bool]:
        """Pure-data packet processor (also unit-testable without Scapy packet construction)."""
        # 1. Idle timeout check (skipped while flow is manually pinned)
        if (
            self.target_flow is not None
            and not self.pinned
            and (now - self.last_seen_ts) > self.idle_timeout_sec
        ):
            print(f"🔓 Flow idle timeout ({self.idle_timeout_sec:.0f}s); unlocking to track next sustained flow.")
            self.reset()

        # 2. Candidate qualification ("Elephant Flow" filter) when unlocked
        if self.target_flow is None:
            # If user pinned a specific host pair, lock onto the first active TCP flow matching that pair
            if self.pinned and self.pinned_pair is not None:
                p_src, p_dst = self.pinned_pair
                matches_pair = (src == p_src and dst == p_dst) or (src == p_dst and dst == p_src)
                if matches_pair and payload_len > 0:
                    self.target_flow = (src, dst, sport, dport)
                    self.highest_seq = (seq + payload_len) % SEQ_MOD
                    self.last_seen_ts = now
                    print(f"📌 Locked onto pinned host pair flow: {src}:{sport} -> {dst}:{dport}")
                else:
                    return None, None, False, False
            else:
                if payload_len <= 0 or (tcp_flags & (TCP_FIN | TCP_RST)):
                    return None, None, False, False

                if len(self.candidate_flows) > 128:
                    self._prune_candidates(now)

                flow_key = (src, dst, sport, dport)
                stats = self.candidate_flows.get(flow_key)
                if stats is None or (now - stats["last_seen"]) > self.candidate_window_sec:
                    stats = {
                        "pkts": 0,
                        "bytes": 0,
                        "start": now,
                        "last_seen": now,
                        "highest_seq": (seq + payload_len) % SEQ_MOD,
                    }
                    self.candidate_flows[flow_key] = stats

                stats["pkts"] += 1
                stats["bytes"] += payload_len
                stats["last_seen"] = now
                seg_end = (seq + payload_len) % SEQ_MOD
                if seq_diff(seg_end, stats["highest_seq"]) > 0:
                    stats["highest_seq"] = seg_end

                if stats["pkts"] >= self.min_packets_to_lock and stats["bytes"] >= self.min_bytes_to_lock:
                    self.target_flow = flow_key
                    self.highest_seq = stats["highest_seq"]
                    self.last_seen_ts = now
                    self.candidate_flows.clear()
                    print(
                        f"🔒 Locked onto sustained flow: {src}:{sport} -> {dst}:{dport} "
                        f"({stats['pkts']} pkts, {stats['bytes']} B)"
                    )
                else:
                    return None, None, False, False

        # 3. Track locked flow
        is_forward = (src, dst, sport, dport) == self.target_flow
        is_reverse = (dst, src, dport, sport) == self.target_flow
        if not (is_forward or is_reverse):
            return None, None, False, False

        self.last_seen_ts = now
        is_retrans = False
        is_dup_ack = False

        if is_forward:
            seg_end = (seq + payload_len) % SEQ_MOD
            if payload_len > 0 and seq_diff(seq, self.highest_seq) < 0:
                is_retrans = True
            if seq_diff(seg_end, self.highest_seq) > 0:
                self.highest_seq = seg_end
        elif is_reverse and (tcp_flags & TCP_ACK):
            if not self.has_ack:
                self.highest_ack = ack
                self.last_ack = ack
                self.has_ack = True
            else:
                if ack == self.last_ack and payload_len == 0:
                    self.dup_ack_count += 1
                    is_dup_ack = self.dup_ack_count >= 1
                elif seq_diff(ack, self.highest_ack) > 0:
                    self.highest_ack = ack
                    self.last_ack = ack
                    self.dup_ack_count = 0

        # 4. Graceful TCP teardown (FIN/RST) unlocks immediately unless pinned
        if tcp_flags & (TCP_FIN | TCP_RST):
            if not self.pinned:
                print(
                    f"🔓 Flow ended (FIN/RST): "
                    f"{self.target_flow[0]}:{self.target_flow[2]} -> {self.target_flow[1]}:{self.target_flow[3]}"
                )
                self.reset()
            return None, None, is_retrans, is_dup_ack

        if self.has_ack:
            bytes_in_flight = seq_diff(self.highest_seq, self.highest_ack)
            if bytes_in_flight > 0:
                estimated_cwnd_mss = min(100.0, bytes_in_flight / MSS_BYTES)

                if estimated_cwnd_mss > self.max_recent_cwnd:
                    self.max_recent_cwnd = estimated_cwnd_mss

                # Detect a sudden drop in estimated cwnd (loss event)
                if self.max_recent_cwnd > 10.0 and estimated_cwnd_mss < (self.max_recent_cwnd * 0.8):
                    drop_ratio = estimated_cwnd_mss / self.max_recent_cwnd
                    if drop_ratio < 0.25:
                        self.algorithm_guess = "Tahoe-like (Severe Collapse to 1)"
                    else:
                        self.algorithm_guess = "Reno/CUBIC-like (Fast Recovery Halving)"
                    self.max_recent_cwnd = estimated_cwnd_mss

                return estimated_cwnd_mss, self.algorithm_guess, is_retrans, is_dup_ack

        return None, None, is_retrans, is_dup_ack

    def process(self, pkt, now: float) -> Tuple[Optional[float], Optional[str], bool, bool]:
        """Processes a Scapy packet and returns (estimated_cwnd_mss, algorithm_guess, is_retrans, is_dup_ack)."""
        if TCP not in pkt or IP not in pkt:
            return None, None, False, False

        return self.process_fields(
            src=pkt[IP].src,
            dst=pkt[IP].dst,
            sport=int(pkt[TCP].sport),
            dport=int(pkt[TCP].dport),
            payload_len=len(pkt[TCP].payload),
            tcp_flags=int(pkt[TCP].flags),
            seq=int(pkt[TCP].seq),
            ack=int(pkt[TCP].ack),
            now=now,
        )


class LivePacketBridge:
    """Coordinates Scapy packet capture with batched Producer-Consumer WebSocket broadcast."""

    def __init__(
        self,
        iface: Optional[str] = None,
        max_bytes: int = MAX_CAPTURE_BYTES,
        idle_timeout: float = FLOW_IDLE_TIMEOUT_SEC,
        min_packets: int = MIN_PACKETS_TO_LOCK,
        min_bytes: int = MIN_BYTES_TO_LOCK,
        batch_interval: float = BATCH_INTERVAL_SEC,
    ):
        self.iface = iface
        self.max_bytes = max_bytes
        self.batch_interval = batch_interval
        self.local_ip = detect_local_ip()
        self.start_time = time.monotonic()
        self.flow_tracker = TCPFlowTracker(
            idle_timeout_sec=idle_timeout,
            min_packets_to_lock=min_packets,
            min_bytes_to_lock=min_bytes,
        )
        self.last_broadcast_flow: Optional[Tuple[str, str, int, int]] = None
        self.last_broadcast_pinned: bool = False

        # Producer-Consumer shared state (protected by _lock)
        self._lock = threading.Lock()
        self._pending_packets: Deque[Dict[str, Any]] = deque(maxlen=PACKET_BUFFER_MAXLEN)
        self._pending_telemetry: Optional[Dict[str, Any]] = None
        self._pending_flow_update: Optional[Dict[str, Any]] = None

        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.clients: Set[asyncio.Queue] = set()
        self.stop_event = threading.Event()

    def _build_flow_update_payload(self) -> Dict[str, Any]:
        cur_flow = self.flow_tracker.target_flow
        if cur_flow is not None:
            return {
                "type": "flow_update",
                "active": True,
                "pinned": self.flow_tracker.pinned,
                "src": cur_flow[0],
                "dst": cur_flow[1],
                "sport": cur_flow[2],
                "dport": cur_flow[3],
                "iface": self.iface or "auto",
            }
        return {
            "type": "flow_update",
            "active": False,
            "pinned": self.flow_tracker.pinned,
            "iface": self.iface or "auto",
        }

    def _enqueue_for_all(self, payload_json: str) -> None:
        """Runs on the asyncio event loop: fans out batched frame to all clients without blocking."""
        for q in list(self.clients):
            if q.full():
                try:
                    q.get_nowait()  # Drop oldest batch for slow client
                except asyncio.QueueEmpty:
                    pass
            try:
                q.put_nowait(payload_json)
            except asyncio.QueueFull:
                pass

    def scapy_callback(self, pkt) -> None:
        """Producer running on the Scapy worker thread. Never blocks the asyncio event loop."""
        if IP not in pkt:
            return

        now = time.monotonic()
        with self._lock:
            live_cwnd, cognition, is_retrans, is_dup_ack = self.flow_tracker.process(pkt, now)

            # Skip serialization overhead when no dashboard client is connected
            if not self.clients:
                return

            cur_flow = self.flow_tracker.target_flow
            cur_pinned = self.flow_tracker.pinned
            if cur_flow != self.last_broadcast_flow or cur_pinned != self.last_broadcast_pinned:
                self.last_broadcast_flow = cur_flow
                self.last_broadcast_pinned = cur_pinned
                self._pending_flow_update = self._build_flow_update_payload()

        ip_layer = pkt[IP]
        src_ip, dst_ip = ip_layer.src, ip_layer.dst
        has_tcp = TCP in pkt
        has_udp = UDP in pkt
        proto = "TCP" if has_tcp else ("UDP" if has_udp else "IP")

        src_port = int(pkt[TCP].sport) if has_tcp else (int(pkt[UDP].sport) if has_udp else 0)
        dst_port = int(pkt[TCP].dport) if has_tcp else (int(pkt[UDP].dport) if has_udp else 0)
        payload_bytes = bytes(pkt[TCP].payload) if has_tcp else (bytes(pkt[UDP].payload) if has_udp else b"")
        raw_bytes = bytes(pkt)[: self.max_bytes]

        crypto_meta: Dict[str, Any] = {"mode": "cleartext", "encrypted": False, "live": True}
        info_str = pkt.summary().replace("Ether / ", "")
        if has_tcp and payload_bytes:
            tls_proto, tls_meta = inspect_tls_payload(payload_bytes, src_port, dst_port)
            if tls_proto and tls_meta:
                proto = tls_proto
                crypto_meta = tls_meta
                sni = PacketPayloadCleaner.parse_tls_sni(payload_bytes)
                if sni:
                    crypto_meta["sni"] = sni
                    info_str = f'Client Hello (SNI: {sni}) — {info_str}'
        elif has_udp and (src_port == 53 or dst_port == 53) and payload_bytes:
            qname = PacketPayloadCleaner.parse_dns_qname(payload_bytes)
            if qname:
                proto = "DNS"
                crypto_meta["dnsQname"] = qname
                qr = "Response" if (len(payload_bytes) >= 3 and (payload_bytes[2] & 0x80)) else "Query"
                info_str = f"DNS {qr}: {qname}"

        if src_ip == self.local_ip:
            direction = "C2S"
        elif dst_ip == self.local_ip:
            direction = "S2C"
        else:
            direction = "C2S" if src_port > dst_port else "S2C"

        cleaned_preview = ""
        if payload_bytes and not crypto_meta.get("encrypted"):
            if crypto_meta.get("dnsQname"):
                cleaned_preview = f"DNS {crypto_meta['dnsQname']}"
            elif crypto_meta.get("sni"):
                cleaned_preview = f'TLS SNI: {crypto_meta["sni"]}'
            else:
                cleaned_preview = PacketPayloadCleaner.to_human_readable(payload_bytes)[:240]

        ui_packet = {
            "type": "packet",
            "time": round(now - self.start_time, 6),
            "src": src_ip,
            "dst": dst_ip,
            "srcPort": src_port,
            "dstPort": dst_port,
            "proto": proto,
            "length": len(pkt),
            "payloadLen": len(payload_bytes),
            "payloadText": cleaned_preview,
            "seqNum": int(pkt[TCP].seq) if has_tcp else 0,
            "ackNum": int(pkt[TCP].ack) if has_tcp else 0,
            "ipId": int(ip_layer.id) if ip_layer.id is not None else 0,
            "ipSum": int(ip_layer.chksum) if ip_layer.chksum is not None else 0,
            "tcpSum": int(pkt[TCP].chksum) if (has_tcp and pkt[TCP].chksum is not None) else 0,
            "flags": int(pkt[TCP].flags) if has_tcp else 0,
            "info": info_str,
            "badChecksum": False,
            "isRetrans": is_retrans,
            "isDupAck": is_dup_ack,
            "dir": direction,
            "iface": self.iface or "auto",
            "crypto": crypto_meta,
            "rawBytesB64": base64.b64encode(raw_bytes).decode("ascii"),
        }

        with self._lock:
            self._pending_packets.append(ui_packet)
            if live_cwnd is not None:
                self._pending_telemetry = {
                    "type": "telemetry",
                    "live_cwnd": round(live_cwnd, 3),
                    "cognition": cognition,
                }

    def drain_batch(self) -> Optional[Dict[str, Any]]:
        """Drains coalesced packets, telemetry, and flow state into one batch message."""
        with self._lock:
            if not self._pending_packets and self._pending_telemetry is None and self._pending_flow_update is None:
                return None

            packets: List[Dict[str, Any]] = []
            # If buffer accumulated more than MAX_PACKETS_PER_BATCH, keep the most recent frames
            while len(self._pending_packets) > MAX_PACKETS_PER_BATCH:
                self._pending_packets.popleft()
            while self._pending_packets:
                packets.append(self._pending_packets.popleft())

            telemetry = self._pending_telemetry
            self._pending_telemetry = None

            flow_update = self._pending_flow_update
            self._pending_flow_update = None

        return {
            "type": "batch",
            "packets": packets,
            "telemetry": telemetry,
            "flow_update": flow_update,
        }

    async def broadcast_loop(self) -> None:
        """Consumer running on the asyncio loop: flushes batched updates at a steady cadence."""
        while not self.stop_event.is_set():
            await asyncio.sleep(self.batch_interval)
            if not self.clients:
                continue
            batch = self.drain_batch()
            if batch is not None:
                self._enqueue_for_all(json.dumps(batch))

    def handle_client_command(self, raw_msg: str) -> None:
        """Handles bidirectional control commands from the web dashboard (pin/unpin/select/unlock)."""
        try:
            cmd = json.loads(raw_msg)
        except Exception:
            return
        if not isinstance(cmd, dict):
            return

        ctype = cmd.get("type")
        with self._lock:
            if ctype == "pin_flow":
                pinned = bool(cmd.get("pinned", True))
                self.flow_tracker.set_pinned(pinned)
                self.last_broadcast_pinned = self.flow_tracker.pinned
                self._pending_flow_update = self._build_flow_update_payload()
                state_str = "PINNED" if pinned else "UNPINNED"
                print(f"📌 Flow lock {state_str} by dashboard.")
            elif ctype == "unlock_flow":
                self.flow_tracker.reset(clear_pin=True)
                self.flow_tracker.candidate_flows.clear()
                self.last_broadcast_flow = None
                self.last_broadcast_pinned = False
                self._pending_flow_update = self._build_flow_update_payload()
                print("🔓 Flow unlocked manually by dashboard.")
            elif ctype == "select_flow":
                src = str(cmd.get("src", "")).strip()
                dst = str(cmd.get("dst", "")).strip()
                if src and dst:
                    self.flow_tracker.pin_host_pair(src, dst)
                    self.last_broadcast_flow = self.flow_tracker.target_flow
                    self.last_broadcast_pinned = self.flow_tracker.pinned
                    self._pending_flow_update = self._build_flow_update_payload()

    def start_sniffing(self) -> None:
        iface_msg = f" on {self.iface}" if self.iface else ""
        print(
            f"🦈 Scapy bound to network interface{iface_msg} "
            f"(min {self.flow_tracker.min_packets_to_lock} pkts / {self.flow_tracker.min_bytes_to_lock} B, "
            f"idle {self.flow_tracker.idle_timeout_sec:.0f}s)..."
        )
        sniff(
            iface=self.iface,
            prn=self.scapy_callback,
            store=False,
            stop_filter=lambda _: self.stop_event.is_set(),
        )

    async def handle_client(self, websocket) -> None:
        client_queue: asyncio.Queue = asyncio.Queue(maxsize=CLIENT_QUEUE_MAXSIZE)
        self.clients.add(client_queue)
        print(f"🟢 Dashboard connected ({len(self.clients)} active client(s)).")

        async def sender() -> None:
            while True:
                pkt_json = await client_queue.get()
                await websocket.send(pkt_json)

        async def receiver() -> None:
            async for message in websocket:
                if isinstance(message, str):
                    self.handle_client_command(message)

        try:
            with self._lock:
                tf = self.flow_tracker.target_flow
                hello = {
                    "type": "bridge_info",
                    "iface": self.iface or "auto",
                    "local_ip": self.local_ip,
                    "pinned": self.flow_tracker.pinned,
                    "target_flow": (
                        {"src": tf[0], "dst": tf[1], "sport": tf[2], "dport": tf[3]}
                        if tf
                        else None
                    ),
                }
            await websocket.send(json.dumps(hello))

            send_task = asyncio.create_task(sender())
            recv_task = asyncio.create_task(receiver())
            done, pending = await asyncio.wait(
                {send_task, recv_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            for task in done:
                # Re-raise unexpected errors while ignoring clean close
                exc = task.exception()
                if exc and not isinstance(exc, websockets.exceptions.ConnectionClosed):
                    raise exc
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            self.clients.discard(client_queue)
            print(f"🔴 Dashboard disconnected ({len(self.clients)} active client(s)).")

    async def serve(self, host: str, port: int) -> None:
        self.loop = asyncio.get_running_loop()
        sniffer_thread = threading.Thread(target=self.start_sniffing, daemon=True)
        sniffer_thread.start()
        broadcaster_task = asyncio.create_task(self.broadcast_loop())

        print(
            f"🚀 WebSocket server listening on ws://{host}:{port} "
            f"(batch={int(self.batch_interval * 1000)}ms, ping={WS_PING_INTERVAL}s/{WS_PING_TIMEOUT}s)"
        )
        try:
            async with websockets.serve(
                self.handle_client,
                host,
                port,
                ping_interval=WS_PING_INTERVAL,
                ping_timeout=WS_PING_TIMEOUT,
                max_queue=64,
            ):
                await asyncio.Future()
        finally:
            self.stop_event.set()
            broadcaster_task.cancel()
            await asyncio.gather(broadcaster_task, return_exceptions=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Live Scapy-to-WebSocket bridge for Network Flow Visualizer.")
    parser.add_argument("--host", default="localhost", help="WebSocket bind host (default: localhost)")
    parser.add_argument("--port", type=int, default=8765, help="WebSocket bind port (default: 8765)")
    parser.add_argument("--iface", default=None, help="Network interface to sniff (default: Scapy auto)")
    parser.add_argument("--max-bytes", type=int, default=MAX_CAPTURE_BYTES, help="Max raw bytes per packet sent to UI")
    parser.add_argument(
        "--idle-timeout",
        type=float,
        default=FLOW_IDLE_TIMEOUT_SEC,
        help=f"Seconds of inactivity before unlocking an unpinned flow (default: {FLOW_IDLE_TIMEOUT_SEC})",
    )
    parser.add_argument(
        "--min-packets",
        type=int,
        default=MIN_PACKETS_TO_LOCK,
        help=f"Min data packets before locking onto a candidate flow (default: {MIN_PACKETS_TO_LOCK})",
    )
    parser.add_argument(
        "--min-bytes",
        type=int,
        default=MIN_BYTES_TO_LOCK,
        help=f"Min payload bytes before locking onto a candidate flow (default: {MIN_BYTES_TO_LOCK})",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    bridge = LivePacketBridge(
        iface=args.iface,
        max_bytes=args.max_bytes,
        idle_timeout=args.idle_timeout,
        min_packets=args.min_packets,
        min_bytes=args.min_bytes,
    )
    try:
        asyncio.run(bridge.serve(args.host, args.port))
    except KeyboardInterrupt:
        print("\n🛑 Live bridge stopped.")


if __name__ == "__main__":
    main()
