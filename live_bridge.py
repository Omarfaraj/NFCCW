"""
live_bridge.py - Streams live Scapy packets and TCP cwnd telemetry over WebSockets.
"""

import argparse
import asyncio
import base64
import json
import threading
import time
from typing import Dict, Optional, Set, Tuple

import websockets
from scapy.all import IP, TCP, UDP, sniff

MSS_BYTES = 1460.0
SEQ_MOD = 1 << 32
SEQ_HALF = 1 << 31
FLOW_IDLE_TIMEOUT_SEC = 10.0
CLIENT_QUEUE_MAXSIZE = 256
MAX_CAPTURE_BYTES = 1514

TCP_FIN = 0x01
TCP_RST = 0x04
TCP_ACK = 0x10


def seq_diff(a: int, b: int) -> int:
    """Signed 32-bit modular difference (a - b) handling TCP sequence wraparound."""
    diff = (a - b) % SEQ_MOD
    return diff - SEQ_MOD if diff >= SEQ_HALF else diff


class TCPFlowTracker:
    """
    Locks onto a high-volume TCP flow, estimates bytes-in-flight / cwnd (in MSS),
    and classifies congestion behavior (Tahoe-like vs Reno/CUBIC-like).
    Automatically unlocks on FIN/RST or idle timeout so new flows can be tracked.
    """

    def __init__(self, idle_timeout_sec: float = FLOW_IDLE_TIMEOUT_SEC):
        self.idle_timeout_sec = idle_timeout_sec
        self.reset()

    def reset(self) -> None:
        self.target_flow: Optional[Tuple[str, str, int, int]] = None
        self.highest_seq: int = 0
        self.highest_ack: int = 0
        self.has_ack: bool = False
        self.last_ack: Optional[int] = None
        self.dup_ack_count: int = 0
        self.max_recent_cwnd: float = 0.0
        self.last_seen_ts: float = 0.0
        self.algorithm_guess: str = "Analyzing baseline..."

    def process(self, pkt, now: float) -> Tuple[Optional[float], Optional[str], bool, bool]:
        """
        Processes a packet and returns:
            (estimated_cwnd_mss, algorithm_guess, is_retrans, is_dup_ack)
        """
        if TCP not in pkt or IP not in pkt:
            return None, None, False, False

        # Unlock stale flows automatically
        if self.target_flow is not None and (now - self.last_seen_ts) > self.idle_timeout_sec:
            print("🔓 Flow idle timeout reached; unlocking to track next heavy flow.")
            self.reset()

        src, dst = pkt[IP].src, pkt[IP].dst
        sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
        payload_len = len(pkt[TCP].payload)
        tcp_flags = int(pkt[TCP].flags)
        seq = int(pkt[TCP].seq)
        ack = int(pkt[TCP].ack)

        # Lock onto the first heavy data flow
        if self.target_flow is None and payload_len > 500:
            self.target_flow = (src, dst, sport, dport)
            self.highest_seq = (seq + payload_len) % SEQ_MOD
            self.last_seen_ts = now
            print(f"🔒 Locked onto flow: {src}:{sport} -> {dst}:{dport}")

        if self.target_flow is None:
            return None, None, False, False

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

        # Unlock after FIN/RST so subsequent flows can be observed
        if tcp_flags & (TCP_FIN | TCP_RST):
            print(f"🔓 Flow ended (FIN/RST): {self.target_flow[0]}:{self.target_flow[2]} -> {self.target_flow[1]}:{self.target_flow[3]}")
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


class LivePacketBridge:
    """Coordinates Scapy packet capture with bounded per-client WebSocket broadcast."""

    def __init__(self, iface: Optional[str] = None, max_bytes: int = MAX_CAPTURE_BYTES):
        self.iface = iface
        self.max_bytes = max_bytes
        self.start_time = time.monotonic()
        self.flow_tracker = TCPFlowTracker()
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.clients: Set[asyncio.Queue] = set()
        self.stop_event = threading.Event()

    def _enqueue_for_all(self, payload_json: str) -> None:
        """Runs on the asyncio event loop: fans out to every connected client without blocking."""
        for q in list(self.clients):
            if q.full():
                try:
                    q.get_nowait()  # Drop oldest frame for slow client
                except asyncio.QueueEmpty:
                    pass
            try:
                q.put_nowait(payload_json)
            except asyncio.QueueFull:
                pass

    def _broadcast(self, message: Dict) -> None:
        if not self.loop or not self.clients:
            return
        payload = json.dumps(message)
        self.loop.call_soon_threadsafe(self._enqueue_for_all, payload)

    def scapy_callback(self, pkt) -> None:
        if IP not in pkt:
            return

        now = time.monotonic()
        live_cwnd, cognition, is_retrans, is_dup_ack = self.flow_tracker.process(pkt, now)

        # Skip serialization overhead when no dashboard client is connected
        if not self.clients:
            return

        ip_layer = pkt[IP]
        src_ip, dst_ip = ip_layer.src, ip_layer.dst
        has_tcp = TCP in pkt
        has_udp = UDP in pkt
        proto = "TCP" if has_tcp else ("UDP" if has_udp else "IP")

        src_port = int(pkt[TCP].sport) if has_tcp else (int(pkt[UDP].sport) if has_udp else 0)
        dst_port = int(pkt[TCP].dport) if has_tcp else (int(pkt[UDP].dport) if has_udp else 0)
        payload_bytes = bytes(pkt[TCP].payload) if has_tcp else (bytes(pkt[UDP].payload) if has_udp else b"")
        raw_bytes = bytes(pkt)[: self.max_bytes]

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
            "payloadText": payload_bytes[:64].decode("utf-8", errors="replace") if payload_bytes else "",
            "seqNum": int(pkt[TCP].seq) if has_tcp else 0,
            "ackNum": int(pkt[TCP].ack) if has_tcp else 0,
            "ipId": int(ip_layer.id) if ip_layer.id is not None else 0,
            "ipSum": int(ip_layer.chksum) if ip_layer.chksum is not None else 0,
            "tcpSum": int(pkt[TCP].chksum) if (has_tcp and pkt[TCP].chksum is not None) else 0,
            "flags": int(pkt[TCP].flags) if has_tcp else 0,
            "info": pkt.summary().replace("Ether / ", ""),
            "badChecksum": False,
            "isRetrans": is_retrans,
            "isDupAck": is_dup_ack,
            "dir": "C2S" if src_port > dst_port else "S2C",
            "rawBytesB64": base64.b64encode(raw_bytes).decode("ascii"),
        }
        self._broadcast(ui_packet)

        if live_cwnd is not None:
            self._broadcast({
                "type": "telemetry",
                "live_cwnd": round(live_cwnd, 3),
                "cognition": cognition,
            })

    def start_sniffing(self) -> None:
        iface_msg = f" on {self.iface}" if self.iface else ""
        print(f"🦈 Scapy bound to network interface{iface_msg}. Waiting for a large TCP flow...")
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
        try:
            while True:
                pkt_json = await client_queue.get()
                await websocket.send(pkt_json)
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            self.clients.discard(client_queue)
            print(f"🔴 Dashboard disconnected ({len(self.clients)} active client(s)).")

    async def serve(self, host: str, port: int) -> None:
        self.loop = asyncio.get_running_loop()
        sniffer_thread = threading.Thread(target=self.start_sniffing, daemon=True)
        sniffer_thread.start()

        print(f"🚀 WebSocket server listening on ws://{host}:{port}")
        try:
            async with websockets.serve(self.handle_client, host, port):
                await asyncio.Future()
        finally:
            self.stop_event.set()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Live Scapy-to-WebSocket bridge for Network Flow Visualizer.")
    parser.add_argument("--host", default="localhost", help="WebSocket bind host (default: localhost)")
    parser.add_argument("--port", type=int, default=8765, help="WebSocket bind port (default: 8765)")
    parser.add_argument("--iface", default=None, help="Network interface to sniff (default: Scapy auto)")
    parser.add_argument("--max-bytes", type=int, default=MAX_CAPTURE_BYTES, help="Max raw bytes per packet sent to UI")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    bridge = LivePacketBridge(iface=args.iface, max_bytes=args.max_bytes)
    try:
        asyncio.run(bridge.serve(args.host, args.port))
    except KeyboardInterrupt:
        print("\n🛑 Live bridge stopped.")


if __name__ == "__main__":
    main()
