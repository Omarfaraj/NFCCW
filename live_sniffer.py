"""
live_sniffer.py - Terminal live network topology mapper using Scapy.
Throttles screen redraws with ANSI escape codes to avoid CPU spikes and flicker.
"""

import argparse
from collections import Counter
import sys
import time
from typing import Tuple

from scapy.all import IP, sniff


class LiveTopologySniffer:
    def __init__(self, top_n: int = 15, refresh_interval: float = 0.5):
        self.top_n = top_n
        self.refresh_interval = refresh_interval
        self.conversations: Counter[Tuple[str, str]] = Counter()
        self.total_packets = 0
        self.last_render = 0.0

    def render(self) -> None:
        lines = [
            "\033[H\033[J=== 🌐 LIVE NETWORK TOPOLOGY MAPPER ===",
            f"Capturing live IP traffic... Total IP packets: {self.total_packets} (Ctrl+C to stop)\n",
            f"{'Host A':<18} <---> {'Host B':<18} : {'Packets'}",
            "-" * 55,
        ]
        for (host_a, host_b), count in self.conversations.most_common(self.top_n):
            lines.append(f"{host_a:<18} <---> {host_b:<18} : {count}")

        sys.stdout.write("\n".join(lines) + "\n")
        sys.stdout.flush()

    def packet_callback(self, packet) -> None:
        if IP not in packet:
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        edge = (src_ip, dst_ip) if src_ip <= dst_ip else (dst_ip, src_ip)
        self.conversations[edge] += 1
        self.total_packets += 1

        now = time.monotonic()
        if (now - self.last_render) >= self.refresh_interval:
            self.last_render = now
            self.render()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Live terminal network topology mapper.")
    parser.add_argument("--iface", default=None, help="Network interface to sniff (e.g., eth0)")
    parser.add_argument("--top", type=int, default=15, help="Number of top conversations to display")
    parser.add_argument("--interval", type=float, default=0.5, help="UI refresh interval in seconds")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    sniffer = LiveTopologySniffer(top_n=args.top, refresh_interval=args.interval)
    print("Initializing live capture... (Waiting for first IP packet)")
    try:
        sniff(iface=args.iface, prn=sniffer.packet_callback, store=False)
    except KeyboardInterrupt:
        sniffer.render()
        print(f"\n🛑 Capture stopped. Observed {len(sniffer.conversations)} unique host pairs.")


if __name__ == "__main__":
    main()
