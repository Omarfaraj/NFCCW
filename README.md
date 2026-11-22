# Network Flow & Congestion Control Workbench

Interactive visualizer and Python protocol engine for exploring Tanenbaum's Data Link Layer ARQ protocols, TCP congestion control (Tahoe vs. Reno), token-bucket traffic shaping, synthetic `.pcap` generation, and live Scapy packet capture.

## Features
- **ARQ Sliding Window Protocols** (`core/protocols/`): Stop-and-Wait (Protocol 3), Go-Back-N (Protocol 5), and Selective Repeat (Protocol 6) with circular sequence arithmetic (`core/buffer.py`) and retransmission timers (`core/timers.py`).
- **Congestion Control & Shaping** (`core/congestion/`): TCP Tahoe, TCP Reno (Fast Recovery), and Token Bucket.
- **PCAP Generator** (`pcap/`): Builds raw Ethernet II / IPv4 / TCP frames with RFC 1071 checksums and writes standard Wireshark-compatible `.pcap` files.
- **Interactive Web Workbench** (`main.py` + `ui/index.html`): Visualizes sliding windows, TCP `cwnd`/`ssthresh` curves, token-bucket dynamics, Wireshark-style packet dissection/filtering, and `.pcap` export.
- **Live Packet Capture & Telemetry** (`live_bridge.py`, `live_sniffer.py`): Streams live Scapy packets and estimated TCP `cwnd` telemetry over WebSockets (`ws://localhost:8765`) into the web dashboard, or maps active IP conversations in the terminal.

## Setup
```bash
pip install -r requirements.txt
```

## Usage
Start the web dashboard:
```bash
python3 main.py
# Open http://localhost:8080/index.html
```

(Optional) Stream live traffic into the dashboard (requires capture privileges):
```bash
sudo python3 live_bridge.py --iface eth0
```

(Optional) Run the standalone terminal topology mapper:
```bash
sudo python3 live_sniffer.py --iface eth0
```

## Running Tests
```bash
pytest -v
```
