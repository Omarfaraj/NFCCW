    # Network Flow & Congestion Control Workbench (NFCCW)

    An interactive full-stack networking workbench and Python protocol engine for visualizing and inspecting the network stack end-to-end — from **Layer 2 Data-Link Sliding Windows**, **Layer 3 Routing (BFS vs. Dijkstra)**, and **Layer 4 TCP Congestion Control & Traffic Shaping**, to **Hybrid RSA/TLS Encryption**, **Multi-Stage Payload Unpacking (GZIP/JSON/DNS/SNI)**, **Wireshark-style 3-Pane Packet Dissection**, and **Live Scapy Packet Capture**.

    > **Theoretical & Tooling Grounding**
    > - Andrew S. Tanenbaum & David J. Wetherall, *Computer Networks* (5th ed. — Ch. 3 Data-Link ARQ, Ch. 5 Routing & Token Bucket QoS, Ch. 6 TCP Tahoe/Reno & Stream Reassembly, Ch. 8 Network Security & Hybrid TLS)
    > - Jessey Bullock & Jeff T. Parker, *Wireshark for Security Professionals* (Ch. 1–6 Filtering, OSI Subtrees & PCAP, Ch. 7 Decrypting SSL/TLS & Follow SSL Stream)
    > - Aditya Bhargava, *Grokking Algorithms* (Ch. 6–7 BFS & Dijkstra, Ch. 9 Dynamic Programming LCS, Ch. 11 Hash-Map Signature Matching)

    ---

    ## Features

    1. **Data-Link Sliding Window & In-Flight Link Pipeline** (`core/protocols/`, `ui/index.html` §1–2)
    - Compare **Stop-and-Wait (P3)**, **Go-Back-N (P5)**, and **Selective Repeat (P6)** with circular sequence wheels, `between(a, b, c)` wrap-around evaluator, retransmission timers, latency/jitter/loss sliders, and fault injection (*Drop Next Frame*, *Corrupt CRC*, *Drop Next ACK*).
    - Dynamic **Active Network Flow** endpoints auto-detected from your machine via `/api/network-info` (or synced to live Scapy flows with **Pin Flow** / **Unlock** controls).
    2. **Application Encryption & Wireshark SSL/TLS Decryptor** (`ui/index.html` §1 & §4)
    - Four transmit modes: **Cleartext (`HTTP/80`)**, **Stream XOR + HMAC-SHA256**, **Web Crypto AES-256-GCM**, and **Hybrid RSA-2048 / TLS 1.2 Handshake** (`Client Hello`, `Server Hello + Cert`, `Client Key Exchange` with RSA-encrypted 48-byte premaster secret, `Change Cipher Spec / Finished`, `Encrypted Application Data`).
    - Optional **GZIP (`0x1f 0x8b`)** payload compression before encryption.
    - Dedicated **SSL/TLS Decryptor** modal supporting `.pem`/`.key` paste or file upload, RSA premaster secret recovery, PRF session-key derivation, MAC/tamper error verification, and a two-tab **Raw TCP Stream** vs. **Decrypted TLS Stream** viewer.
    3. **TCP Congestion Control & Token Bucket Traffic Shaper** (`core/congestion/`, `ui/index.html` §3)
    - Side-by-side **TCP Tahoe vs. TCP Reno** (`cwnd` & `ssthresh` Slow Start, AIMD, Fast Retransmit on 3× Dup-ACK, Fast Recovery, RTO Timeout) plus live captured flow `cwnd` overlay.
    - Interactive **Token Bucket Shaper `(R, B)`** with animated bucket tank and burst duration formula `S = B / (M - R)`.
    4. **Wireshark 3-Pane Dissector, Payload Inspector Drawer & `.pcap` Export** (`pcap/`, `core/payload_unpacker.py`, `ui/index.html` §4)
    - Live display filter engine (`tls`, `tls.handshake`, `http`, `icmp`, `ospf`, `tcp.len > 0`, `crypto.encrypted == 1`, `tls.decrypted == 1`, `frame.bad_checksum == 1`).
    - Dynamic IPv4 `IHL` and TCP `Data Offset` parsing (strips RFC 7323 TCP Timestamp options cleanly with zero payload bleed), **DNS RFC 1035 QNAME** decoding, **TLS Client Hello SNI** extraction, and **HTTP/2** binary frame detection.
    - **Sliding Bottom Payload Inspector Drawer** (click any in-flight packet, double-click any Wireshark row, or click **Payload Drawer**) with **Raw Hex** (16-byte Wireshark dump), **Decrypted Text** (auto-decompressed GZIP/Zlib, HTTP headers, pretty-printed JSON, strings filter, and anomaly signature scanner), and **Stream Reassembly** (5-tuple `seq`-ordered client/server dialogue with duplicate stripping).
    - Export real Libpcap v2.4 `.pcap` files readable directly in desktop Wireshark.
    5. **Dynamic Network Layer Routing Mesh & LCS Payload Diff** (`ui/index.html` §5)
    - Interactive multi-router SVG canvas comparing **BFS / RIP** (fewest hops) vs. **Dijkstra / OSPF** (lowest latency) across 3 presets, with step-by-step distance tables, **Cable Cut Tool**, router crash/reboot convergence, animated **IPv4 TTL Exhaustion / Traceroute** (logging real **ICMP Type 11** & **OSPF LS Update** frames into Wireshark), and a **Dynamic Programming LCS** payload diff inspector.
    6. **Live Packet Capture & Telemetry Bridge** (`live_bridge.py`, `live_sniffer.py`)
    - Captures real traffic from your network interface with Scapy and streams batched WebSocket frames (~16 Hz producer–consumer pipeline) into the browser dashboard.
    - Includes an **Elephant Flow Qualification Filter** (ignores short-lived background "mice" flows) and bidirectional **Pin Flow** / **Unlock** control from the UI.

    ---

    ## Step-by-Step Setup (Run on Your Machine)

    ### Prerequisites
    - **Python 3.10+** (tested through Python 3.14)
    - **pip** (Python package manager)
    - A modern browser (Chrome, Edge, Firefox, or Safari)
    - *(Optional, for live sniffing)* Root/capture privileges on Linux/macOS (`sudo`), or [Npcap](https://npcap.com/) on Windows.

    ### Step 1: Clone the Repository
    ```bash
    git clone https://github.com/Omarfaraj/NFCCW.git
    cd NFCCW
    ```

    ### Step 2: Create a Virtual Environment & Install Dependencies
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate        # On Windows (PowerShell): .venv\Scripts\Activate.ps1
    pip install -r requirements.txt
    ```

    ### Step 3: Start the Web Dashboard (Terminal 1)
    ```bash
    python3 main.py
    ```
    - The server auto-detects your local IP, gateway, and active interface and starts on **`http://localhost:8080/index.html`**.
    - Need a different port? Pass `--port`:
    ```bash
    python3 main.py --port 8081
    ```
    - Open **`http://localhost:8080/index.html`** in your browser.
    *(All simulation, encryption, TLS decryption, routing mesh, and `.pcap` export features work immediately without root privileges.)*

    ### Step 4: (Optional) Connect Live Network Traffic (Terminal 2)
    To switch the dashboard badge from `LIVE SNIFFER OFFLINE` to **`LIVE SNIFFER CONNECTED`** and stream real traffic from your machine:

    1. **Find your active network interface name** (optional — `main.py` also prints it on startup):
    - **Linux:** `ip -br addr` (e.g., `wlan0`, `eth0`, `enp0s3`)
    - **macOS:** `ifconfig` (e.g., `en0`)
    - **Windows:** `ipconfig` (ensure Npcap is installed)
    2. **Start the Scapy-to-WebSocket bridge** using your active Python environment:
    ```bash
    # Linux / macOS (preserves your virtualenv / installed packages under sudo)
    sudo -E $(which python3) live_bridge.py --iface <your-interface>

    # Or let Scapy auto-detect the default interface:
    sudo -E $(which python3) live_bridge.py
    ```
    *(Optional tuning flags: `--idle-timeout 15`, `--min-packets 6`, `--min-bytes 4096`, `--port 8765`.)*
    3. **Verify in your browser:**
    - Within a few seconds the badge automatically turns green: **`LIVE SNIFFER CONNECTED`**.
    - Browse any website or run `curl -I https://example.com` in a third terminal to see live packets, DNS names, TLS SNI hostnames, and estimated `cwnd` stream in.
    - Use the **Live flows** dropdown and **Pin Flow** button in Section 1 to lock onto and hold any conversation.

    *(Optional on Linux — run `live_bridge.py` without `sudo` every time):*
    ```bash
    sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
    python3 live_bridge.py
    ```

    ### Step 5: (Optional) Standalone Terminal Topology Mapper
    ```bash
    sudo -E $(which python3) live_sniffer.py --iface <your-interface>
    ```

    ---

    ## Quick Interactive Walkthroughs

    ### A. Encrypt, Inspect & Decrypt a GZIP-Compressed TLS 1.2 JSON Flow
    1. In **Section 1 (Application Payload & Encryption Layer)**, select **Hybrid RSA / TLS 1.2**.
    2. Click the **`JSON + GZIP Response`** preset (this enables the **`GZIP (0x1f 0x8b)`** checkbox automatically).
    3. Click **Encrypt & Send Payload** — watch the 4-step TLS handshake (`Client Hello` → `Server Hello + Cert` → `Client Key Exch` → `CCS + Finished`) and the locked encrypted data frame fly across the pipeline.
    4. Click **SSL/TLS Decryptor** (header or Section 4):
    - Try **Test Wrong Key** to observe **`Decryption Failed / MAC Check Error`**.
    - Click **Load Server RSA Key** (or **Download .pem** and **Upload .key/.pem**) and click **Decrypt Captured Stream**.
    - The decryptor recovers the 48-byte premaster secret from `Client Key Exchange`, derives the 256-bit AES-GCM session key, verifies the GCM tag, auto-decompresses the GZIP stream, and displays clean formatted JSON in green.
    5. Double-click any frame in Wireshark (or click an in-flight packet) to inspect it inside the sliding **Payload Inspector Drawer** (`Raw Hex` | `Decrypted Text` | `Stream Reassembly`).

    ### B. Test Routing Failover & IPv4 TTL Expiry
    1. Jump to **5. Routing Mesh** in the top navigation bar.
    2. Click **Run BFS vs Dijkstra** to see RIP (`R1 → R4 → R8`, 90 ms) vs. OSPF (`R1 → R2 → R5 → R7 → R8`, 24 ms).
    3. Toggle **Cable Cut Tool: ON** and click link `R2—R5` to sever the fiber and watch Dijkstra re-converge in real time (while logging an OSPF LS Update into Wireshark).
    4. Set **Initial IPv4 TTL** to `2` and click **Send IPv4 Packet** (or **Run Traceroute**) to trigger **ICMP Time Exceeded (Type 11, Code 0)** frames captured in Section 4.

    ---

    ## Display Filter Cheat Sheet (Section 4)

    The Wireshark Display Filter supports standard `&&` / `||` expressions (no parentheses needed):

    | Goal | Filter Expression |
    | :--- | :--- |
    | All encrypted / TLS traffic | `tls` |
    | TLS handshake records only | `tls.handshake` |
    | Encrypted application data only | `crypto.encrypted == 1` |
    | Successfully decrypted frames | `tls.decrypted == 1` |
    | Cleartext HTTP payloads | `http` |
    | ICMP & TTL exceeded probes | `icmp` or `icmp.type == 11` |
    | OSPF topology updates | `ospf` |
    | Corrupt CRC / bad checksums | `frame.bad_checksum == 1` |
    | Retransmissions | `tcp.analysis.retransmission` |
    | Specific host on ports 443 or 8443 | `ip.addr == 10.20.3.216 && tcp.port == 443 && tls \|\| ip.addr == 10.20.3.216 && tcp.port == 8443 && tls` |

    ---

    ## Project Structure

    ```text
    .
    ├── main.py                    # Local HTTP server (ui/) + /api/network-info host auto-detection
    ├── live_bridge.py             # Scapy -> WebSocket live bridge (elephant filter, pinning, 16Hz batching)
    ├── live_sniffer.py            # Standalone terminal IP conversation mapper
    ├── ui/
    │   └── index.html             # Self-contained Aurora interactive web workbench (Sections 1–5 + Modals/Drawer)
    ├── core/
    │   ├── buffer.py              # Circular sequence arithmetic & sliding window buffer
    │   ├── channel.py             # Simulated lossy/delayed channel
    │   ├── timers.py              # Retransmission timers
    │   ├── payload_unpacker.py    # Dynamic TCP offset slicer, GZIP/Zlib unpacker, DNS/SNI/HTTP2 & 5-tuple reassembler
    │   ├── protocols/             # Stop-and-Wait, Go-Back-N, Selective Repeat
    │   └── congestion/            # TCP Tahoe, TCP Reno, Token Bucket
    ├── pcap/                      # Ethernet II / IPv4 / TCP binary builder & Libpcap writer
    ├── scenarios/                 # Link condition scenario configs
    ├── tests/                     # Pytest test suite (26 tests)
    ├── requirements.txt           # scapy, websockets, pytest
    └── vercel.json                # Static deployment config (ui/)
    ```

    ---

    ## Running Tests

    ```bash
    pytest -v
    ```
    Runs all **26 unit and integration tests** covering ARQ sliding window protocols, sequence wrap-around math, TCP Tahoe/Reno & Token Bucket, Libpcap `.pcap` export, live bridge elephant-flow qualification / Pin-Hold / WebSocket batching, dynamic TCP Timestamp options stripping, GZIP/Zlib auto-decompression, DNS QNAME, TLS SNI, HTTP/2 frame detection, and 5-tuple stream reassembly.

    ---

    ## Troubleshooting

    - **`OSError: [Errno 98] Address already in use` on `python3 main.py`**: Stop the earlier server (`pkill -f "main.py" || fuser -k 8080/tcp`) or run on another port (`python3 main.py --port 8081`).
    - **`LIVE SNIFFER OFFLINE`**: Ensure `live_bridge.py` is running in a second terminal and that you opened the dashboard at `http://localhost:8080/index.html` (or `http://127.0.0.1:8080/index.html`) — browsers block remote HTTPS pages from connecting to local `ws://localhost:8765`.
    - **`ModuleNotFoundError` when using `sudo`**: Always invoke `sudo -E $(which python3) live_bridge.py` so `sudo` uses your virtualenv Python rather than system Python.
    - **Why external HTTPS sites stay locked in the SSL Decryptor**: Real internet HTTPS servers (Google, GitHub, etc.) negotiate ephemeral ECDHE keys whose private keys only live on the remote server. Use Section 1's **Encryption Bar** (AES-256-GCM, Stream XOR, or Hybrid RSA / TLS 1.2) to run end-to-end key-based decryption, and use the **`Scope: Workbench Session`** toggle inside the decryptor modal to isolate your session from background internet traffic.
