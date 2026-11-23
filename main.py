"""
main.py - Entry point for the Network Flow Visualizer.
Hosts the HTML/JS frontend dashboard locally and exposes local network info.
"""
import argparse
import http.server
import json
import socket
import socketserver
import struct
import os
import sys

# Define the default port and the directory where index.html lives
PORT = 8080
DIRECTORY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui")


def detect_network_info():
    """Detect the host's active local IP, default gateway, and interface name."""
    local_ip = "127.0.0.1"
    gateway_ip = ""
    iface = "auto"
    hostname = socket.gethostname()

    # Read Linux routing table for default gateway & interface (no privileges needed)
    try:
        with open("/proc/net/route", "r", encoding="utf-8") as f:
            next(f)
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3 and parts[1] == "00000000":
                    iface = parts[0]
                    gw_hex = int(parts[2], 16)
                    gateway_ip = socket.inet_ntoa(struct.pack("<L", gw_hex))
                    break
    except Exception:
        pass

    # Determine outbound local IP via UDP socket routing lookup (sends zero packets)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        target = gateway_ip if gateway_ip and gateway_ip != "0.0.0.0" else "8.8.8.8"
        sock.connect((target, 80))
        local_ip = sock.getsockname()[0]
        sock.close()
    except Exception:
        try:
            local_ip = socket.gethostbyname(hostname)
        except Exception:
            pass

    if not gateway_ip or gateway_ip == "0.0.0.0":
        octets = local_ip.split(".")
        gateway_ip = f"{octets[0]}.{octets[1]}.{octets[2]}.1" if len(octets) == 4 else "127.0.0.1"

    return {
        "local_ip": local_ip,
        "gateway_ip": gateway_ip,
        "iface": iface,
        "hostname": hostname,
    }


class UIHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        # Force the server to look in the /ui folder
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def do_GET(self):
        if self.path.split("?", 1)[0] == "/api/network-info":
            payload = json.dumps(detect_network_info()).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        super().do_GET()

    def log_message(self, format, *args):
        # Suppress standard HTTP logging for a cleaner terminal output
        pass


def start_server(port: int = PORT):
    if not os.path.exists(os.path.join(DIRECTORY, "index.html")):
        print(f"❌ Error: Could not find 'index.html' in {DIRECTORY}")
        sys.exit(1)

    net = detect_network_info()
    # Allow address reuse so the script doesn't crash if restarted quickly
    socketserver.TCPServer.allow_reuse_address = True

    try:
        httpd = socketserver.TCPServer(("", port), UIHandler)
    except OSError as exc:
        print(f"❌ Port {port} is already in use ({exc}).")
        print(f"   Stop the existing process (e.g. `fuser -k {port}/tcp` or `pkill -f main.py`)")
        print(f"   or start on another port with: `python3 main.py --port {port + 1}`")
        sys.exit(1)

    with httpd:
        print("=======================================================")
        print(" 🌐 Network Flow & Congestion Control Workbench")
        print("=======================================================\n")
        print(f"📡 Detected Host: {net['local_ip']} (iface: {net['iface']}, gateway: {net['gateway_ip']})")
        print(f"🚀 Server is live! Open your browser and navigate to:")
        print(f"👉 http://localhost:{port}/index.html\n")
        iface_hint = f" --iface {net['iface']}" if net["iface"] != "auto" else ""
        print(f"💡 To stream live network traffic, run in another terminal:")
        print(f"   sudo -E $(which python3) live_bridge.py{iface_hint}\n")
        print("Press Ctrl+C to shut down the server.")

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n🛑 Shutting down server...")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Flow & Congestion Control Workbench web server.")
    parser.add_argument("--port", type=int, default=PORT, help=f"HTTP port to bind (default: {PORT})")
    args = parser.parse_args()
    start_server(port=args.port)