"""
main.py - Entry point for the Network Flow Visualizer.
Hosts the HTML/JS frontend dashboard locally.
"""
import http.server
import socketserver
import os
import sys

# Define the port and the directory where index.html lives
PORT = 8080
DIRECTORY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui")

class UIHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        # Force the server to look in the /ui folder
        super().__init__(*args, directory=DIRECTORY, **kwargs)
        
    def log_message(self, format, *args):
        # Suppress standard HTTP logging for a cleaner terminal output
        pass

def start_server():
    if not os.path.exists(os.path.join(DIRECTORY, "index.html")):
        print(f"❌ Error: Could not find 'index.html' in {DIRECTORY}")
        sys.exit(1)

    # Allow address reuse so the script doesn't crash if restarted quickly
    socketserver.TCPServer.allow_reuse_address = True
    
    with socketserver.TCPServer(("", PORT), UIHandler) as httpd:
        print("=======================================================")
        print(" 🌐 Network Flow & Congestion Control Workbench")
        print("=======================================================\n")
        print(f"🚀 Server is live! Open your browser and navigate to:")
        print(f"👉 http://localhost:{PORT}/index.html\n")
        print("Press Ctrl+C to shut down the server.")
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n🛑 Shutting down server...")

if __name__ == "__main__":
    start_server()