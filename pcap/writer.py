"""
pcap/writer.py - File streaming context manager for .pcap generation.
"""
import time
from .headers import get_global_header, get_packet_header

class PcapWriter:
    def __init__(self, filename: str):
        self.filename = filename
        self.file = None

    def __enter__(self):
        # Open in binary write mode ('wb')
        self.file = open(self.filename, 'wb')
        # Write the global header once at the start of the file
        self.file.write(get_global_header())
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.file:
            self.file.close()

    def write_packet(self, raw_bytes: bytes, ts_sec: int = None, ts_usec: int = None):
        """Writes a single Ethernet frame to the pcap file with a timestamp."""
        if ts_sec is None or ts_usec is None:
            now = time.time()
            ts_sec = int(now)
            ts_usec = int((now - ts_sec) * 1_000_000)
            
        length = len(raw_bytes)
        self.file.write(get_packet_header(ts_sec, ts_usec, length))
        self.file.write(raw_bytes)