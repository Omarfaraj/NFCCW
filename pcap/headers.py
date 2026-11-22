"""
pcap/headers.py - Libpcap binary header definitions.
"""
import struct

def get_global_header() -> bytes:
    """
    Returns the 24-byte Libpcap global header.
    Format: Magic Number, Major, Minor, Timezone, SigFigs, SnapLen, LinkType
    Magic Number 0xa1b2c3d4 indicates microsecond resolution.
    LinkType 1 indicates Ethernet.
    """
    # < indicates Little-Endian (standard for pcap headers on x86)
    return struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

def get_packet_header(ts_sec: int, ts_usec: int, length: int) -> bytes:
    """
    Returns the 16-byte header prepended to every captured frame in the file.
    Format: Timestamp Seconds, Timestamp Microseconds, Captured Length, Wire Length
    """
    return struct.pack("<IIII", ts_sec, ts_usec, length, length)