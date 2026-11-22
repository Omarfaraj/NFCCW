"""
pcap/packet_builder.py - Forges Ethernet, IPv4, and TCP headers from scratch.
"""
import struct
import socket

def calculate_checksum(data: bytes) -> int:
    """
    Calculates the standard RFC 1071 Internet Checksum.
    Used for IPv4 and TCP headers to ensure data integrity.
    """
    if len(data) % 2 == 1:
        data += b'\x00' # Pad to even length
        
    s = sum(int.from_bytes(data[i:i+2], 'big') for i in range(0, len(data), 2))
    
    # Fold 32-bit sum into 16 bits
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
        
    return ~s & 0xffff

def build_ethernet_header(src_mac: bytes, dst_mac: bytes, ethertype: int = 0x0800) -> bytes:
    """Builds a 14-byte Ethernet II header (EtherType 0x0800 is IPv4)."""
    # !6s6sH = 6 bytes (dst), 6 bytes (src), 2 bytes (type)
    return struct.pack("!6s6sH", dst_mac, src_mac, ethertype)

def build_ipv4_header(src_ip: str, dst_ip: str, payload_len: int, protocol: int = 6) -> bytes:
    """Builds a 20-byte IPv4 header with a calculated checksum."""
    version_ihl = (4 << 4) | 5 # IPv4 (4), Header Length 5 words (20 bytes)
    dscp_ecn = 0
    total_len = 20 + payload_len
    identification = 54321
    flags_frag = 0
    ttl = 64
    
    src_ip_bytes = socket.inet_aton(src_ip)
    dst_ip_bytes = socket.inet_aton(dst_ip)
    
    # Pack header with 0 for the checksum field first
    header_without_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, dscp_ecn, total_len, identification, flags_frag,
        ttl, protocol, 0, src_ip_bytes, dst_ip_bytes
    )
    
    # Calculate checksum and repack
    checksum = calculate_checksum(header_without_checksum)
    return struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, dscp_ecn, total_len, identification, flags_frag,
        ttl, protocol, checksum, src_ip_bytes, dst_ip_bytes
    )

def build_tcp_header(src_port: int, dst_port: int, seq: int, ack: int, flags: int, payload: bytes) -> bytes:
    """Builds a standard 20-byte TCP header."""
    data_offset = (5 << 4) # 5 words = 20 bytes
    window = 8192
    urgent_ptr = 0
    
    # Pack without checksum (TCP checksums are complex as they require an IP pseudo-header,
    # but Wireshark will still parse the packet even if the TCP checksum is left as 0).
    return struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq, ack, data_offset, flags, window, 0, urgent_ptr
    ) + payload

def create_synthetic_packet(seq: int, ack: int, is_ack: bool, payload_str: str = "") -> bytes:
    """Helper to generate a full synthetic packet from our simulation."""
    payload = payload_str.encode('utf-8')
    
    # TCP Flags: ACK = 0x10, PSH = 0x08
    tcp_flags = 0x10 if is_ack else (0x10 | 0x08)
    
    tcp_segment = build_tcp_header(
        src_port=12345, dst_port=80, 
        seq=seq, ack=ack, flags=tcp_flags, payload=payload
    )
    
    ipv4_packet = build_ipv4_header(
        src_ip="192.168.1.100", dst_ip="192.168.1.200", payload_len=len(tcp_segment)
    ) + tcp_segment
    
    eth_frame = build_ethernet_header(
        src_mac=b'\x00\x11\x22\x33\x44\x55', 
        dst_mac=b'\xaa\xbb\xcc\xdd\xee\xff'
    ) + ipv4_packet
    
    return eth_frame