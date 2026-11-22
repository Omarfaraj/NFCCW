"""
tests/test_pcap_export.py - Unit tests for synthetic Ethernet/IPv4/TCP packet and PCAP writing.
"""

import struct

from pcap.headers import get_global_header, get_packet_header
from pcap.packet_builder import calculate_checksum, create_synthetic_packet
from pcap.writer import PcapWriter


def test_pcap_headers_format():
    gh = get_global_header()
    assert len(gh) == 24
    magic, major, minor, _, _, snaplen, linktype = struct.unpack("<IHHiIII", gh)
    assert magic == 0xA1B2C3D4
    assert (major, minor) == (2, 4)
    assert snaplen == 65535
    assert linktype == 1

    ph = get_packet_header(1700000000, 123456, 60)
    assert len(ph) == 16
    assert struct.unpack("<IIII", ph) == (1700000000, 123456, 60, 60)


def test_synthetic_packet_and_ipv4_checksum():
    pkt = create_synthetic_packet(seq=100, ack=50, is_ack=False, payload_str="hello")
    # 14 (Ethernet) + 20 (IPv4) + 20 (TCP) + 5 (payload) = 59 bytes
    assert len(pkt) == 59
    ipv4_header = pkt[14:34]
    # RFC 1071 verification: checksum over header including its checksum field must equal 0
    assert calculate_checksum(ipv4_header) == 0


def test_pcap_writer_creates_valid_file(tmp_path):
    out_file = tmp_path / "capture.pcap"
    pkt1 = create_synthetic_packet(seq=1, ack=0, is_ack=False, payload_str="frame-1")
    pkt2 = create_synthetic_packet(seq=0, ack=1, is_ack=True)

    with PcapWriter(str(out_file)) as writer:
        writer.write_packet(pkt1, ts_sec=1000, ts_usec=100)
        writer.write_packet(pkt2, ts_sec=1000, ts_usec=200)

    raw = out_file.read_bytes()
    expected_size = 24 + (16 + len(pkt1)) + (16 + len(pkt2))
    assert len(raw) == expected_size
    assert raw[:4] == struct.pack("<I", 0xA1B2C3D4)
