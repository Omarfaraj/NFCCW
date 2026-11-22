"""
tests/test_congestion.py - Verification tests for TCP Tahoe, TCP Reno, and TokenBucket.
"""

from core.congestion.tcp_reno import RenoState, TCPReno
from core.congestion.tcp_tahoe import TahoeState, TCPTahoe
from core.congestion.token_bucket import TokenBucket


def test_tcp_tahoe():
    tahoe = TCPTahoe(initial_ssthresh=8)
    assert tahoe.state == TahoeState.SLOW_START
    assert tahoe.cwnd == 1.0

    # 1. Slow Start (exponential growth to ssthresh)
    for i in range(1, 8):
        tahoe.handle_ack(i)
    assert tahoe.state == TahoeState.CONGESTION_AVOIDANCE
    assert tahoe.cwnd == 8.0

    # 2. Congestion Avoidance (linear AIMD growth)
    for i in range(8, 16):
        tahoe.handle_ack(i)
    assert 8.5 < tahoe.cwnd < 10.0

    # 3. 3 Duplicate ACKs trigger reset to Slow Start with cwnd = 1.0
    expected_ssthresh = max(2, int(tahoe.cwnd / 2))
    for _ in range(3):
        tahoe.handle_ack(15)
    assert tahoe.state == TahoeState.SLOW_START
    assert tahoe.cwnd == 1.0
    assert tahoe.ssthresh == expected_ssthresh
    assert tahoe.duplicate_acks == 0

    # 4. Timeout resets cwnd and duplicate_acks
    tahoe.handle_ack(16)
    tahoe.handle_ack(16)
    assert tahoe.duplicate_acks == 1
    tahoe.handle_timeout()
    assert tahoe.cwnd == 1.0
    assert tahoe.duplicate_acks == 0
    assert tahoe.state == TahoeState.SLOW_START


def test_tcp_reno():
    reno = TCPReno(initial_ssthresh=8)

    # 1. Slow Start & Congestion Avoidance
    for i in range(1, 16):
        reno.handle_ack(i)
    assert reno.state == RenoState.CONGESTION_AVOIDANCE
    expected_ssthresh = max(2, int(reno.cwnd / 2))

    # 2. 3 Duplicate ACKs enter Fast Recovery
    for _ in range(3):
        reno.handle_ack(15)
    assert reno.state == RenoState.FAST_RECOVERY
    assert reno.ssthresh == expected_ssthresh
    assert reno.cwnd == expected_ssthresh + 3

    # 3. Additional dup ACK inflates cwnd
    reno.handle_ack(15)
    assert reno.cwnd == expected_ssthresh + 4

    # 4. New ACK deflates cwnd to ssthresh and returns to Congestion Avoidance
    reno.handle_ack(20)
    assert reno.state == RenoState.CONGESTION_AVOIDANCE
    assert reno.cwnd == reno.ssthresh
    assert reno.duplicate_acks == 0

    # 5. Severe loss (Timeout) drops cwnd to 1 and restarts Slow Start
    reno.handle_timeout()
    assert reno.state == RenoState.SLOW_START
    assert reno.cwnd == 1.0
    assert reno.duplicate_acks == 0


def test_token_bucket():
    bucket = TokenBucket(refill_rate_bytes_per_sec=1000.0, capacity_bytes=2000.0)
    assert bucket.consume(1500.0) is True
    assert bucket.consume(1000.0) is False  # Only 500 bytes left

    bucket.refill(0.5)  # +500 -> 1000
    assert bucket.consume(1000.0) is True
    assert bucket.tokens == 0.0

    bucket.refill(10.0)  # Capped at capacity
    assert bucket.tokens == 2000.0
