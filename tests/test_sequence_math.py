"""
tests/test_sequence_math.py - Unit tests for circular sequence arithmetic and CircularBuffer.
"""

import pytest

from core.buffer import CircularBuffer, between, inc


def test_between_normal_and_wraparound():
    assert between(0, 0, 4) is True
    assert between(0, 3, 4) is True
    assert between(0, 4, 4) is False
    assert between(0, 5, 4) is False

    # Wraparound window [6, 2) in mod-8 space: valid seqs are 6, 7, 0, 1
    assert between(6, 6, 2) is True
    assert between(6, 7, 2) is True
    assert between(6, 0, 2) is True
    assert between(6, 1, 2) is True
    assert between(6, 2, 2) is False
    assert between(6, 5, 2) is False


def test_inc_wraps_around():
    assert inc(0, max_seq=7) == 1
    assert inc(6, max_seq=7) == 7
    assert inc(7, max_seq=7) == 0


def test_circular_buffer_lifecycle_and_validation():
    with pytest.raises(ValueError):
        CircularBuffer(max_seq=7, max_window_size=8)

    buf = CircularBuffer(max_seq=3, max_window_size=3)
    assert buf.is_empty() is True
    assert buf.contains(0) is False

    assert buf.append("A") == 0
    assert buf.append("B") == 1
    assert buf.append("C") == 2
    assert buf.is_full() is True
    assert buf.contains(0) is True
    assert buf.contains(2) is True
    assert buf.contains(3) is False

    with pytest.raises(OverflowError):
        buf.append("D")

    assert buf.advance_lower() == "A"
    assert buf.append("D") == 3
    assert buf.contains(3) is True
    assert buf.contains(0) is False
