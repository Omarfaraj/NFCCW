"""
tests/test_arq_protocols.py - Deterministic end-to-end tests for ARQ protocols.
"""

import random
import pytest

from core.channel import NetworkChannel
from core.protocols.base import Frame, FrameKind
from core.protocols.go_back_n import GoBackNProtocol
from core.protocols.selective_repeat import SelectiveRepeatProtocol
from core.protocols.stop_and_wait import StopAndWaitProtocol


def run_simulation(proto_a, proto_b, loss_rate: float, num_messages: int, seed: int = 42):
    """
    Runs an end-to-end simulation between two protocol nodes.
    Node A sends `num_messages` to Node B.
    """
    random.seed(seed)
    forward_link = NetworkChannel(latency_ticks=1, loss_rate=loss_rate)
    reverse_link = NetworkChannel(latency_ticks=1, loss_rate=loss_rate)

    send_queue = [f"Payload-{i}" for i in range(num_messages)]
    retransmissions = 0

    max_ticks = 2000
    for tick in range(1, max_ticks + 1):
        if send_queue:
            frame = proto_a.send_data(send_queue[0], tick)
            if frame:
                forward_link.transmit(frame)
                send_queue.pop(0)

        for re_frame in proto_a.handle_tick(tick):
            forward_link.transmit(re_frame)
            retransmissions += 1

        arrived_at_b = forward_link.step()
        arrived_at_a = reverse_link.step()

        for frame in arrived_at_b:
            ack_or_nak = proto_b.receive_frame(frame, tick)
            if ack_or_nak:
                reverse_link.transmit(ack_or_nak)

        proto_b.handle_tick(tick)

        for frame in arrived_at_a:
            proto_a.receive_frame(frame, tick)

        if not send_queue and not forward_link.pipe and not reverse_link.pipe:
            if hasattr(proto_a, "waiting_for_ack"):
                is_done = not proto_a.waiting_for_ack
            else:
                is_done = proto_a.sender_window.is_empty()
            if is_done:
                return tick, retransmissions

    return -1, retransmissions


def test_stop_and_wait_clean():
    node_a = StopAndWaitProtocol(timeout_ticks=5)
    node_b = StopAndWaitProtocol(timeout_ticks=5)
    ticks, retrans = run_simulation(node_a, node_b, loss_rate=0.0, num_messages=5)
    assert ticks > 0
    assert retrans == 0


def test_stop_and_wait_lossy():
    node_a = StopAndWaitProtocol(timeout_ticks=5)
    node_b = StopAndWaitProtocol(timeout_ticks=5)
    ticks, retrans = run_simulation(node_a, node_b, loss_rate=0.25, num_messages=8, seed=7)
    assert ticks > 0
    assert retrans > 0


def test_go_back_n_clean():
    node_a = GoBackNProtocol(max_seq=7, max_window_size=7, timeout_ticks=8)
    node_b = GoBackNProtocol(max_seq=7, max_window_size=7, timeout_ticks=8)
    ticks, retrans = run_simulation(node_a, node_b, loss_rate=0.0, num_messages=15)
    assert ticks > 0
    assert retrans == 0


def test_go_back_n_lossy():
    node_a = GoBackNProtocol(max_seq=7, max_window_size=7, timeout_ticks=8)
    node_b = GoBackNProtocol(max_seq=7, max_window_size=7, timeout_ticks=8)
    ticks, retrans = run_simulation(node_a, node_b, loss_rate=0.25, num_messages=15, seed=42)
    assert ticks > 0
    assert retrans > 0


def test_selective_repeat_lossy():
    node_a = SelectiveRepeatProtocol(max_seq=7, max_window_size=4, timeout_ticks=8)
    node_b = SelectiveRepeatProtocol(max_seq=7, max_window_size=4, timeout_ticks=8)
    ticks, retrans = run_simulation(node_a, node_b, loss_rate=0.25, num_messages=15, seed=42)
    assert ticks > 0
    assert retrans > 0


def test_selective_repeat_validates_window_size():
    with pytest.raises(ValueError):
        SelectiveRepeatProtocol(max_seq=7, max_window_size=5)


def test_selective_repeat_old_duplicate_does_not_send_spurious_nak():
    receiver = SelectiveRepeatProtocol(max_seq=7, max_window_size=4)
    # Deliver seq 0 cleanly -> recv_lower advances to 1
    ack0 = receiver.receive_frame(Frame(kind=FrameKind.DATA, seq=0, payload="P0"), current_tick=1)
    assert ack0 is not None and ack0.kind == FrameKind.ACK and ack0.ack == 0

    # Receiving old duplicate seq 0 should re-ACK 0, not emit a NAK for 1
    reply = receiver.receive_frame(Frame(kind=FrameKind.DATA, seq=0, payload="P0"), current_tick=2)
    assert reply is not None
    assert reply.kind == FrameKind.ACK
    assert reply.ack == 0
    assert receiver.nak_sent[1] is False
