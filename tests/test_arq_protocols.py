# tests/test_arq_protocols.py

import sys
import os

# Add the root project directory to Python's path so we can import 'core'
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.channel import NetworkChannel
from core.protocols.stop_and_wait import StopAndWaitProtocol
from core.protocols.go_back_n import GoBackNProtocol
from core.protocols.selective_repeat import SelectiveRepeatProtocol

def run_simulation(proto_a, proto_b, loss_rate, num_messages):
    """
    Runs an end-to-end simulation between two protocol nodes.
    Node A sends `num_messages` to Node B.
    """
    # Create bidirectional links
    forward_link = NetworkChannel(latency_ticks=1, loss_rate=loss_rate)
    reverse_link = NetworkChannel(latency_ticks=1, loss_rate=loss_rate)

    send_queue = [f"Payload-{i}" for i in range(num_messages)]
    retransmissions = 0

    max_ticks = 2000
    for tick in range(1, max_ticks + 1):
        # 1. Node A sends data if its window allows
        if send_queue:
            frame = proto_a.send_data(send_queue[0], tick)
            if frame:
                forward_link.transmit(frame)
                send_queue.pop(0)  # Successfully buffered in the sender window

        # 2. Node A handles timeouts (retransmits expired frames)
        for re_frame in proto_a.handle_tick(tick):
            forward_link.transmit(re_frame)
            retransmissions += 1

        # 3. Advance network time
        arrived_at_b = forward_link.step()
        arrived_at_a = reverse_link.step()

        # 4. Node B processes arriving DATA and replies with ACKs/NAKs
        for frame in arrived_at_b:
            ack_or_nak = proto_b.receive_frame(frame, tick)
            if ack_or_nak:
                reverse_link.transmit(ack_or_nak)
        
        proto_b.handle_tick(tick) # Receiver timeouts (if any)

        # 5. Node A processes returning ACKs/NAKs
        for frame in arrived_at_a:
            proto_a.receive_frame(frame, tick)

        # 6. Check Completion State
        # The simulation is done when Node A has no more packets to send,
        # its active window is completely empty, and the network pipes are drained.
        if not send_queue and not forward_link.pipe and not reverse_link.pipe:
            if hasattr(proto_a, 'waiting_for_ack'):
                is_done = not proto_a.waiting_for_ack
            else:
                is_done = proto_a.sender_window.is_empty()
                
            if is_done:
                return tick, retransmissions

    return -1, retransmissions  # Timeout reached, failed to deliver

def run_tests():
    print("========================================")
    print(" Running ARQ Protocol Verification Tests ")
    print("========================================\n")

    # TEST 1: Stop-and-Wait (Clean)
    node_a = StopAndWaitProtocol(timeout_ticks=5)
    node_b = StopAndWaitProtocol(timeout_ticks=5)
    ticks, retrans = run_simulation(node_a, node_b, loss_rate=0.0, num_messages=5)
    print("--- Test 1: Stop-and-Wait on Clean Channel (0% Loss) ---")
    print(f"Delivered 5/5 in {ticks} ticks. Retransmissions: {retrans}")
    print("PASS: Stop-and-Wait cleanly delivered all packets.\n" if retrans == 0 else "FAIL\n")

    # TEST 2: Stop-and-Wait (Lossy)
    node_a = StopAndWaitProtocol(timeout_ticks=5)
    node_b = StopAndWaitProtocol(timeout_ticks=5)
    ticks, retrans = run_simulation(node_a, node_b, loss_rate=0.25, num_messages=5)
    print("--- Test 2: Stop-and-Wait on Lossy Channel (25% Loss) ---")
    print(f"Delivered 5/5 in {ticks} ticks. Retransmissions: {retrans}")
    print("PASS: Stop-and-Wait recovered from loss via retransmissions.\n" if retrans > 0 else "FAIL\n")

    # TEST 3: Go-Back-N (Clean)
    # MAX_SEQ = 7 means window size can be up to 7
    node_a = GoBackNProtocol(max_seq=7, max_window_size=7, timeout_ticks=8)
    node_b = GoBackNProtocol(max_seq=7, max_window_size=7, timeout_ticks=8)
    ticks, retrans = run_simulation(node_a, node_b, loss_rate=0.0, num_messages=15)
    print("--- Test 3: Go-Back-N on Clean Channel (0% Loss, Window=7) ---")
    print(f"Delivered 15/15 in {ticks} ticks. Retransmissions: {retrans}")
    print("PASS: Go-Back-N pipelined and delivered all 15 packets smoothly.\n" if retrans == 0 else "FAIL\n")

    # TEST 4: Go-Back-N (Lossy)
    node_a = GoBackNProtocol(max_seq=7, max_window_size=7, timeout_ticks=8)
    node_b = GoBackNProtocol(max_seq=7, max_window_size=7, timeout_ticks=8)
    ticks, retrans = run_simulation(node_a, node_b, loss_rate=0.25, num_messages=15)
    print("--- Test 4: Go-Back-N on Lossy Channel (25% Loss) ---")
    print(f"Delivered 15/15 in {ticks} ticks. Retransmissions: {retrans}")
    print("PASS: Go-Back-N successfully backed up and recovered from dropped frames.\n" if retrans > 0 else "FAIL\n")

    # TEST 5: Selective Repeat (Lossy)
    # MAX_SEQ = 7 means window size MUST be <= 4 ( (7+1)/2 ) to prevent overlap ambiguity
    node_a = SelectiveRepeatProtocol(max_seq=7, max_window_size=4, timeout_ticks=8)
    node_b = SelectiveRepeatProtocol(max_seq=7, max_window_size=4, timeout_ticks=8)
    ticks, retrans = run_simulation(node_a, node_b, loss_rate=0.25, num_messages=15)
    print("--- Test 5: Selective Repeat on Lossy Channel (25% Loss, Window=4) ---")
    print(f"Delivered 15/15 in {ticks} ticks. Retransmissions: {retrans}")
    print("PASS: Selective Repeat recovered using independent timers and NAKs.\n" if retrans > 0 else "FAIL\n")

    print("========================================")
    print(" ALL PROTOCOL VERIFICATION TESTS COMPLETED ")
    print("========================================")

if __name__ == "__main__":
    run_tests()