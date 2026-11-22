# tests/test_congestion.py

import sys
import os

# Add the root project directory to Python's path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.congestion.tcp_tahoe import TCPTahoe, TahoeState
from core.congestion.tcp_reno import TCPReno, RenoState

def format_cwnd(cwnd):
    """Helper to cleanly format the float cwnd for printing."""
    return f"{cwnd:.2f}"

def test_tcp_tahoe():
    print("--- Testing TCP Tahoe ---")
    tahoe = TCPTahoe(initial_ssthresh=8)
    
    print(f"Initial State: {tahoe.state.name}, cwnd: {format_cwnd(tahoe.cwnd)}, ssthresh: {tahoe.ssthresh}")
    
    # 1. Simulate Slow Start (Exponential Growth)
    print("\nSimulating Slow Start (Receiving 7 ACKs)...")
    for i in range(1, 8):
        tahoe.handle_ack(i)
        
    print(f"Current State: {tahoe.state.name}, cwnd: {format_cwnd(tahoe.cwnd)}, ssthresh: {tahoe.ssthresh}")
    if tahoe.state == TahoeState.CONGESTION_AVOIDANCE and tahoe.cwnd >= 8.0:
        print("✅ Slow Start threshold reached. Transitioned to Congestion Avoidance.")
    else:
        print("❌ FAILED: Did not transition to Congestion Avoidance correctly.")

    # 2. Simulate Congestion Avoidance (Linear Growth - AIMD)
    print("\nSimulating Congestion Avoidance (Receiving 8 ACKs)...")
    for i in range(8, 16):
        tahoe.handle_ack(i)
        
    print(f"Current State: {tahoe.state.name}, cwnd: {format_cwnd(tahoe.cwnd)}")
    # Expected: cwnd increases by roughly 1 MSS for every full window of ACKs
    if tahoe.cwnd > 8.0 and tahoe.cwnd < 16.0: 
         print("✅ Congestion Avoidance (Linear Growth) verified.")
    else:
         print("❌ FAILED: Linear growth incorrect.")

    # 3. Simulate Packet Loss via 3 Duplicate ACKs
    print("\nSimulating Packet Loss (Receiving 3 Duplicate ACKs for seq 15)...")
    for _ in range(3):
        tahoe.handle_ack(15)
        
    print(f"Current State: {tahoe.state.name}, cwnd: {format_cwnd(tahoe.cwnd)}, ssthresh: {tahoe.ssthresh}")
    if tahoe.state == TahoeState.SLOW_START and tahoe.cwnd == 1.0:
        print("✅ Fast Retransmit verified. Tahoe dropped cwnd to 1 and entered Slow Start.")
    else:
        print("❌ FAILED: Tahoe did not reset to cwnd=1 on 3 duplicate ACKs.")

def test_tcp_reno():
    print("\n--- Testing TCP Reno ---")
    reno = TCPReno(initial_ssthresh=8)
    
    print(f"Initial State: {reno.state.name}, cwnd: {format_cwnd(reno.cwnd)}, ssthresh: {reno.ssthresh}")
    
    # 1. Simulate Slow Start & Congestion Avoidance
    print("\nSimulating Slow Start and Congestion Avoidance (Receiving 15 ACKs)...")
    for i in range(1, 16):
        reno.handle_ack(i)
        
    print(f"Current State: {reno.state.name}, cwnd: {format_cwnd(reno.cwnd)}, ssthresh: {reno.ssthresh}")

    expected_ssthresh = max(2, int(reno.cwnd / 2))
    
    # 2. Simulate Packet Loss via 3 Duplicate ACKs
    print("\nSimulating Packet Loss (Receiving 3 Duplicate ACKs for seq 15)...")
    for _ in range(3):
        reno.handle_ack(15)
        
    print(f"Current State: {reno.state.name}, cwnd: {format_cwnd(reno.cwnd)}, ssthresh: {reno.ssthresh}")
    
    if reno.state == RenoState.FAST_RECOVERY and reno.ssthresh == expected_ssthresh:
        print(f"✅ Fast Recovery verified. Reno halved ssthresh to {reno.ssthresh} and inflated cwnd.")
    else:
        print("❌ FAILED: Reno did not enter Fast Recovery correctly.")

    # 3. Simulate Recovery Complete (Receiving a NEW ACK)
    print("\nSimulating Recovery Complete (Receiving new ACK for seq 20)...")
    reno.handle_ack(20)
    print(f"Current State: {reno.state.name}, cwnd: {format_cwnd(reno.cwnd)}, ssthresh: {reno.ssthresh}")
    
    if reno.state == RenoState.CONGESTION_AVOIDANCE and reno.cwnd == reno.ssthresh:
        print("✅ Deflation verified. Reno returned to Congestion Avoidance with cwnd = ssthresh.")
    else:
        print("❌ FAILED: Reno did not deflate cwnd correctly after Fast Recovery.")

    # 4. Simulate Severe Packet Loss (Timeout)
    print("\nSimulating Severe Packet Loss (Timeout)...")
    reno.handle_timeout()
    print(f"Current State: {reno.state.name}, cwnd: {format_cwnd(reno.cwnd)}, ssthresh: {reno.ssthresh}")
    
    if reno.state == RenoState.SLOW_START and reno.cwnd == 1.0:
        print("✅ Timeout verified. Reno dropped cwnd to 1 and restarted Slow Start.")
    else:
        print("❌ FAILED: Reno did not drop to cwnd=1 on timeout.")

def run_tests():
    print("===========================================")
    print(" Running TCP Congestion Verification Tests ")
    print("===========================================\n")
    
    test_tcp_tahoe()
    test_tcp_reno()

    print("\n===========================================")
    print(" ALL CONGESTION VERIFICATION TESTS COMPLETED ")
    print("===========================================")

if __name__ == "__main__":
    run_tests()