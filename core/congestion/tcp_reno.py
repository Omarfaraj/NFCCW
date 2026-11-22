"""
core/congestion/tcp_reno.py - TCP Reno Congestion Control (Fast Recovery)
"""
from enum import Enum, auto

class RenoState(Enum):
    SLOW_START = auto()
    CONGESTION_AVOIDANCE = auto()
    FAST_RECOVERY = auto()

class TCPReno:
    def __init__(self, initial_ssthresh: int = 64):
        self.cwnd = 1.0
        self.ssthresh = initial_ssthresh
        self.state = RenoState.SLOW_START
        self.duplicate_acks = 0
        self.last_ack_received = -1

    def handle_ack(self, ack_seq: int):
        if ack_seq == self.last_ack_received:
            self.duplicate_acks += 1
            
            if self.state == RenoState.FAST_RECOVERY:
                # In Fast Recovery, inflate cwnd for each dup ACK to maintain ACK clock
                self.cwnd += 1
            elif self.duplicate_acks == 3:
                # Enter Fast Recovery instead of dropping to Slow Start
                self.ssthresh = max(2, int(self.cwnd / 2))
                self.cwnd = self.ssthresh + 3
                self.state = RenoState.FAST_RECOVERY
            return

        # New ACK received
        self.last_ack_received = ack_seq
        
        if self.state == RenoState.FAST_RECOVERY:
            # New ACK signals recovery complete. Deflate window.
            self.cwnd = self.ssthresh
            self.state = RenoState.CONGESTION_AVOIDANCE
            self.duplicate_acks = 0
            
        elif self.state == RenoState.SLOW_START:
            self.cwnd += 1
            if self.cwnd >= self.ssthresh:
                self.state = RenoState.CONGESTION_AVOIDANCE
                
        elif self.state == RenoState.CONGESTION_AVOIDANCE:
            self.cwnd += (1.0 / int(self.cwnd))
            
        self.duplicate_acks = 0

    def handle_timeout(self):
        """A timeout still forces Reno to drop to 1 (Slow Start) just like Tahoe."""
        self.ssthresh = max(2, int(self.cwnd / 2))
        self.cwnd = 1.0
        self.duplicate_acks = 0
        self.state = RenoState.SLOW_START