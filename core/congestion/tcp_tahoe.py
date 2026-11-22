"""
core/congestion/tcp_tahoe.py - TCP Tahoe Congestion Control
"""
from enum import Enum, auto

class TahoeState(Enum):
    SLOW_START = auto()
    CONGESTION_AVOIDANCE = auto()

class TCPTahoe:
    def __init__(self, initial_ssthresh: int = 64):
        self.cwnd = 1.0 # Congestion Window starts at 1 Maximum Segment Size (MSS)
        self.ssthresh = initial_ssthresh # Slow Start Threshold
        self.state = TahoeState.SLOW_START
        self.duplicate_acks = 0
        self.last_ack_received = -1

    def handle_ack(self, ack_seq: int):
        """Called when a valid ACK is received."""
        if ack_seq == self.last_ack_received:
            self.duplicate_acks += 1
            if self.duplicate_acks == 3:
                # 3 Duplicate ACKs trigger a Fast Retransmit (Loss detected)
                self._handle_loss()
            return
            
        # New ACK received
        self.duplicate_acks = 0
        self.last_ack_received = ack_seq
        
        if self.state == TahoeState.SLOW_START:
            # Exponential growth: cwnd doubles every RTT (adds 1 per ACK)
            self.cwnd += 1
            if self.cwnd >= self.ssthresh:
                self.state = TahoeState.CONGESTION_AVOIDANCE
                
        elif self.state == TahoeState.CONGESTION_AVOIDANCE:
            # Linear growth: Adds 1 MSS per RTT (1/cwnd per ACK)
            self.cwnd += (1.0 / int(self.cwnd))

    def handle_timeout(self):
        """Called when the retransmission timer expires (Severe Loss)."""
        self._handle_loss()

    def _handle_loss(self):
        """Tahoe handles loss by dropping cwnd to 1 and restarting Slow Start."""
        # ssthresh becomes half the current congestion window (minimum 2)
        self.ssthresh = max(2, int(self.cwnd / 2))
        self.cwnd = 1.0
        self.state = TahoeState.SLOW_START