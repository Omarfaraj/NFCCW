"""
core/protocols/stop_and_wait.py - Protocol 3 (Alternating Bit)
"""

from typing import Any, List, Optional
from .base import BaseProtocol, Frame, FrameKind
from ..timers import TimerManager
from ..buffer import inc

class StopAndWaitProtocol(BaseProtocol):
    def __init__(self, max_seq: int = 1, timeout_ticks: int = 10):
        # Stop and wait strictly uses a 1-bit sequence number (0 or 1)
        super().__init__(max_seq=1)
        
        self.timers = TimerManager(default_timeout_ticks=timeout_ticks)
        
        # Sender state
        self.next_frame_to_send = 0
        self.frame_in_transit: Optional[Frame] = None
        self.waiting_for_ack = False
        
        # Receiver state
        self.frame_expected = 0

    def send_data(self, payload: Any, current_tick: int) -> Optional[Frame]:
        """Called by network layer to send data."""
        if self.waiting_for_ack:
            return None # Cannot send, window is full (size 1)
            
        frame = Frame(kind=FrameKind.DATA, seq=self.next_frame_to_send, ack=0, payload=payload)
        self.frame_in_transit = frame
        self.waiting_for_ack = True
        
        self.timers.start(self.next_frame_to_send, current_tick)
        return frame

    def receive_frame(self, frame: Frame, current_tick: int) -> Optional[Frame]:
        """Processes incoming DATA or ACK frames."""
        outbound_frame = None

        if frame.kind == FrameKind.DATA:
            if frame.seq == self.frame_expected:
                # Accept frame and advance receiver window
                self.frame_expected = inc(self.frame_expected, self.max_seq)
                # Send ACK for the frame just received
                outbound_frame = Frame(kind=FrameKind.ACK, seq=0, ack=frame.seq)
            else:
                # Duplicate/out-of-order frame. ACK the last successfully received frame.
                last_ack = 1 if self.frame_expected == 0 else 0
                outbound_frame = Frame(kind=FrameKind.ACK, seq=0, ack=last_ack)

        elif frame.kind == FrameKind.ACK:
            if self.waiting_for_ack and frame.ack == self.next_frame_to_send:
                # ACK matches the frame we are waiting for
                self.timers.stop(self.next_frame_to_send)
                self.waiting_for_ack = False
                self.frame_in_transit = None
                self.next_frame_to_send = inc(self.next_frame_to_send, self.max_seq)

        return outbound_frame

    def handle_tick(self, current_tick: int) -> List[Frame]:
        """Checks for timeouts and retransmits if necessary."""
        retransmissions = []
        expired_seqs = self.timers.check_timeouts(current_tick)
        
        if expired_seqs and self.frame_in_transit:
            # Retransmit the unacknowledged frame
            retransmissions.append(self.frame_in_transit)
            # Restart timer
            self.timers.start(self.next_frame_to_send, current_tick)
            
        return retransmissions