"""
core/protocols/go_back_n.py - Protocol 5
"""
from typing import Any, List, Optional
from .base import BaseProtocol, Frame, FrameKind
from ..timers import TimerManager
from ..buffer import CircularBuffer, between, inc

class GoBackNProtocol(BaseProtocol):
    def __init__(self, max_seq: int, max_window_size: int, timeout_ticks: int = 10):
        super().__init__(max_seq)
        self.sender_window = CircularBuffer(max_seq, max_window_size)
        self.timers = TimerManager(default_timeout_ticks=timeout_ticks)
        self.frame_expected = 0
        self.last_ack_sent = max_seq

    def send_data(self, payload: Any, current_tick: int) -> Optional[Frame]:
        if self.sender_window.is_full():
            return None
            
        seq_num = self.sender_window.append(payload)
        frame = Frame(kind=FrameKind.DATA, seq=seq_num, ack=0, payload=payload)
        
        if self.sender_window.count == 1:
            self.timers.start(self.sender_window.lower, current_tick)
            
        return frame

    def receive_frame(self, frame: Frame, current_tick: int) -> Optional[Frame]:
        outbound_frame = None

        if frame.kind == FrameKind.DATA:
            if frame.seq == self.frame_expected:
                self.frame_expected = inc(self.frame_expected, self.max_seq)
                self.last_ack_sent = frame.seq
                outbound_frame = Frame(kind=FrameKind.ACK, seq=0, ack=self.last_ack_sent)
            else:
                outbound_frame = Frame(kind=FrameKind.ACK, seq=0, ack=self.last_ack_sent)

        elif frame.kind == FrameKind.ACK:
            if between(self.sender_window.lower, frame.ack, self.sender_window.upper):
                while between(self.sender_window.lower, frame.ack, self.sender_window.upper):
                    # FIX: Stop the timer for the specific frame BEFORE advancing lower
                    self.timers.stop(self.sender_window.lower)
                    self.sender_window.advance_lower()
                
                if not self.sender_window.is_empty():
                    self.timers.start(self.sender_window.lower, current_tick)

        return outbound_frame

    def handle_tick(self, current_tick: int) -> List[Frame]:
        retransmissions = []
        if not self.sender_window.is_empty():
            expired = self.timers.check_timeouts(current_tick)
            if expired:
                seq = self.sender_window.lower
                while seq != self.sender_window.upper:
                    payload = self.sender_window.get(seq)
                    if payload is not None:
                        retransmissions.append(Frame(kind=FrameKind.DATA, seq=seq, ack=0, payload=payload))
                    seq = inc(seq, self.max_seq)
                self.timers.start(self.sender_window.lower, current_tick)
                
        return retransmissions