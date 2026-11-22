"""
core/protocols/selective_repeat.py - Protocol 6 (Selective Repeat)
"""
from typing import Any, List, Optional
from .base import BaseProtocol, Frame, FrameKind
from ..timers import TimerManager
from ..buffer import CircularBuffer, between, inc

class SelectiveRepeatProtocol(BaseProtocol):
    def __init__(self, max_seq: int, max_window_size: int, timeout_ticks: int = 10):
        super().__init__(max_seq)
        self.sender_window = CircularBuffer(max_seq, max_window_size)
        self.timers = TimerManager(default_timeout_ticks=timeout_ticks)
        
        self.receiver_window = CircularBuffer(max_seq, max_window_size)
        self.recv_lower = 0 
        self.recv_upper = max_window_size 
        self.nak_sent = {i: False for i in range(max_seq + 1)}

    def send_data(self, payload: Any, current_tick: int) -> Optional[Frame]:
        if self.sender_window.is_full():
            return None 
            
        seq_num = self.sender_window.append(payload)
        frame = Frame(kind=FrameKind.DATA, seq=seq_num, ack=0, payload=payload)
        self.timers.start(seq_num, current_tick)
        return frame

    def receive_frame(self, frame: Frame, current_tick: int) -> Optional[Frame]:
        outbound_frame = None

        if frame.kind == FrameKind.ACK:
            if between(self.sender_window.lower, frame.ack, self.sender_window.upper):
                while between(self.sender_window.lower, frame.ack, self.sender_window.upper):
                    seq = self.sender_window.lower
                    self.timers.stop(seq)
                    self.sender_window.advance_lower()
                    
        elif frame.kind == FrameKind.NAK:
            if between(self.sender_window.lower, frame.ack, self.sender_window.upper):
                payload = self.sender_window.get(frame.ack)
                if payload is not None:
                    self.timers.start(frame.ack, current_tick)
                    return Frame(kind=FrameKind.DATA, seq=frame.ack, ack=0, payload=payload)

        elif frame.kind == FrameKind.DATA:
            if frame.seq != self.recv_lower and not self.nak_sent[self.recv_lower]:
                outbound_frame = Frame(kind=FrameKind.NAK, seq=0, ack=self.recv_lower)
                self.nak_sent[self.recv_lower] = True

            if between(self.recv_lower, frame.seq, self.recv_upper):
                if self.receiver_window.get(frame.seq) is None:
                    self.receiver_window.put_at(frame.seq, frame.payload)

                while self.receiver_window.get(self.recv_lower) is not None:
                    # FIX: Manually erase the slot data to prevent ghost frames on wraparound!
                    self.receiver_window.put_at(self.recv_lower, None)
                    self.nak_sent[self.recv_lower] = False 
                    
                    self.recv_lower = inc(self.recv_lower, self.max_seq)
                    self.recv_upper = inc(self.recv_upper, self.max_seq)
                    
                    highest_received = (self.recv_lower - 1) % (self.max_seq + 1)
                    outbound_frame = Frame(kind=FrameKind.ACK, seq=0, ack=highest_received)
            else:
                if outbound_frame is None:
                    highest_received = (self.recv_lower - 1) % (self.max_seq + 1)
                    outbound_frame = Frame(kind=FrameKind.ACK, seq=0, ack=highest_received)

        return outbound_frame

    def handle_tick(self, current_tick: int) -> List[Frame]:
        retransmissions = []
        expired = self.timers.check_timeouts(current_tick)
        for seq in expired:
            payload = self.sender_window.get(seq)
            if payload is not None:
                retransmissions.append(Frame(kind=FrameKind.DATA, seq=seq, ack=0, payload=payload))
                self.timers.start(seq, current_tick)
                
        return retransmissions