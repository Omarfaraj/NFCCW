"""
core/timers.py - Retransmission timer management for ARQ protocols.
"""

from typing import Callable, Dict, Optional

class TimerManager:
    """
    Manages sequence timers in discrete simulation ticks.
    """

    def __init__(self, default_timeout_ticks: int = 10):
        self.default_timeout_ticks = default_timeout_ticks
        # Mapping: seq_num -> expiry_tick
        self.active_timers: Dict[int, int] = {}

    def start(self, seq: int, current_tick: int, timeout: Optional[int] = None) -> None:
        """Starts or restarts the timer for sequence number `seq`."""
        duration = timeout if timeout is not None else self.default_timeout_ticks
        self.active_timers[seq] = current_tick + duration

    def stop(self, seq: int) -> None:
        """Stops and clears the timer for sequence number `seq`."""
        self.active_timers.pop(seq, None)

    def is_running(self, seq: int) -> bool:
        """Checks if a timer is currently active for `seq`."""
        return seq in self.active_timers

    def check_timeouts(self, current_tick: int) -> list[int]:
        """
        Checks for expired timers at `current_tick`.
        Returns a list of sequence numbers whose timers have expired.
        """
        expired = [seq for seq, expiry in self.active_timers.items() if current_tick >= expiry]
        for seq in expired:
            del self.active_timers[seq]
        return expired