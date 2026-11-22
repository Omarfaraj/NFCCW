"""
core/buffer.py - Circular sequence arithmetic and sliding window buffers.
Grounded in Tanenbaum, Chapter 3 (Data Link Layer ARQ Protocols).
"""

from typing import Any, List, Optional

def between(a: int, b: int, c: int) -> bool:
    """
    Circular sequence comparison from Tanenbaum (Protocol 5 & 6).
    Returns True if a <= b < c circularly.
    Handles wraparound where c <= a or b < c < a.
    """
    return ((a <= b < c) or (c < a <= b) or (b < c < a))

def inc(seq: int, max_seq: int) -> int:
    """Circular increment of a sequence number modulo (MAX_SEQ + 1)."""
    return (seq + 1) % (max_seq + 1)

class CircularBuffer:
    """
    Circular window buffer representing the sender or receiver window.
    Maintains slots indexed by sequence numbers [0 .. MAX_SEQ].
    """

    def __init__(self, max_seq: int, max_window_size: int):
        if max_seq < 1:
            raise ValueError("max_seq must be at least 1.")
        if not (1 <= max_window_size <= max_seq):
            raise ValueError(
                f"max_window_size must be between 1 and max_seq ({max_seq}) "
                "to avoid full/empty wraparound ambiguity."
            )
        self.max_seq = max_seq
        self.space_size = max_seq + 1
        self.max_window_size = max_window_size

        # Slots to hold packet payloads or buffered frames
        self.slots: List[Optional[Any]] = [None] * self.space_size

        # Window bounds: [lower, upper)
        self.lower: int = 0
        self.upper: int = 0
        self.count: int = 0

    def is_full(self) -> bool:
        """Checks if the window has reached maximum allowed unacknowledged frames."""
        return self.count >= self.max_window_size

    def is_empty(self) -> bool:
        """Checks if there are no outstanding frames inside the window."""
        return self.count == 0

    def contains(self, seq: int) -> bool:
        """Returns whether sequence number `seq` lies within the active window."""
        if self.is_empty():
            return False
        return between(self.lower, seq, self.upper)

    def append(self, item: Any) -> int:
        """
        Stores an item at the current `upper` boundary and advances `upper`.
        Returns the assigned sequence number.
        """
        if self.is_full():
            raise OverflowError("Circular buffer window is full.")

        assigned_seq = self.upper
        self.slots[assigned_seq] = item
        self.upper = inc(self.upper, self.max_seq)
        self.count += 1
        return assigned_seq

    def put_at(self, seq: int, item: Any) -> None:
        """Inserts an item directly at a sequence position (used by Selective Repeat)."""
        self.slots[seq] = item

    def get(self, seq: int) -> Optional[Any]:
        """Retrieves item stored at sequence slot `seq`."""
        return self.slots[seq]

    def advance_lower(self) -> Optional[Any]:
        """
        Pops and frees the oldest acknowledged slot at `lower`, advancing the window.
        """
        if self.is_empty():
            return None

        item = self.slots[self.lower]
        self.slots[self.lower] = None
        self.lower = inc(self.lower, self.max_seq)
        self.count -= 1
        return item