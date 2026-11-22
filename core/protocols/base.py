"""
core/protocols/base.py - Frame structures and base protocol definitions.
Grounded in Tanenbaum Chapter 3 protocol models.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, List, Optional

class FrameKind(Enum):
    DATA = auto()
    ACK = auto()
    NAK = auto()

@dataclass
class Frame:
    """
    Data Link Layer Frame layout (Tanenbaum).
    - kind: DATA, ACK, or NAK
    - seq: sequence number of this frame (for DATA)
    - ack: acknowledgement sequence number
    - payload: packet data payload
    """
    kind: FrameKind
    seq: int = 0
    ack: int = 0
    payload: Optional[Any] = None

class BaseProtocol(ABC):
    """
    Abstract Base Class for Data Link Layer ARQ Protocols.
    """

    def __init__(self, max_seq: int):
        self.max_seq = max_seq

    @abstractmethod
    def send_data(self, payload: Any, current_tick: int) -> Optional[Frame]:
        """Accepts a payload from the network layer to transmit."""
        pass

    @abstractmethod
    def receive_frame(self, frame: Frame, current_tick: int) -> Optional[Frame]:
        """Handles an incoming frame from the physical layer."""
        pass

    @abstractmethod
    def handle_tick(self, current_tick: int) -> List[Frame]:
        """Advances protocol internal clock and handles timeouts."""
        pass