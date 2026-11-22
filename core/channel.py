"""
core/channel.py - Simulated network channel supporting latency, jitter, and loss.
"""

import random
from dataclasses import dataclass
from typing import Any, List, Optional

@dataclass
class InFlightPacket:
    payload: Any
    deliver_at_tick: int
    is_corrupted: bool = False

class NetworkChannel:
    """
    Simulates a bi-directional or uni-directional link with configurable:
    - Propagation delay (ticks)
    - Delay jitter (variance in ticks)
    - Loss probability (0.0 to 1.0)
    """

    def __init__(self, latency_ticks: int = 3, jitter_ticks: int = 0, loss_rate: float = 0.0):
        self.latency_ticks = latency_ticks
        self.jitter_ticks = jitter_ticks
        self.loss_rate = loss_rate

        self.pipe: List[InFlightPacket] = []
        self.current_tick: int = 0

    def transmit(self, packet: Any) -> bool:
        """
        Transmits a packet across the channel.
        Returns True if packet successfully entered the pipe, or False if dropped.
        """
        # Determine probabilistic packet loss
        if random.random() < self.loss_rate:
            return False  # Dropped on wire

        jitter = random.randint(-self.jitter_ticks, self.jitter_ticks) if self.jitter_ticks > 0 else 0
        total_delay = max(1, self.latency_ticks + jitter)

        delivery_tick = self.current_tick + total_delay
        self.pipe.append(InFlightPacket(payload=packet, deliver_at_tick=delivery_tick))
        return True

    def step(self) -> List[Any]:
        """
        Advances channel clock by 1 tick and returns all packets ready for arrival.
        """
        self.current_tick += 1
        arrived: List[Any] = []
        remaining: List[InFlightPacket] = []

        for item in self.pipe:
            if item.deliver_at_tick <= self.current_tick:
                arrived.append(item.payload)
            else:
                remaining.append(item)

        self.pipe = remaining
        return arrived