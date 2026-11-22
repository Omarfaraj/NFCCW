"""
core/congestion/token_bucket.py - Token Bucket traffic shaper.
"""


class TokenBucket:
    """
    Simulates a token bucket shaper with configurable refill rate (bytes/sec)
    and burst capacity (bytes).
    """

    def __init__(self, refill_rate_bytes_per_sec: float, capacity_bytes: float):
        if refill_rate_bytes_per_sec <= 0 or capacity_bytes <= 0:
            raise ValueError("refill_rate_bytes_per_sec and capacity_bytes must be positive.")
        self.refill_rate = float(refill_rate_bytes_per_sec)
        self.capacity = float(capacity_bytes)
        self.tokens = float(capacity_bytes)

    def refill(self, elapsed_sec: float) -> float:
        """Adds tokens accumulated over `elapsed_sec`, capped at `capacity`."""
        if elapsed_sec > 0:
            self.tokens = min(self.capacity, self.tokens + elapsed_sec * self.refill_rate)
        return self.tokens

    def consume(self, packet_bytes: float) -> bool:
        """Consumes `packet_bytes` tokens if available; returns True if conforming."""
        if packet_bytes <= self.tokens:
            self.tokens -= packet_bytes
            return True
        return False
