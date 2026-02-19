"""Safety limits for the autonomous loop."""

from __future__ import annotations

import time

from pydantic import BaseModel, PrivateAttr


class SafetyLimits(BaseModel):
    """Configurable limits to prevent runaway execution."""

    max_steps: int = 100
    max_duration_seconds: float = 3600.0
    batch_size: int = 5
    cooldown_per_capability: float = 0.0  # seconds between same capability runs
    _start_time: float = PrivateAttr(default=0.0)

    def start(self) -> None:
        """Record the start time."""
        self._start_time = time.monotonic()

    def can_continue(self, step: int) -> bool:
        """Check if the loop should continue."""
        if step > self.max_steps:
            return False
        if self._start_time > 0:
            elapsed = time.monotonic() - self._start_time
            if elapsed >= self.max_duration_seconds:
                return False
        return True

    @property
    def elapsed(self) -> float:
        if self._start_time <= 0:
            return 0.0
        return time.monotonic() - self._start_time
