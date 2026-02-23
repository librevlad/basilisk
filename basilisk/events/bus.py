"""Lightweight async event bus for the orchestrator."""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

logger = logging.getLogger(__name__)


class EventType(StrEnum):
    ENTITY_CREATED = "entity_created"
    ENTITY_UPDATED = "entity_updated"
    KNOWLEDGE_UPDATED = "knowledge_updated"
    OBSERVATION_APPLIED = "observation_applied"
    PLUGIN_STARTED = "plugin_started"
    PLUGIN_FINISHED = "plugin_finished"
    GAP_DETECTED = "gap_detected"
    STEP_COMPLETED = "step_completed"
    DECISION_MADE = "decision_made"
    FINDING_VERIFIED = "finding_verified"
    BELIEF_STRENGTHENED = "belief_strengthened"
    BELIEF_WEAKENED = "belief_weakened"
    HYPOTHESIS_CONFIRMED = "hypothesis_confirmed"
    HYPOTHESIS_REJECTED = "hypothesis_rejected"


@dataclass
class Event:
    """A single event in the bus."""

    type: EventType
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.monotonic)


class EventBus:
    """Simple pub/sub event bus supporting both sync and async handlers."""

    def __init__(self) -> None:
        self._subscribers: dict[EventType, list[Callable]] = defaultdict(list)

    def subscribe(self, event_type: EventType, handler: Callable[[Event], None]) -> None:
        """Register a handler for an event type."""
        self._subscribers[event_type].append(handler)

    def emit(self, event: Event) -> None:
        """Emit an event synchronously — calls all registered handlers."""
        for handler in self._subscribers.get(event.type, []):
            try:
                handler(event)
            except Exception:
                logger.exception("Error in event handler for %s", event.type)

    async def emit_async(self, event: Event) -> None:
        """Emit an event, awaiting any async handlers."""
        for handler in self._subscribers.get(event.type, []):
            try:
                result = handler(event)
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                logger.exception("Error in async event handler for %s", event.type)
