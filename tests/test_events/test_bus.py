"""Tests for the event bus."""

from __future__ import annotations

from basilisk.events.bus import Event, EventBus, EventType


class TestEventBus:
    def test_subscribe_and_emit(self):
        bus = EventBus()
        received = []
        bus.subscribe(EventType.ENTITY_CREATED, lambda e: received.append(e))
        bus.emit(Event(EventType.ENTITY_CREATED, {"id": "test"}))
        assert len(received) == 1
        assert received[0].data["id"] == "test"

    def test_multiple_subscribers(self):
        bus = EventBus()
        count = {"a": 0, "b": 0}
        bus.subscribe(EventType.STEP_COMPLETED, lambda _: count.__setitem__("a", count["a"] + 1))
        bus.subscribe(EventType.STEP_COMPLETED, lambda _: count.__setitem__("b", count["b"] + 1))
        bus.emit(Event(EventType.STEP_COMPLETED))
        assert count["a"] == 1
        assert count["b"] == 1

    def test_no_cross_event_delivery(self):
        bus = EventBus()
        received = []
        bus.subscribe(EventType.ENTITY_CREATED, lambda e: received.append(e))
        bus.emit(Event(EventType.PLUGIN_STARTED))
        assert len(received) == 0

    def test_handler_exception_doesnt_crash(self):
        bus = EventBus()
        received = []

        def bad_handler(e):
            raise ValueError("oops")

        bus.subscribe(EventType.ENTITY_CREATED, bad_handler)
        bus.subscribe(EventType.ENTITY_CREATED, lambda e: received.append(e))
        # Should not raise
        bus.emit(Event(EventType.ENTITY_CREATED))
        # Second handler still called
        assert len(received) == 1

    async def test_emit_async(self):
        bus = EventBus()
        received = []

        async def async_handler(e):
            received.append(e)

        bus.subscribe(EventType.ENTITY_CREATED, async_handler)
        await bus.emit_async(Event(EventType.ENTITY_CREATED, {"async": True}))
        assert len(received) == 1
