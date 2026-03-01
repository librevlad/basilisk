"""Tests for KnowledgeSnapshotStore — snapshot facade for display layer."""

from __future__ import annotations

from basilisk.events.bus import Event, EventBus, EventType
from basilisk.knowledge.snapshot import KnowledgeSnapshot, KnowledgeSnapshotStore


class TestKnowledgeSnapshot:
    """Test KnowledgeSnapshot immutability."""

    def test_frozen(self):
        snap = KnowledgeSnapshot()
        try:
            snap.step = 5  # type: ignore[misc]
            raise AssertionError("Should be frozen")
        except AttributeError:
            pass

    def test_default_empty(self):
        snap = KnowledgeSnapshot()
        assert snap.domains == frozenset()
        assert snap.ports == frozenset()
        assert snap.endpoints == frozenset()
        assert snap.entity_count == 0
        assert snap.fingerprint == ""


class TestKnowledgeSnapshotStore:
    """Test KnowledgeSnapshotStore event handling and snapshot generation."""

    def _make(self) -> tuple[EventBus, KnowledgeSnapshotStore]:
        bus = EventBus()
        store = KnowledgeSnapshotStore()
        store.subscribe(bus)
        return bus, store

    def test_host_entity_populates_domains(self):
        bus, store = self._make()
        bus.emit(Event(EventType.ENTITY_CREATED, {
            "entity_type": "host",
            "host": "example.com",
        }))
        snap = store.snapshot()
        assert "example.com" in snap.domains

    def test_service_entity_populates_ports(self):
        bus, store = self._make()
        bus.emit(Event(EventType.ENTITY_CREATED, {
            "entity_type": "service",
            "host": "example.com",
            "port": 443,
            "service": "https",
        }))
        snap = store.snapshot()
        assert ("example.com", 443, "https") in snap.ports

    def test_service_entity_from_key_data(self):
        bus, store = self._make()
        bus.emit(Event(EventType.ENTITY_CREATED, {
            "entity_type": "service",
            "host": "example.com",
            "key_data": "host=example.com port=80",
            "service": "http",
        }))
        snap = store.snapshot()
        assert ("example.com", 80, "http") in snap.ports

    def test_endpoint_entity_populates_endpoints(self):
        bus, store = self._make()
        bus.emit(Event(EventType.ENTITY_CREATED, {
            "entity_type": "endpoint",
            "host": "example.com",
            "path": "/api/users",
        }))
        snap = store.snapshot()
        assert ("example.com", "/api/users") in snap.endpoints

    def test_technology_entity_populates_technologies(self):
        bus, store = self._make()
        bus.emit(Event(EventType.ENTITY_CREATED, {
            "entity_type": "technology",
            "host": "example.com",
            "technology": "nginx",
        }))
        snap = store.snapshot()
        assert ("example.com", "nginx") in snap.technologies

    def test_finding_entity_populates_findings(self):
        bus, store = self._make()
        bus.emit(Event(EventType.ENTITY_CREATED, {
            "entity_type": "finding",
            "host": "example.com",
            "title": "SQL Injection",
            "severity": "high",
        }))
        snap = store.snapshot()
        assert len(snap.findings_verified) == 1
        assert snap.findings_verified[0]["title"] == "SQL Injection"
        assert snap.findings_verified[0]["verified"] is False

    def test_finding_verified_updates(self):
        bus, store = self._make()
        bus.emit(Event(EventType.ENTITY_CREATED, {
            "entity_type": "finding",
            "host": "example.com",
            "title": "XSS",
            "severity": "medium",
        }))
        bus.emit(Event(EventType.FINDING_VERIFIED, {"title": "XSS"}))
        snap = store.snapshot()
        assert snap.findings_verified[0]["verified"] is True

    def test_step_completed_updates_totals(self):
        bus, store = self._make()
        bus.emit(Event(EventType.STEP_COMPLETED, {
            "step": 5,
            "entities": 42,
            "relations": 15,
        }))
        snap = store.snapshot()
        assert snap.step == 5
        assert snap.entity_count == 42
        assert snap.relation_count == 15

    def test_snapshot_is_frozen(self):
        bus, store = self._make()
        bus.emit(Event(EventType.ENTITY_CREATED, {
            "entity_type": "host",
            "host": "example.com",
        }))
        snap = store.snapshot()
        try:
            snap.step = 10  # type: ignore[misc]
            raise AssertionError("Should be frozen")
        except AttributeError:
            pass

    def test_fingerprint_changes_on_new_knowledge(self):
        bus, store = self._make()
        snap1 = store.snapshot()
        fp1 = snap1.fingerprint

        bus.emit(Event(EventType.ENTITY_CREATED, {
            "entity_type": "host",
            "host": "new.example.com",
        }))
        snap2 = store.snapshot()
        fp2 = snap2.fingerprint

        assert fp1 != fp2

    def test_fingerprint_stable_without_changes(self):
        bus, store = self._make()
        bus.emit(Event(EventType.ENTITY_CREATED, {
            "entity_type": "host",
            "host": "example.com",
        }))
        snap1 = store.snapshot()
        snap2 = store.snapshot()
        assert snap1.fingerprint == snap2.fingerprint

    def test_duplicate_entities_dont_change_fingerprint(self):
        bus, store = self._make()
        bus.emit(Event(EventType.ENTITY_CREATED, {
            "entity_type": "host",
            "host": "example.com",
        }))
        snap1 = store.snapshot()

        # Emit same entity again
        bus.emit(Event(EventType.ENTITY_CREATED, {
            "entity_type": "host",
            "host": "example.com",
        }))
        snap2 = store.snapshot()

        # Domains set didn't change, but dirty flag was set
        # fingerprint should be same since domains set is identical
        assert snap1.fingerprint == snap2.fingerprint

    def test_multiple_entity_types(self):
        bus, store = self._make()
        bus.emit(Event(EventType.ENTITY_CREATED, {
            "entity_type": "host", "host": "example.com",
        }))
        bus.emit(Event(EventType.ENTITY_CREATED, {
            "entity_type": "service", "host": "example.com",
            "port": 80, "service": "http",
        }))
        bus.emit(Event(EventType.ENTITY_CREATED, {
            "entity_type": "endpoint", "host": "example.com",
            "path": "/login",
        }))
        bus.emit(Event(EventType.ENTITY_CREATED, {
            "entity_type": "technology", "host": "example.com",
            "technology": "Apache",
        }))
        snap = store.snapshot()
        assert len(snap.domains) == 1
        assert len(snap.ports) == 1
        assert len(snap.endpoints) == 1
        assert len(snap.technologies) == 1

    def test_entity_updated_triggers_dirty(self):
        bus, store = self._make()
        bus.emit(Event(EventType.ENTITY_CREATED, {
            "entity_type": "host", "host": "example.com",
        }))
        snap1 = store.snapshot()

        bus.emit(Event(EventType.ENTITY_UPDATED, {
            "entity_type": "host", "host": "new.example.com",
        }))
        snap2 = store.snapshot()
        assert snap1.fingerprint != snap2.fingerprint
