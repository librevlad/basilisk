"""KnowledgeSnapshotStore — maintains a snapshot of discovered knowledge.

Provides immutable KnowledgeSnapshot for diff-based UI rendering.
Tracks ENTITY_CREATED/UPDATED/FINDING_VERIFIED/STEP_COMPLETED events.
The snapshot changes only when knowledge changes (fingerprint-gated).

NOTE: This module does NOT import basilisk.events to satisfy the
knowledge → events dependency constraint. Callers wire up event
subscriptions via subscribe() which accepts any bus-like object.
"""

from __future__ import annotations

import contextlib
import hashlib
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class KnowledgeSnapshot:
    """Immutable point-in-time view of discovered knowledge.

    Used by display layer for diff-based rendering — update only when
    the fingerprint changes.
    """

    domains: frozenset[str] = field(default_factory=frozenset)
    ports: frozenset[tuple[str, int, str]] = field(default_factory=frozenset)
    endpoints: frozenset[tuple[str, str]] = field(default_factory=frozenset)
    surfaces: frozenset[tuple[str, str]] = field(default_factory=frozenset)
    technologies: frozenset[tuple[str, str]] = field(default_factory=frozenset)
    findings_verified: tuple[dict[str, Any], ...] = ()
    entity_count: int = 0
    relation_count: int = 0
    step: int = 0
    fingerprint: str = ""


class KnowledgeSnapshotStore:
    """EventBus subscriber that maintains a snapshot of discovered knowledge.

    Reads ENTITY_CREATED/UPDATED/FINDING_VERIFIED events.
    Provides snapshot() for UI consumption.
    """

    def __init__(self) -> None:
        self._domains: set[str] = set()
        self._ports: set[tuple[str, int, str]] = set()
        self._endpoints: set[tuple[str, str]] = set()
        self._surfaces: set[tuple[str, str]] = set()
        self._technologies: set[tuple[str, str]] = set()
        self._findings: list[dict[str, Any]] = []
        self._entity_count: int = 0
        self._relation_count: int = 0
        self._step: int = 0
        self._fingerprint: str = ""
        self._dirty: bool = True

    def subscribe(self, bus: Any) -> None:
        """Subscribe to relevant EventBus events.

        Accepts any bus with a ``subscribe(event_type, handler)`` method.
        Uses string event types to avoid importing basilisk.events.
        """
        bus.subscribe("entity_created", self._on_entity_created)
        bus.subscribe("entity_updated", self._on_entity_updated)
        bus.subscribe("finding_verified", self._on_finding_verified)
        bus.subscribe("step_completed", self._on_step_completed)

    def snapshot(self) -> KnowledgeSnapshot:
        """Return frozen snapshot. Cheap — no graph queries."""
        if self._dirty:
            self._fingerprint = self._compute_fingerprint()
            self._dirty = False

        return KnowledgeSnapshot(
            domains=frozenset(self._domains),
            ports=frozenset(self._ports),
            endpoints=frozenset(self._endpoints),
            surfaces=frozenset(self._surfaces),
            technologies=frozenset(self._technologies),
            findings_verified=tuple(self._findings),
            entity_count=self._entity_count,
            relation_count=self._relation_count,
            step=self._step,
            fingerprint=self._fingerprint,
        )

    def _on_entity_created(self, event: Any) -> None:
        """Route to appropriate set based on entity_type."""
        entity_type = event.data.get("entity_type", "")
        self._route_entity(entity_type, event.data)
        self._dirty = True

    def _on_entity_updated(self, event: Any) -> None:
        """Entity updates may change knowledge."""
        entity_type = event.data.get("entity_type", "")
        self._route_entity(entity_type, event.data)
        self._dirty = True

    def _on_finding_verified(self, event: Any) -> None:
        """Mark a finding as verified."""
        title = event.data.get("title", "")
        for f in self._findings:
            if f.get("title") == title:
                f["verified"] = True
                self._dirty = True
                break

    def _on_step_completed(self, event: Any) -> None:
        """Update entity/relation totals and step counter."""
        self._step = event.data.get("step", self._step)
        self._entity_count = event.data.get("entities", self._entity_count)
        self._relation_count = event.data.get("relations", self._relation_count)
        self._dirty = True

    def _route_entity(self, entity_type: str, data: dict[str, Any]) -> None:
        """Add data to the appropriate set based on entity type."""
        host = data.get("host", "")
        key_data = data.get("key_data", "")

        if entity_type == "host" and host:
            self._domains.add(host)

        elif entity_type == "service":
            port = data.get("port", 0)
            service_name = data.get("service", "")
            # Try to extract from key_data if not in direct fields
            if not port and key_data:
                for part in key_data.split():
                    if part.startswith("port="):
                        with contextlib.suppress(ValueError, IndexError):
                            port = int(part.split("=")[1])
            if host and port:
                self._ports.add((host, port, service_name))

        elif entity_type == "endpoint":
            path = data.get("path", "")
            if not path and key_data:
                for part in key_data.split():
                    if part.startswith("path="):
                        path = part.split("=", 1)[1]
            if host and path:
                self._endpoints.add((host, path))

        elif entity_type == "technology":
            tech = data.get("technology", "") or data.get("name", "")
            if host and tech:
                self._technologies.add((host, tech))

        elif entity_type == "finding":
            title = data.get("title", "")
            if title:
                severity = data.get("severity", "info")
                self._findings.append({
                    "title": title,
                    "severity": severity,
                    "host": host,
                    "verified": False,
                })
                if host:
                    self._surfaces.add((host, f"finding:{severity}"))

    def _compute_fingerprint(self) -> str:
        """Hash of all sets — changes only when knowledge changes."""
        parts = [
            str(sorted(self._domains)),
            str(sorted(self._ports)),
            str(sorted(self._endpoints)),
            str(sorted(self._technologies)),
            str(len(self._findings)),
            str(self._entity_count),
            str(self._relation_count),
        ]
        raw = "|".join(parts)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]
