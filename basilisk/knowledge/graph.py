"""Knowledge graph — in-memory entity/relation store with dedup and queries."""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import TYPE_CHECKING, Any

from basilisk.knowledge.entities import Entity, EntityType
from basilisk.knowledge.relations import Relation, RelationType
from basilisk.models.target import Target, TargetType

if TYPE_CHECKING:
    from basilisk.orchestrator.planner import KnowledgeGap

logger = logging.getLogger(__name__)


class KnowledgeGraph:
    """In-memory graph of entities and relations.

    Supports deterministic dedup, confidence merging, gap detection,
    and execution tracking.
    """

    def __init__(self) -> None:
        self._entities: dict[str, Entity] = {}
        self._relations: list[Relation] = []
        self._relation_index: dict[str, list[Relation]] = defaultdict(list)
        self._reverse_index: dict[str, list[Relation]] = defaultdict(list)
        self._execution_log: dict[str, float] = {}  # fingerprint → timestamp

    @property
    def entity_count(self) -> int:
        return len(self._entities)

    @property
    def relation_count(self) -> int:
        return len(self._relations)

    def add_entity(self, entity: Entity) -> Entity:
        """Add a new entity. If same ID exists, merge instead."""
        existing = self._entities.get(entity.id)
        if existing:
            return self.merge_entity(entity)
        self._entities[entity.id] = entity
        return entity

    def merge_entity(self, entity: Entity) -> Entity:
        """Merge entity with existing one of same ID.

        Confidence merge: 1 - (1-old) * (1-new)  (probabilistic OR)
        Data: new keys override old
        """
        existing = self._entities.get(entity.id)
        if not existing:
            self._entities[entity.id] = entity
            return entity

        # Probabilistic OR for confidence
        merged_confidence = 1.0 - (1.0 - existing.confidence) * (1.0 - entity.confidence)
        merged_confidence = min(merged_confidence, 1.0)

        # Merge data (new overrides)
        merged_data = {**existing.data, **entity.data}

        # Merge evidence
        merged_evidence = list(existing.evidence)
        for e in entity.evidence:
            if e not in merged_evidence:
                merged_evidence.append(e)

        existing.confidence = merged_confidence
        existing.data = merged_data
        existing.evidence = merged_evidence
        existing.observation_count += entity.observation_count
        existing.last_seen = max(existing.last_seen, entity.last_seen)

        return existing

    def add_relation(self, relation: Relation) -> None:
        """Add a relation. Deduplicates by (source, target, type)."""
        for existing in self._relation_index[relation.source_id]:
            if existing.target_id == relation.target_id and existing.type == relation.type:
                return  # already exists
        self._relations.append(relation)
        self._relation_index[relation.source_id].append(relation)
        self._reverse_index[relation.target_id].append(relation)

    def get(self, entity_id: str) -> Entity | None:
        """Get entity by ID."""
        return self._entities.get(entity_id)

    def query(self, entity_type: EntityType, **filters: Any) -> list[Entity]:
        """Query entities by type and optional data field filters."""
        results = []
        for entity in self._entities.values():
            if entity.type != entity_type:
                continue
            if filters:
                match = all(entity.data.get(k) == v for k, v in filters.items())
                if not match:
                    continue
            results.append(entity)
        return results

    def neighbors(
        self, entity_id: str, relation_type: RelationType | None = None,
    ) -> list[Entity]:
        """Get entities connected FROM entity_id via outgoing relations."""
        results = []
        for rel in self._relation_index.get(entity_id, []):
            if relation_type and rel.type != relation_type:
                continue
            target = self._entities.get(rel.target_id)
            if target:
                results.append(target)
        return results

    def reverse_neighbors(
        self, entity_id: str, relation_type: RelationType | None = None,
    ) -> list[Entity]:
        """Get entities connected TO entity_id via incoming relations."""
        results = []
        for rel in self._reverse_index.get(entity_id, []):
            if relation_type and rel.type != relation_type:
                continue
            source = self._entities.get(rel.source_id)
            if source:
                results.append(source)
        return results

    def outgoing_relations(
        self, entity_id: str, relation_type: RelationType | None = None,
    ) -> list[Relation]:
        """Get outgoing relations from an entity."""
        rels = self._relation_index.get(entity_id, [])
        if relation_type:
            return [r for r in rels if r.type == relation_type]
        return list(rels)

    def hosts(self) -> list[Entity]:
        """Get all Host entities."""
        return self.query(EntityType.HOST)

    def services(self) -> list[Entity]:
        """Get all Service entities."""
        return self.query(EntityType.SERVICE)

    def endpoints(self) -> list[Entity]:
        """Get all Endpoint entities."""
        return self.query(EntityType.ENDPOINT)

    def technologies(self) -> list[Entity]:
        """Get all Technology entities."""
        return self.query(EntityType.TECHNOLOGY)

    def findings(self) -> list[Entity]:
        """Get all Finding entities."""
        return self.query(EntityType.FINDING)

    def to_targets(self) -> list[Target]:
        """Convert Host entities back to Target objects for plugin execution."""
        targets = []
        for entity in self.hosts():
            host = entity.data.get("host", "")
            target_type = entity.data.get("type", "domain")

            if target_type == "subdomain":
                parent = entity.data.get("parent", "")
                targets.append(Target.subdomain(host, parent=parent))
            elif target_type == "ip":
                targets.append(Target.ip(host))
            else:
                targets.append(Target.domain(host))
        return targets

    def entity_to_target(self, entity: Entity) -> Target:
        """Convert a single Host entity to a Target object."""
        host = entity.data.get("host", "")
        target_type = entity.data.get("type", "domain")

        if target_type == TargetType.SUBDOMAIN:
            parent = entity.data.get("parent", "")
            return Target.subdomain(host, parent=parent)
        if target_type == TargetType.IP:
            return Target.ip(host)
        return Target.domain(host)

    def find_missing_knowledge(self) -> list[KnowledgeGap]:
        """Delegate gap detection to the planner module."""
        from basilisk.orchestrator.planner import Planner
        return Planner().find_gaps(self)

    def record_execution(self, fingerprint: str) -> None:
        """Record that a capability was executed (for dedup)."""
        import time
        self._execution_log[fingerprint] = time.monotonic()

    def was_executed(self, fingerprint: str) -> bool:
        """Check if a capability fingerprint was already run."""
        return fingerprint in self._execution_log

    def all_entities(self) -> list[Entity]:
        """Return all entities."""
        return list(self._entities.values())

    def all_relations(self) -> list[Relation]:
        """Return all relations."""
        return list(self._relations)

    def clear(self) -> None:
        """Reset the graph."""
        self._entities.clear()
        self._relations.clear()
        self._relation_index.clear()
        self._reverse_index.clear()
        self._execution_log.clear()
