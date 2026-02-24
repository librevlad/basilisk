"""SQLite persistence for the knowledge graph."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

import aiosqlite

from basilisk.knowledge.entities import Entity, EntityType
from basilisk.knowledge.relations import Relation, RelationType

if TYPE_CHECKING:
    from basilisk.knowledge.graph import KnowledgeGraph

logger = logging.getLogger(__name__)

KG_SCHEMA = """
CREATE TABLE IF NOT EXISTS kg_entities (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    data TEXT NOT NULL,
    confidence REAL DEFAULT 1.0,
    evidence TEXT DEFAULT '[]',
    observation_count INTEGER DEFAULT 1,
    first_seen TEXT,
    last_seen TEXT
);

CREATE TABLE IF NOT EXISTS kg_relations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id TEXT NOT NULL REFERENCES kg_entities(id),
    target_id TEXT NOT NULL REFERENCES kg_entities(id),
    type TEXT NOT NULL,
    confidence REAL DEFAULT 1.0,
    source_plugin TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_kg_rel_source ON kg_relations(source_id);
CREATE INDEX IF NOT EXISTS idx_kg_rel_target ON kg_relations(target_id);

CREATE TABLE IF NOT EXISTS kg_executions (
    fingerprint TEXT PRIMARY KEY,
    timestamp REAL NOT NULL
);
"""


class KnowledgeStore:
    """Persist and restore a KnowledgeGraph to/from SQLite."""

    def __init__(self, db: aiosqlite.Connection) -> None:
        self.db = db

    async def init_schema(self) -> None:
        """Create KG tables if they don't exist."""
        await self.db.executescript(KG_SCHEMA)

    async def save(self, graph: KnowledgeGraph) -> None:
        """Save entire graph to DB (upsert), including execution log."""
        for entity in graph.all_entities():
            await self.save_entity(entity)
        for relation in graph.all_relations():
            await self.save_relation(relation)
        for fp, ts in graph._execution_log.items():
            await self.db.execute(
                "INSERT OR REPLACE INTO kg_executions (fingerprint, timestamp) VALUES (?, ?)",
                (fp, ts),
            )
        await self.db.commit()

    async def save_entity(self, entity: Entity) -> None:
        """Upsert a single entity."""
        await self.db.execute(
            """INSERT INTO kg_entities (id, type, data, confidence, evidence,
                observation_count, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                data = excluded.data,
                confidence = excluded.confidence,
                evidence = excluded.evidence,
                observation_count = excluded.observation_count,
                last_seen = excluded.last_seen
            """,
            (
                entity.id,
                entity.type.value,
                json.dumps(entity.data, default=str),
                entity.confidence,
                json.dumps(entity.evidence),
                entity.observation_count,
                entity.first_seen.isoformat(),
                entity.last_seen.isoformat(),
            ),
        )

    async def save_relation(self, relation: Relation) -> None:
        """Insert a relation if it doesn't exist."""
        await self.db.execute(
            """INSERT OR IGNORE INTO kg_relations (source_id, target_id, type, confidence,
                source_plugin)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                relation.source_id,
                relation.target_id,
                relation.type.value,
                relation.confidence,
                relation.source_plugin,
            ),
        )

    async def load(self) -> KnowledgeGraph:
        """Load full graph from DB."""
        from basilisk.knowledge.graph import KnowledgeGraph

        graph = KnowledgeGraph()

        async with self.db.execute("SELECT * FROM kg_entities") as cursor:
            async for row in cursor:
                entity = Entity(
                    id=row[0],
                    type=EntityType(row[1]),
                    data=json.loads(row[2]),
                    confidence=row[3],
                    evidence=json.loads(row[4]),
                    observation_count=row[5],
                    first_seen=row[6],
                    last_seen=row[7],
                )
                graph.add_entity(entity)

        async with self.db.execute("SELECT * FROM kg_relations") as cursor:
            async for row in cursor:
                relation = Relation(
                    source_id=row[1],
                    target_id=row[2],
                    type=RelationType(row[3]),
                    confidence=row[4],
                    source_plugin=row[5],
                )
                graph.add_relation(relation)

        # Restore execution log (dedup fingerprints).
        try:
            async with self.db.execute(
                "SELECT fingerprint, timestamp FROM kg_executions",
            ) as cursor:
                async for row in cursor:
                    graph._execution_log[row[0]] = row[1]
        except Exception:
            pass  # table may not exist in older DBs

        return graph
