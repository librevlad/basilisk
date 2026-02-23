"""Async SQLite persistence for campaign memory."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import aiosqlite

from basilisk.campaign.models import (
    PluginEfficacy,
    TargetProfile,
    TechFingerprint,
    TechStackRecord,
)

logger = logging.getLogger(__name__)

CAMPAIGN_SCHEMA = """
CREATE TABLE IF NOT EXISTS target_profiles (
    host TEXT PRIMARY KEY,
    last_audited TEXT NOT NULL,
    audit_count INTEGER DEFAULT 1,
    known_services TEXT DEFAULT '[]',
    known_technologies TEXT DEFAULT '[]',
    known_endpoints_count INTEGER DEFAULT 0,
    known_findings_count INTEGER DEFAULT 0,
    finding_severities TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS plugin_efficacy (
    plugin_name TEXT PRIMARY KEY,
    total_runs INTEGER DEFAULT 0,
    total_successes INTEGER DEFAULT 0,
    total_new_entities INTEGER DEFAULT 0,
    total_findings INTEGER DEFAULT 0,
    total_runtime REAL DEFAULT 0.0,
    tech_stack_stats TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS tech_fingerprints (
    base_domain TEXT PRIMARY KEY,
    technologies TEXT DEFAULT '[]',
    observation_count INTEGER DEFAULT 1,
    last_seen TEXT NOT NULL
);
"""


class CampaignStore:
    """Persist and restore campaign memory to/from SQLite."""

    def __init__(self, db: aiosqlite.Connection) -> None:
        self.db = db

    @classmethod
    async def open(cls, path: Path | str) -> CampaignStore:
        """Open (or create) the campaign database."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        db = await aiosqlite.connect(str(path))
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA synchronous=NORMAL")
        store = cls(db)
        await store.init_schema()
        return store

    async def init_schema(self) -> None:
        """Create campaign tables if they don't exist."""
        await self.db.executescript(CAMPAIGN_SCHEMA)

    async def close(self) -> None:
        """Close the database connection."""
        await self.db.close()

    # --- Target Profiles ---

    async def save_target_profile(self, profile: TargetProfile) -> None:
        """Upsert a target profile."""
        await self.db.execute(
            """INSERT INTO target_profiles
                (host, last_audited, audit_count, known_services, known_technologies,
                 known_endpoints_count, known_findings_count, finding_severities)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(host) DO UPDATE SET
                last_audited = excluded.last_audited,
                audit_count = excluded.audit_count,
                known_services = excluded.known_services,
                known_technologies = excluded.known_technologies,
                known_endpoints_count = excluded.known_endpoints_count,
                known_findings_count = excluded.known_findings_count,
                finding_severities = excluded.finding_severities
            """,
            (
                profile.host,
                profile.last_audited.isoformat(),
                profile.audit_count,
                json.dumps([s.model_dump() for s in profile.known_services]),
                json.dumps([t.model_dump() for t in profile.known_technologies]),
                profile.known_endpoints_count,
                profile.known_findings_count,
                json.dumps(profile.finding_severities),
            ),
        )
        await self.db.commit()

    async def load_target_profile(self, host: str) -> TargetProfile | None:
        """Load a single target profile by host, or None if not found."""
        async with self.db.execute(
            "SELECT * FROM target_profiles WHERE host = ?", (host,),
        ) as cursor:
            row = await cursor.fetchone()
            if row is None:
                return None
            return self._row_to_target_profile(row)

    async def load_all_target_profiles(self) -> list[TargetProfile]:
        """Load all target profiles."""
        profiles = []
        async with self.db.execute("SELECT * FROM target_profiles") as cursor:
            async for row in cursor:
                profiles.append(self._row_to_target_profile(row))
        return profiles

    @staticmethod
    def _row_to_target_profile(row: tuple) -> TargetProfile:
        from basilisk.campaign.models import ServiceRecord, TechRecord

        return TargetProfile(
            host=row[0],
            last_audited=row[1],
            audit_count=row[2],
            known_services=[ServiceRecord(**s) for s in json.loads(row[3])],
            known_technologies=[TechRecord(**t) for t in json.loads(row[4])],
            known_endpoints_count=row[5],
            known_findings_count=row[6],
            finding_severities=json.loads(row[7]),
        )

    # --- Plugin Efficacy ---

    async def save_plugin_efficacy(self, efficacy: PluginEfficacy) -> None:
        """Upsert plugin efficacy record."""
        await self.db.execute(
            """INSERT INTO plugin_efficacy
                (plugin_name, total_runs, total_successes, total_new_entities,
                 total_findings, total_runtime, tech_stack_stats)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(plugin_name) DO UPDATE SET
                total_runs = excluded.total_runs,
                total_successes = excluded.total_successes,
                total_new_entities = excluded.total_new_entities,
                total_findings = excluded.total_findings,
                total_runtime = excluded.total_runtime,
                tech_stack_stats = excluded.tech_stack_stats
            """,
            (
                efficacy.plugin_name,
                efficacy.total_runs,
                efficacy.total_successes,
                efficacy.total_new_entities,
                efficacy.total_findings,
                efficacy.total_runtime,
                json.dumps(
                    {k: v.model_dump() for k, v in efficacy.tech_stack_stats.items()},
                ),
            ),
        )
        await self.db.commit()

    async def load_all_plugin_efficacy(self) -> list[PluginEfficacy]:
        """Load all plugin efficacy records."""
        records = []
        async with self.db.execute("SELECT * FROM plugin_efficacy") as cursor:
            async for row in cursor:
                tech_stats_raw = json.loads(row[6])
                tech_stats = {
                    k: TechStackRecord(**v) for k, v in tech_stats_raw.items()
                }
                records.append(PluginEfficacy(
                    plugin_name=row[0],
                    total_runs=row[1],
                    total_successes=row[2],
                    total_new_entities=row[3],
                    total_findings=row[4],
                    total_runtime=row[5],
                    tech_stack_stats=tech_stats,
                ))
        return records

    # --- Tech Fingerprints ---

    async def save_tech_fingerprint(self, fp: TechFingerprint) -> None:
        """Upsert a tech fingerprint."""
        await self.db.execute(
            """INSERT INTO tech_fingerprints
                (base_domain, technologies, observation_count, last_seen)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(base_domain) DO UPDATE SET
                technologies = excluded.technologies,
                observation_count = excluded.observation_count,
                last_seen = excluded.last_seen
            """,
            (
                fp.base_domain,
                json.dumps(fp.technologies),
                fp.observation_count,
                fp.last_seen.isoformat(),
            ),
        )
        await self.db.commit()

    async def load_tech_fingerprint(self, base_domain: str) -> TechFingerprint | None:
        """Load a tech fingerprint by base domain."""
        async with self.db.execute(
            "SELECT * FROM tech_fingerprints WHERE base_domain = ?", (base_domain,),
        ) as cursor:
            row = await cursor.fetchone()
            if row is None:
                return None
            return TechFingerprint(
                base_domain=row[0],
                technologies=json.loads(row[1]),
                observation_count=row[2],
                last_seen=row[3],
            )
