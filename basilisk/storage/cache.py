"""Cross-run result cache backed by SQLite."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import aiosqlite

from basilisk.models.result import Finding, PluginResult, Severity
from basilisk.storage.db import close_db, open_db

logger = logging.getLogger(__name__)

# Default TTL per plugin category (hours)
DEFAULT_TTL: dict[str, float] = {
    "recon": 24.0,
    "scanning": 12.0,
    "analysis": 12.0,
    "pentesting": 6.0,
    "exploitation": 2.0,
    "post_exploit": 2.0,
    "privesc": 2.0,
    "lateral": 2.0,
    "crypto": 12.0,
    "forensics": 12.0,
}

DEFAULT_CACHE_DIR = Path.home() / ".basilisk"
DEFAULT_CACHE_DB = DEFAULT_CACHE_DIR / "cache.db"


def _reconstruct_finding(row: dict[str, Any]) -> Finding:
    """Reconstruct a Finding from a DB row."""
    tags = json.loads(row["tags"]) if isinstance(row["tags"], str) else row["tags"]
    return Finding(
        severity=Severity(row["severity"]),
        title=row["title"],
        description=row.get("description", ""),
        evidence=row.get("evidence", ""),
        remediation=row.get("remediation", ""),
        tags=tags,
    )


def _reconstruct_plugin_result(
    pd_row: dict[str, Any],
    finding_rows: list[dict[str, Any]],
) -> PluginResult:
    """Reconstruct a PluginResult from plugin_data + findings rows."""
    data = json.loads(pd_row["data"]) if isinstance(pd_row["data"], str) else pd_row["data"]
    findings = [_reconstruct_finding(f) for f in finding_rows]
    return PluginResult(
        plugin=pd_row["plugin"],
        target=pd_row["host"],
        status=pd_row["status"],
        findings=findings,
        data=data,
        duration=pd_row["duration"],
        error=pd_row.get("error"),
    )


class ResultCache:
    """Cross-run result cache backed by SQLite.

    For non-project audits: uses ~/.basilisk/cache.db.
    For project audits: uses the project's own DB.
    """

    def __init__(self, db: aiosqlite.Connection):
        self.db = db

    @classmethod
    async def open_global(cls) -> ResultCache:
        """Open the global cache database at ~/.basilisk/cache.db."""
        DEFAULT_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        db = await open_db(DEFAULT_CACHE_DB)
        return cls(db)

    @classmethod
    async def from_db(cls, db: aiosqlite.Connection) -> ResultCache:
        """Wrap an existing project DB as a cache."""
        return cls(db)

    async def close(self) -> None:
        await close_db(self.db)

    async def get_cached(
        self,
        plugin: str,
        host: str,
        max_age_hours: float,
    ) -> PluginResult | None:
        """Load a cached result if fresh enough.

        Returns None if no cached result or if it has expired.
        """
        # Find the most recent plugin_data row for this (plugin, host)
        cursor = await self.db.execute(
            """SELECT pd.*, d.host
               FROM plugin_data pd
               JOIN domains d ON pd.domain_id = d.id
               WHERE pd.plugin = ? AND d.host = ?
                 AND pd.status IN ('success', 'partial')
                 AND pd.created_at > datetime('now', ?)
               ORDER BY pd.id DESC
               LIMIT 1""",
            (plugin, host, f"-{max_age_hours} hours"),
        )
        pd_row = await cursor.fetchone()
        if not pd_row:
            return None

        pd_dict = dict(pd_row)

        # Load associated findings
        cursor = await self.db.execute(
            """SELECT f.*
               FROM findings f
               WHERE f.domain_id = ? AND f.plugin = ? AND f.run_id = ?
               ORDER BY f.severity DESC, f.id""",
            (pd_dict["domain_id"], plugin, pd_dict["run_id"]),
        )
        finding_rows = [dict(r) for r in await cursor.fetchall()]

        result = _reconstruct_plugin_result(pd_dict, finding_rows)
        logger.debug("Cache HIT: %s:%s (age OK, %d findings)", plugin, host, len(finding_rows))
        return result

    async def put(self, host: str, result: PluginResult, run_id: int | None = None) -> None:
        """Store a plugin result in cache.

        Creates a domain entry and a synthetic run if needed.
        """
        # Only cache successful or partial results
        if result.status not in ("success", "partial"):
            return

        # Ensure domain exists
        await self.db.execute(
            "INSERT OR IGNORE INTO domains (host) VALUES (?)",
            (host,),
        )
        await self.db.commit()
        cursor = await self.db.execute(
            "SELECT id FROM domains WHERE host = ?",
            (host,),
        )
        domain_row = await cursor.fetchone()
        domain_id = domain_row[0]

        # Ensure we have a run_id (use provided or create a cache run)
        if run_id is None:
            cursor = await self.db.execute(
                """SELECT id FROM scan_runs
                   WHERE project_id IS NULL AND status = 'cache'
                   ORDER BY id DESC LIMIT 1""",
            )
            row = await cursor.fetchone()
            if row:
                run_id = row[0]
            else:
                cursor = await self.db.execute(
                    "INSERT INTO scan_runs (status) VALUES ('cache')",
                )
                await self.db.commit()
                run_id = cursor.lastrowid

        # Save plugin_data
        from basilisk.storage.repo import _SafeEncoder
        await self.db.execute(
            """INSERT INTO plugin_data (run_id, domain_id, plugin, status, data, duration, error)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id, domain_id, result.plugin, result.status,
                json.dumps(result.data, cls=_SafeEncoder), result.duration, result.error,
            ),
        )

        # Save findings
        if result.findings:
            params = [
                (
                    run_id, domain_id, result.plugin, int(f.severity),
                    f.title, f.description, f.evidence,
                    f.remediation, json.dumps(f.tags),
                )
                for f in result.findings
            ]
            await self.db.executemany(
                """INSERT INTO findings (run_id, domain_id, plugin, severity,
                   title, description, evidence, remediation, tags)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                params,
            )

        await self.db.commit()
        logger.debug(
            "Cache PUT: %s:%s (%d findings)", result.plugin, host, len(result.findings),
        )

    async def invalidate(
        self,
        host: str | None = None,
        plugin: str | None = None,
    ) -> int:
        """Remove cached entries. Returns count deleted."""
        conditions: list[str] = []
        params: list[str] = []

        if host:
            conditions.append(
                "domain_id IN (SELECT id FROM domains WHERE host = ?)"
            )
            params.append(host)
        if plugin:
            conditions.append("plugin = ?")
            params.append(plugin)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        # Delete findings first (FK constraint)
        await self.db.execute(
            f"DELETE FROM findings {where}",  # noqa: S608
            params,
        )
        cursor = await self.db.execute(
            f"DELETE FROM plugin_data {where}",  # noqa: S608
            params,
        )
        await self.db.commit()
        deleted = cursor.rowcount
        logger.debug("Cache INVALIDATE: host=%s plugin=%s deleted=%d", host, plugin, deleted)
        return deleted
