"""Repository — CRUD, bulk operations, pagination for audit data."""

from __future__ import annotations

import json
from datetime import date, datetime
from typing import Any

import aiosqlite

from basilisk.models.result import Finding, PluginResult, Severity


class _SafeEncoder(json.JSONEncoder):
    """JSON encoder that handles datetime and other non-serializable types."""

    def default(self, o: object) -> object:
        if isinstance(o, (datetime, date)):
            return o.isoformat()
        return super().default(o)


class ResultRepository:
    """Async repository for audit data. Designed for millions of records."""

    def __init__(self, db: aiosqlite.Connection, chunk_size: int = 1000):
        self.db = db
        self.chunk_size = chunk_size

    # === Domains ===

    async def insert_domain(
        self,
        host: str,
        type_: str = "domain",
        parent: str | None = None,
        project_id: int | None = None,
        ips: list[str] | None = None,
    ) -> int:
        await self.db.execute(
            """INSERT OR IGNORE INTO domains (host, type, parent, project_id, ips)
               VALUES (?, ?, ?, ?, ?)""",
            (host, type_, parent, project_id, json.dumps(ips or [])),
        )
        await self.db.commit()
        # Always SELECT to get correct ID (lastrowid unreliable with INSERT OR IGNORE)
        row = await (await self.db.execute(
            "SELECT id FROM domains WHERE host = ? AND COALESCE(project_id, -1) = COALESCE(?, -1)",
            (host, project_id),
        )).fetchone()
        return row[0] if row else 0  # type: ignore[index]

    async def bulk_insert_domains(
        self,
        domains: list[dict[str, Any]],
        project_id: int | None = None,
    ) -> int:
        """Bulk insert domains in chunks. Returns count of inserted rows."""
        total = 0
        for i in range(0, len(domains), self.chunk_size):
            chunk = domains[i : i + self.chunk_size]
            params = [
                (
                    d.get("host", d) if isinstance(d, dict) else d,
                    d.get("type", "domain") if isinstance(d, dict) else "domain",
                    d.get("parent") if isinstance(d, dict) else None,
                    project_id,
                    json.dumps(d.get("ips", [])) if isinstance(d, dict) else "[]",
                )
                for d in chunk
            ]
            await self.db.executemany(
                """INSERT OR IGNORE INTO domains (host, type, parent, project_id, ips)
                   VALUES (?, ?, ?, ?, ?)""",
                params,
            )
            total += len(chunk)
        await self.db.commit()
        return total

    async def get_domain(self, host: str, project_id: int | None = None) -> dict[str, Any] | None:
        if project_id is not None:
            cursor = await self.db.execute(
                "SELECT * FROM domains WHERE host = ? AND project_id = ?",
                (host, project_id),
            )
        else:
            cursor = await self.db.execute(
                "SELECT * FROM domains WHERE host = ? LIMIT 1", (host,)
            )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def get_domains_page(
        self,
        project_id: int | None = None,
        offset: int = 0,
        limit: int = 100,
        type_filter: str | None = None,
    ) -> list[dict[str, Any]]:
        conditions = []
        params: list[Any] = []

        if project_id is not None:
            conditions.append("project_id = ?")
            params.append(project_id)
        if type_filter:
            conditions.append("type = ?")
            params.append(type_filter)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        params.extend([limit, offset])

        cursor = await self.db.execute(
            f"SELECT * FROM domains {where} ORDER BY id LIMIT ? OFFSET ?",  # noqa: S608
            params,
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def count_domains(self, project_id: int | None = None) -> int:
        if project_id is not None:
            cursor = await self.db.execute(
                "SELECT COUNT(*) FROM domains WHERE project_id = ?",
                (project_id,),
            )
        else:
            cursor = await self.db.execute("SELECT COUNT(*) FROM domains")
        row = await cursor.fetchone()
        return row[0]  # type: ignore[index]

    # === Scan Runs ===

    async def create_run(
        self,
        project_id: int | None = None,
        plugins: list[str] | None = None,
        target_count: int = 0,
    ) -> int:
        cursor = await self.db.execute(
            """INSERT INTO scan_runs (project_id, plugins, target_count)
               VALUES (?, ?, ?)""",
            (project_id, json.dumps(plugins or []), target_count),
        )
        await self.db.commit()
        return cursor.lastrowid  # type: ignore[return-value]

    async def finish_run(self, run_id: int, status: str = "completed") -> None:
        cursor = await self.db.execute(
            "SELECT COUNT(*) FROM findings WHERE run_id = ?", (run_id,)
        )
        row = await cursor.fetchone()
        finding_count = row[0]  # type: ignore[index]

        await self.db.execute(
            """UPDATE scan_runs SET status = ?, finished_at = datetime('now'),
               finding_count = ? WHERE id = ?""",
            (status, finding_count, run_id),
        )
        await self.db.commit()

    async def get_run(self, run_id: int) -> dict[str, Any] | None:
        cursor = await self.db.execute(
            "SELECT * FROM scan_runs WHERE id = ?", (run_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    # === Findings ===

    async def insert_finding(
        self,
        run_id: int,
        domain_id: int,
        plugin: str,
        finding: Finding,
    ) -> int:
        cursor = await self.db.execute(
            """INSERT INTO findings (run_id, domain_id, plugin, severity,
               title, description, evidence, remediation, tags)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id, domain_id, plugin, int(finding.severity),
                finding.title, finding.description, finding.evidence,
                finding.remediation, json.dumps(finding.tags),
            ),
        )
        await self.db.commit()
        return cursor.lastrowid  # type: ignore[return-value]

    async def bulk_insert_findings(
        self,
        run_id: int,
        findings: list[tuple[int, str, Finding]],
    ) -> int:
        """Bulk insert findings. Each tuple: (domain_id, plugin, Finding)."""
        total = 0
        for i in range(0, len(findings), self.chunk_size):
            chunk = findings[i : i + self.chunk_size]
            params = [
                (
                    run_id, domain_id, plugin, int(f.severity),
                    f.title, f.description, f.evidence,
                    f.remediation, json.dumps(f.tags),
                )
                for domain_id, plugin, f in chunk
            ]
            await self.db.executemany(
                """INSERT INTO findings (run_id, domain_id, plugin, severity,
                   title, description, evidence, remediation, tags)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                params,
            )
            total += len(chunk)
        await self.db.commit()
        return total

    async def get_findings(
        self,
        run_id: int | None = None,
        severity: Severity | None = None,
        plugin: str | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        conditions = []
        params: list[Any] = []

        if run_id is not None:
            conditions.append("f.run_id = ?")
            params.append(run_id)
        if severity is not None:
            conditions.append("f.severity = ?")
            params.append(int(severity))
        if plugin:
            conditions.append("f.plugin = ?")
            params.append(plugin)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        params.extend([limit, offset])

        cursor = await self.db.execute(
            f"""SELECT f.*, d.host FROM findings f
                JOIN domains d ON f.domain_id = d.id
                {where}
                ORDER BY f.severity DESC, f.id
                LIMIT ? OFFSET ?""",  # noqa: S608
            params,
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def count_findings(
        self,
        run_id: int | None = None,
        severity: Severity | None = None,
    ) -> int:
        conditions = []
        params: list[Any] = []

        if run_id is not None:
            conditions.append("run_id = ?")
            params.append(run_id)
        if severity is not None:
            conditions.append("severity = ?")
            params.append(int(severity))

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        cursor = await self.db.execute(
            f"SELECT COUNT(*) FROM findings {where}",  # noqa: S608
            params,
        )
        row = await cursor.fetchone()
        return row[0]  # type: ignore[index]

    # === Plugin Data ===

    async def save_plugin_result(
        self,
        run_id: int,
        domain_id: int,
        result: PluginResult,
    ) -> int:
        cursor = await self.db.execute(
            """INSERT INTO plugin_data (run_id, domain_id, plugin, status,
               data, duration, error)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id, domain_id, result.plugin, result.status,
                json.dumps(result.data, cls=_SafeEncoder), result.duration, result.error,
            ),
        )
        await self.db.commit()
        return cursor.lastrowid  # type: ignore[return-value]

    # === Cache-aware loading ===

    async def load_findings_for_result(
        self,
        run_id: int,
        domain_id: int,
        plugin: str,
    ) -> list[Finding]:
        """Load Finding objects from the findings table."""
        cursor = await self.db.execute(
            """SELECT severity, title, description, evidence, remediation, tags
               FROM findings
               WHERE run_id = ? AND domain_id = ? AND plugin = ?
               ORDER BY severity DESC, id""",
            (run_id, domain_id, plugin),
        )
        results = []
        for row in await cursor.fetchall():
            row_dict = dict(row)
            tags = row_dict["tags"]
            if isinstance(tags, str):
                tags = json.loads(tags)
            results.append(Finding(
                severity=Severity(row_dict["severity"]),
                title=row_dict["title"],
                description=row_dict.get("description", ""),
                evidence=row_dict.get("evidence", ""),
                remediation=row_dict.get("remediation", ""),
                tags=tags,
            ))
        return results

    async def load_plugin_result(
        self,
        plugin: str,
        host: str,
        max_age_hours: float,
    ) -> PluginResult | None:
        """Load cached plugin result if fresh enough.

        Queries plugin_data + findings tables, reconstructs PluginResult.
        Returns None if no fresh result exists.
        """
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
        findings = await self.load_findings_for_result(
            pd_dict["run_id"], pd_dict["domain_id"], plugin,
        )

        data = pd_dict["data"]
        if isinstance(data, str):
            data = json.loads(data)

        return PluginResult(
            plugin=pd_dict["plugin"],
            target=pd_dict["host"],
            status=pd_dict["status"],
            findings=findings,
            data=data,
            duration=pd_dict["duration"],
            error=pd_dict.get("error"),
        )

    # === Stats ===

    async def stats(self, run_id: int | None = None) -> dict[str, Any]:
        """Quick stats using indexed queries."""
        result: dict[str, Any] = {}

        if run_id:
            cond, params = "WHERE run_id = ?", [run_id]
        else:
            cond, params = "", []

        # Severity distribution
        cursor = await self.db.execute(
            f"SELECT severity, COUNT(*) as cnt FROM findings {cond} GROUP BY severity",  # noqa: S608
            params,
        )
        severity_counts = {Severity(row[0]).label: row[1] for row in await cursor.fetchall()}
        result["findings_by_severity"] = severity_counts
        result["total_findings"] = sum(severity_counts.values())

        # Domain count
        cursor = await self.db.execute("SELECT COUNT(*) FROM domains")
        row = await cursor.fetchone()
        result["total_domains"] = row[0]  # type: ignore[index]

        # Top plugins
        cursor = await self.db.execute(
            f"""SELECT plugin, COUNT(*) as cnt FROM findings {cond}
                GROUP BY plugin ORDER BY cnt DESC LIMIT 10""",  # noqa: S608
            params,
        )
        result["top_plugins"] = {row[0]: row[1] for row in await cursor.fetchall()}

        return result

    # === Resume support ===

    async def get_incomplete_run(self, project_id: int) -> dict[str, Any] | None:
        """Find the latest 'running' scan_run for resume."""
        cursor = await self.db.execute(
            "SELECT * FROM scan_runs WHERE project_id = ? AND status = 'running' "
            "ORDER BY id DESC LIMIT 1",
            (project_id,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def get_completed_pairs(self, run_id: int) -> set[tuple[str, str]]:
        """Return {(plugin_name, host), ...} already completed in this run."""
        cursor = await self.db.execute(
            "SELECT pd.plugin, d.host FROM plugin_data pd "
            "JOIN domains d ON pd.domain_id = d.id "
            "WHERE pd.run_id = ?",
            (run_id,),
        )
        return {(row[0], row[1]) for row in await cursor.fetchall()}

    async def get_run_domains(self, project_id: int) -> list[dict[str, Any]]:
        """Get all domains discovered for a project (for scope rebuild)."""
        cursor = await self.db.execute(
            "SELECT host, type, parent FROM domains WHERE project_id = ?",
            (project_id,),
        )
        return [dict(row) for row in await cursor.fetchall()]
