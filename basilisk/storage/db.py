"""SQLite database engine — WAL mode, optimized for millions of records."""

from __future__ import annotations

from pathlib import Path

import aiosqlite

SCHEMA_VERSION = 1

PRAGMAS = [
    "PRAGMA journal_mode = WAL",
    "PRAGMA synchronous = NORMAL",
    "PRAGMA cache_size = -65536",       # 64MB
    "PRAGMA mmap_size = 2147483648",    # 2GB
    "PRAGMA foreign_keys = ON",
    "PRAGMA temp_store = MEMORY",
    "PRAGMA busy_timeout = 5000",
]

SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    path TEXT NOT NULL,
    config TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'created',
    description TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'domain',
    parent TEXT,
    project_id INTEGER,
    ips TEXT NOT NULL DEFAULT '[]',
    first_seen TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_domains_host_project
    ON domains(host, COALESCE(project_id, -1));
CREATE INDEX IF NOT EXISTS idx_domains_host ON domains(host);
CREATE INDEX IF NOT EXISTS idx_domains_project ON domains(project_id);
CREATE INDEX IF NOT EXISTS idx_domains_parent ON domains(parent);
CREATE INDEX IF NOT EXISTS idx_domains_type ON domains(type);

CREATE TABLE IF NOT EXISTS scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER,
    plugins TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'running',
    started_at TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at TEXT,
    target_count INTEGER NOT NULL DEFAULT 0,
    finding_count INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_runs_project ON scan_runs(project_id);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    domain_id INTEGER NOT NULL,
    plugin TEXT NOT NULL,
    severity INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    evidence TEXT NOT NULL DEFAULT '',
    remediation TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (run_id) REFERENCES scan_runs(id) ON DELETE CASCADE,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_domain ON findings(domain_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_plugin ON findings(plugin);
CREATE INDEX IF NOT EXISTS idx_findings_run_severity ON findings(run_id, severity);

CREATE TABLE IF NOT EXISTS plugin_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    domain_id INTEGER NOT NULL,
    plugin TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'success',
    data TEXT NOT NULL DEFAULT '{}',
    duration REAL NOT NULL DEFAULT 0.0,
    error TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (run_id) REFERENCES scan_runs(id) ON DELETE CASCADE,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_pdata_run ON plugin_data(run_id);
CREATE INDEX IF NOT EXISTS idx_pdata_domain ON plugin_data(domain_id);
CREATE INDEX IF NOT EXISTS idx_pdata_plugin ON plugin_data(plugin);
"""


async def open_db(db_path: str | Path) -> aiosqlite.Connection:
    """Open database with WAL mode and performance pragmas."""
    db = await aiosqlite.connect(str(db_path))
    db.row_factory = aiosqlite.Row

    for pragma in PRAGMAS:
        await db.execute(pragma)

    await db.executescript(SCHEMA)

    # Set schema version if empty
    cursor = await db.execute("SELECT COUNT(*) FROM schema_version")
    row = await cursor.fetchone()
    if row[0] == 0:
        await db.execute(
            "INSERT INTO schema_version (version) VALUES (?)", (SCHEMA_VERSION,)
        )
    await db.commit()
    return db


async def close_db(db: aiosqlite.Connection) -> None:
    """Cleanly close database."""
    await db.commit()
    await db.close()
