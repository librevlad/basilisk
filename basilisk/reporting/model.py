"""Canonical report model — single source of truth for all renderers."""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

REPORT_SCHEMA_VERSION = "4.0"


class VulnerabilityInstance(BaseModel, frozen=True):
    """A deduplicated vulnerability aggregated from multiple findings."""

    vulnerability_id: str
    vuln_type: str
    severity: str
    affected_surfaces: list[str]
    scenarios: list[str]
    confidence_aggregate: float
    proofs: list[str]
    reproduction_steps: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_confirmed: datetime | None = None

    @staticmethod
    def make_id(target: str, surface: str, vuln_type: str, proof_key: str) -> str:
        """Deterministic SHA256[:16] identity hash."""
        raw = f"{target}|{surface}|{vuln_type}|{proof_key}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


class TimelineEvent(BaseModel, frozen=True):
    """A single event in the execution timeline."""

    timestamp: datetime
    scenario: str
    action: str  # "started"|"completed"|"failed"|"finding_created"|"verification_passed"
    result: dict[str, Any] = Field(default_factory=dict)


class ReportStatistics(BaseModel, frozen=True):
    """Pre-computed statistics — renderers never recompute."""

    scenarios_executed: int = 0
    requests_sent: int = 0
    findings_total: int = 0
    steps_completed: int = 0
    max_steps: int = 100
    duration_seconds: float = 0.0
    severity_counts: dict[str, int] = Field(default_factory=dict)
    risk_score: float = 0.0
    total_entities: int = 0
    total_relations: int = 0
    total_gaps: int = 0
    entity_counts: dict[str, int] = Field(default_factory=dict)
    kill_chain_coverage: dict[str, int] = Field(default_factory=dict)


class TrainingSection(BaseModel, frozen=True):
    """Training validation results — computed by TrainingReportBuilder."""

    profile_name: str = ""
    expected_total: int = 0
    detected: int = 0
    missed: list[dict[str, Any]] = Field(default_factory=list)
    false_positives: list[dict[str, Any]] = Field(default_factory=list)
    coverage_percent: float = 0.0
    verification_rate: float = 0.0
    passed: bool = False


class ReportModel(BaseModel, frozen=True):
    """Canonical frozen report — single source of truth for ALL renderers.

    Built once by ReportBuilder, consumed by HTML/JSON/CLI renderers.
    Renderers must NOT recompute anything — all data is pre-baked.
    """

    schema_version: str = REPORT_SCHEMA_VERSION
    scan_id: str = ""
    target: str = ""
    mode: str = "auto"
    status: str = "running"
    started_at: datetime | None = None
    finished_at: datetime | None = None
    termination_reason: str = ""
    statistics: ReportStatistics = Field(default_factory=ReportStatistics)
    vulnerabilities: list[VulnerabilityInstance] = Field(default_factory=list)
    execution_timeline: list[TimelineEvent] = Field(default_factory=list)
    training: TrainingSection | None = None
    findings_raw: list[dict[str, Any]] = Field(default_factory=list)
    decisions: list[dict[str, Any]] = Field(default_factory=list)
    plugins_raw: list[dict[str, Any]] = Field(default_factory=list)
    step_history: list[dict[str, Any]] = Field(default_factory=list)
    reasoning: dict[str, Any] = Field(default_factory=dict)
