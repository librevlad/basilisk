"""Canonical report model — single source of truth for all renderers."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

REPORT_SCHEMA_VERSION = "4.1"


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
        from basilisk.knowledge.identity import vulnerability_id

        return vulnerability_id(target, surface, vuln_type, proof_key)


class TimelineEvent(BaseModel, frozen=True):
    """A single event in the execution timeline."""

    timestamp: datetime
    scenario: str
    action: str  # SessionEventType values
    result: dict[str, Any] = Field(default_factory=dict)
    step: int = 0


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
    """Training validation results."""

    profile_name: str = ""
    expected_total: int = 0
    detected: int = 0
    missed: list[dict[str, Any]] = Field(default_factory=list)
    false_positives: list[dict[str, Any]] = Field(default_factory=list)
    coverage_percent: float = 0.0
    verification_rate: float = 0.0
    passed: bool = False


class ReportReasoningEvent(BaseModel, frozen=True):
    """A single reasoning event (hypothesis/belief change)."""

    event_type: str
    step: int = 0
    data: dict[str, Any] = Field(default_factory=dict)


class ReasoningSection(BaseModel, frozen=True):
    """Structured reasoning trace for the report."""

    hypotheses_confirmed: int = 0
    hypotheses_rejected: int = 0
    beliefs_strengthened: int = 0
    beliefs_weakened: int = 0
    events: list[ReportReasoningEvent] = Field(default_factory=list)


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
    reasoning: ReasoningSection = Field(default_factory=ReasoningSection)
    topology: dict[str, Any] = Field(default_factory=dict)
