"""Campaign memory data models."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field


class ServiceRecord(BaseModel):
    """Remembered service on a host."""

    port: int
    protocol: str = "tcp"
    service: str = ""


class TechRecord(BaseModel):
    """Remembered technology on a host."""

    name: str
    version: str = ""
    is_cms: bool = False
    is_waf: bool = False


class TargetProfile(BaseModel):
    """Persistent profile of a previously-audited host."""

    host: str
    last_audited: datetime = Field(default_factory=lambda: datetime.now(UTC))
    audit_count: int = 1
    known_services: list[ServiceRecord] = Field(default_factory=list)
    known_technologies: list[TechRecord] = Field(default_factory=list)
    known_endpoints_count: int = 0
    known_findings_count: int = 0
    finding_severities: dict[str, int] = Field(default_factory=dict)


class TechStackRecord(BaseModel):
    """Per-tech-stack execution statistics for a plugin."""

    runs: int = 0
    successes: int = 0
    new_entities: int = 0
    findings: int = 0

    @property
    def success_rate(self) -> float:
        if self.runs == 0:
            return 0.0
        return self.successes / self.runs


class PluginEfficacy(BaseModel):
    """Accumulated cross-audit statistics for a single plugin."""

    plugin_name: str
    total_runs: int = 0
    total_successes: int = 0
    total_new_entities: int = 0
    total_findings: int = 0
    total_runtime: float = 0.0
    tech_stack_stats: dict[str, TechStackRecord] = Field(default_factory=dict)

    @property
    def success_rate(self) -> float:
        if self.total_runs == 0:
            return 0.0
        return self.total_successes / self.total_runs

    def tech_stack_key(self, techs: list[str]) -> str:
        """Build a canonical key from a list of technology names."""
        return ",".join(sorted(t.lower() for t in techs if t))


class TechFingerprint(BaseModel):
    """Technology stack pattern observed on a base domain."""

    base_domain: str
    technologies: list[str] = Field(default_factory=list)
    observation_count: int = 1
    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
