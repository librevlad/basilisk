"""Result models — findings and plugin outputs."""

from __future__ import annotations

from enum import IntEnum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Severity(IntEnum):
    """Finding severity levels, ordered by criticality."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name

    @property
    def color(self) -> str:
        return {
            Severity.INFO: "blue",
            Severity.LOW: "green",
            Severity.MEDIUM: "yellow",
            Severity.HIGH: "red",
            Severity.CRITICAL: "bold red",
        }[self]


class Finding(BaseModel):
    """A single security finding."""

    severity: Severity
    title: str
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    tags: list[str] = Field(default_factory=list)

    @classmethod
    def critical(cls, title: str, **kwargs: Any) -> Finding:
        return cls(severity=Severity.CRITICAL, title=title, **kwargs)

    @classmethod
    def high(cls, title: str, **kwargs: Any) -> Finding:
        return cls(severity=Severity.HIGH, title=title, **kwargs)

    @classmethod
    def medium(cls, title: str, **kwargs: Any) -> Finding:
        return cls(severity=Severity.MEDIUM, title=title, **kwargs)

    @classmethod
    def low(cls, title: str, **kwargs: Any) -> Finding:
        return cls(severity=Severity.LOW, title=title, **kwargs)

    @classmethod
    def info(cls, title: str, **kwargs: Any) -> Finding:
        return cls(severity=Severity.INFO, title=title, **kwargs)


PluginStatus = Literal["success", "partial", "error", "timeout", "skipped"]


class PluginResult(BaseModel):
    """Result of running a single plugin against a single target."""

    plugin: str
    target: str
    status: PluginStatus = "success"
    findings: list[Finding] = Field(default_factory=list)
    data: dict[str, Any] = Field(default_factory=dict)
    duration: float = 0.0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.status in ("success", "partial")

    @property
    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)

    def findings_by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    @classmethod
    def success(cls, plugin: str, target: str, **kwargs: Any) -> PluginResult:
        return cls(plugin=plugin, target=target, status="success", **kwargs)

    @classmethod
    def fail(cls, plugin: str, target: str, error: str, **kwargs: Any) -> PluginResult:
        return cls(plugin=plugin, target=target, status="error", error=error, **kwargs)

    @classmethod
    def skipped(cls, plugin: str, target: str, reason: str = "") -> PluginResult:
        return cls(plugin=plugin, target=target, status="skipped", error=reason)
