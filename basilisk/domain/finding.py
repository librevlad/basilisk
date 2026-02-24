"""Finding model — strict immutable security findings for v4."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field, model_validator

# Re-export Severity from existing models for backward compat
from basilisk.models.result import Severity


class Proof(BaseModel):
    """Evidence proving a finding is real."""

    raw_request: str = ""
    raw_response: str = ""
    payload_used: str = ""
    description: str = ""


class ReproductionStep(BaseModel):
    """A single step to reproduce a finding."""

    order: int
    action: str
    expected_result: str = ""


class Finding(BaseModel, frozen=True):
    """An immutable security finding with structured proof.

    HIGH/CRITICAL findings MUST have proof with a description.
    """

    title: str
    severity: Severity
    description: str = ""
    proof: Proof | None = None
    reproduction_steps: tuple[ReproductionStep, ...] = ()
    remediation: str = ""
    tags: frozenset[str] = frozenset()
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    host: str = ""
    endpoint: str = ""
    scenario_name: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="after")
    def _validate_proof_for_high(self) -> Finding:
        """HIGH/CRITICAL findings must have proof with description."""
        if self.severity >= Severity.HIGH and (not self.proof or not self.proof.description):
            import logging
            logging.getLogger("basilisk.quality").warning(
                "Finding '%s' (severity=%s) has no proof description",
                self.title, self.severity.label,
            )
        return self

    @classmethod
    def critical(cls, title: str, *, proof: Proof | None = None, **kw: Any) -> Finding:
        return cls(severity=Severity.CRITICAL, title=title, proof=proof, **kw)

    @classmethod
    def high(cls, title: str, *, proof: Proof | None = None, **kw: Any) -> Finding:
        return cls(severity=Severity.HIGH, title=title, proof=proof, **kw)

    @classmethod
    def medium(cls, title: str, **kw: Any) -> Finding:
        return cls(severity=Severity.MEDIUM, title=title, **kw)

    @classmethod
    def low(cls, title: str, **kw: Any) -> Finding:
        return cls(severity=Severity.LOW, title=title, **kw)

    @classmethod
    def info(cls, title: str, **kw: Any) -> Finding:
        return cls(severity=Severity.INFO, title=title, **kw)
