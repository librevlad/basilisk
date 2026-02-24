"""Finding tracker and validation report for training mode."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from basilisk.knowledge.entities import Entity
    from basilisk.training.profile import ExpectedFinding, TrainingProfile


@dataclass
class TrackedFinding:
    """Tracks discovery and verification status of a single expected finding."""

    expected: ExpectedFinding
    discovered: bool = False
    verified: bool = False
    discovery_step: int | None = None
    verification_step: int | None = None
    matched_entity_id: str = ""
    matched_title: str = ""


class FindingTracker:
    """Shared state between planner wrapper and validator.

    Tracks which expected findings have been discovered and verified.
    """

    def __init__(self, profile: TrainingProfile) -> None:
        self.tracked: list[TrackedFinding] = [
            TrackedFinding(expected=ef) for ef in profile.expected_findings
        ]

    _SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    def check_discovery(self, finding_entity: Entity, step: int) -> bool:
        """Check if a finding entity matches any expected finding.

        Matching uses two strategies (first match wins):
        1. Case-insensitive title containment + severity >= expected
        2. Category match + severity >= expected (fallback)

        Returns True if a new match was made.
        """
        title = finding_entity.data.get("title", "").lower()
        severity = finding_entity.data.get("severity", "")
        category = finding_entity.data.get("category", "")
        sev_rank = self._SEVERITY_ORDER.get(severity, -1)

        for tf in self.tracked:
            if tf.discovered:
                continue
            expected_rank = self._SEVERITY_ORDER.get(tf.expected.severity, -1)
            if sev_rank < expected_rank:
                continue
            # Strategy 1: title containment
            if tf.expected.title.lower() in title:
                tf.discovered = True
                tf.discovery_step = step
                tf.matched_entity_id = finding_entity.id
                tf.matched_title = finding_entity.data.get("title", "")
                return True
            # Strategy 2: category match (when category is specific enough)
            if (
                tf.expected.category
                and category
                and tf.expected.category == category
            ):
                tf.discovered = True
                tf.discovery_step = step
                tf.matched_entity_id = finding_entity.id
                tf.matched_title = finding_entity.data.get("title", "")
                return True
        return False

    def check_verification(self, entity_id: str, step: int) -> bool:
        """Mark a discovered finding as verified."""
        for tf in self.tracked:
            if tf.matched_entity_id == entity_id and tf.discovered and not tf.verified:
                tf.verified = True
                tf.verification_step = step
                return True
        return False

    @property
    def coverage(self) -> float:
        """Fraction of expected findings that have been discovered."""
        if not self.tracked:
            return 1.0
        return sum(1 for tf in self.tracked if tf.discovered) / len(self.tracked)

    @property
    def verification_rate(self) -> float:
        """Fraction of discovered findings that have been verified."""
        discovered = [tf for tf in self.tracked if tf.discovered]
        if not discovered:
            return 0.0
        return sum(1 for tf in discovered if tf.verified) / len(discovered)

    @property
    def undiscovered(self) -> list[TrackedFinding]:
        """Expected findings not yet discovered."""
        return [tf for tf in self.tracked if not tf.discovered]

    @property
    def unverified(self) -> list[TrackedFinding]:
        """Discovered but not yet verified findings."""
        return [tf for tf in self.tracked if tf.discovered and not tf.verified]


class ValidationReport(BaseModel):
    """Final report from a training validation run."""

    profile_name: str
    target: str
    total_expected: int
    discovered: int
    verified: int
    coverage: float
    verification_rate: float
    steps_taken: int
    findings_detail: list[dict[str, Any]] = Field(default_factory=list)
    passed: bool
