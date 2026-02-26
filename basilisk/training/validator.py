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


# Category aliases: map plugin-derived tags to profile category names.
# Keys are canonical profile categories, values are plugin tag variants.
_CATEGORY_ALIASES: dict[str, set[str]] = {
    "injection": {
        "cmdi", "command-injection", "ssti", "xxe", "ldap", "xpath",
        "nosqli", "deserialization", "ssrf", "header-injection", "formula-injection",
        "graphql", "soap", "template-injection",
    },
    "auth": {
        "default-creds", "idor", "authorization", "session", "brute-force",
        "bola", "jwt", "authentication", "access-control", "cookie",
    },
    "config": {
        "open-redirect", "redirect", "misconfiguration", "disclosure",
        "cors", "clickjacking", "information-disclosure", "dos",
        "rate-limiting", "error-disclosure",
    },
    "sqli": {"sql-injection", "nosqli"},
    "xss": {"cross-site-scripting", "html-injection"},
    "lfi": {"file-inclusion", "path-traversal", "directory-traversal", "rfi"},
    "upload": {"file-upload", "unrestricted-upload"},
    "csrf": {"cross-site-request-forgery"},
    "crypto": {"weak-crypto", "weak-encryption"},
    "dos": {"denial-of-service", "rate-limiting"},
}

_STOP_WORDS = {"the", "a", "an", "in", "on", "of", "via", "for", "and", "or", "is", "to"}


def _categories_match(expected_cat: str, actual_cat: str) -> bool:
    """Check if categories match, considering aliases."""
    if expected_cat == actual_cat:
        return True
    # Check if actual_cat is an alias of expected_cat
    aliases = _CATEGORY_ALIASES.get(expected_cat, set())
    if actual_cat in aliases:
        return True
    # Check reverse: expected_cat might be an alias of actual_cat
    for canonical, alias_set in _CATEGORY_ALIASES.items():
        if expected_cat in alias_set and canonical == actual_cat:
            return True
    return False


def _word_overlap(expected_title: str, actual_title: str) -> float:
    """Compute word overlap ratio between expected and actual title."""
    expected_words = {
        w for w in expected_title.lower().split() if w not in _STOP_WORDS and len(w) > 1
    }
    actual_words = {
        w for w in actual_title.lower().split() if w not in _STOP_WORDS and len(w) > 1
    }
    if not expected_words:
        return 0.0
    return len(expected_words & actual_words) / len(expected_words)


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

        Matching uses four strategies (first match wins):
        1. Case-insensitive title containment (expected in actual)
        2. Reverse title containment (actual in expected, for short actual titles)
        3. Category match with aliases
        4. Word overlap >= 50%

        Severity tolerance: actual severity must be within 1 level of expected
        (e.g. MEDIUM matches HIGH expectation, HIGH matches CRITICAL).
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
            # Allow ±1 severity tolerance (MEDIUM can match HIGH, HIGH can match CRITICAL)
            if sev_rank < expected_rank - 1:
                continue

            exp_title = tf.expected.title.lower()

            # Strategy 1: title containment (expected in actual)
            if exp_title in title:
                self._mark_discovered(tf, finding_entity, step)
                return True

            # Strategy 2: reverse containment (actual core in expected)
            # e.g. actual "command injection" contained in expected "os command injection"
            # Strip common suffixes from actual title for matching
            title_core = title.split(":")[0].split("(")[0].strip()
            if len(title_core) > 5 and title_core in exp_title:
                self._mark_discovered(tf, finding_entity, step)
                return True

            # Strategy 3: category match with aliases
            if (
                tf.expected.category
                and category
                and _categories_match(tf.expected.category, category)
            ):
                self._mark_discovered(tf, finding_entity, step)
                return True

            # Strategy 4: word overlap (>= 50% of expected title words in actual)
            if _word_overlap(exp_title, title) >= 0.5:
                self._mark_discovered(tf, finding_entity, step)
                return True
        return False

    @staticmethod
    def _mark_discovered(tf: TrackedFinding, entity: Entity, step: int) -> None:
        tf.discovered = True
        tf.discovery_step = step
        tf.matched_entity_id = entity.id
        tf.matched_title = entity.data.get("title", "")

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
