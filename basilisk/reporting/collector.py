"""ReportCollector — EventBus subscriber that accumulates rich state for reports."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from basilisk.events.bus import Event, EventBus
    from basilisk.training.validator import FindingTracker, ValidationReport


@dataclass
class ReportFinding:
    """A finding with full detail for report rendering."""

    title: str
    severity: str
    host: str
    evidence: str = ""
    description: str = ""
    tags: list[str] = field(default_factory=list)
    confidence: float = 0.0
    verified: bool = False
    step: int = 0


@dataclass
class ReportDecision:
    """A decision trace entry."""

    step: int
    plugin: str
    target: str
    score: float
    reasoning: str = ""
    productive: bool = False
    duration: float = 0.0
    new_entities: int = 0


@dataclass
class ReportPlugin:
    """A plugin execution record."""

    name: str
    target: str
    duration: float = 0.0
    findings_count: int = 0
    step: int = 0


@dataclass
class StepSnapshot:
    """Knowledge graph state at a particular step."""

    step: int
    entities: int = 0
    relations: int = 0
    gaps: int = 0
    entities_gained: int = 0


@dataclass
class ReasoningEvent:
    """A reasoning event (hypothesis or belief change)."""

    event_type: str
    data: dict[str, Any] = field(default_factory=dict)
    step: int = 0


@dataclass
class ReportCollector:
    """Accumulates event data for HTML/JSON report generation.

    Subscribes to all 14 EventBus event types and maintains a full
    history of findings, decisions, plugins, and step snapshots.
    """

    # Target and mode
    target: str = ""
    mode: str = "auto"
    max_steps: int = 100
    started_at: float = field(default_factory=time.monotonic)

    # Step progress
    step: int = 0

    # Entity counts by type
    entity_counts: dict[str, int] = field(default_factory=lambda: {
        "host": 0, "service": 0, "endpoint": 0, "technology": 0,
        "credential": 0, "finding": 0, "vulnerability": 0,
        "container": 0, "image": 0,
    })
    total_entities: int = 0
    total_relations: int = 0

    # Gap count
    gap_count: int = 0

    # Full history lists
    findings: list[ReportFinding] = field(default_factory=list)
    decisions: list[ReportDecision] = field(default_factory=list)
    plugins: list[ReportPlugin] = field(default_factory=list)
    step_history: list[StepSnapshot] = field(default_factory=list)
    reasoning_events: list[ReasoningEvent] = field(default_factory=list)

    # Hypothesis stats
    hypotheses_active: int = 0
    hypotheses_confirmed: int = 0
    hypotheses_rejected: int = 0

    # Belief changes
    beliefs_strengthened: int = 0
    beliefs_weakened: int = 0

    # Active plugin tracking (for duration calc)
    _active_plugins: dict[str, float] = field(default_factory=dict)

    # Previous step entity count (for entities_gained)
    _prev_entities: int = 0

    # Termination
    status: str = "running"
    termination_reason: str = ""

    # Training data (set by finalize_training)
    training: dict[str, Any] | None = None

    @property
    def elapsed(self) -> float:
        """Seconds since collection started."""
        return time.monotonic() - self.started_at

    @property
    def severity_counts(self) -> dict[str, int]:
        """Count findings by severity."""
        counts: dict[str, int] = {}
        for f in self.findings:
            sev = f.severity.upper()
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    @property
    def risk_score(self) -> float:
        """Calculate risk score 0-10 based on findings severity."""
        weights = {"CRITICAL": 4.0, "HIGH": 2.5, "MEDIUM": 1.0, "LOW": 0.3, "INFO": 0.0}
        total = sum(weights.get(f.severity.upper(), 0.0) for f in self.findings)
        return min(total, 10.0)

    def subscribe(self, bus: EventBus) -> None:
        """Subscribe to all relevant EventBus events."""
        from basilisk.events.bus import EventType

        bus.subscribe(EventType.GAP_DETECTED, self._on_gap_detected)
        bus.subscribe(EventType.PLUGIN_STARTED, self._on_plugin_started)
        bus.subscribe(EventType.PLUGIN_FINISHED, self._on_plugin_finished)
        bus.subscribe(EventType.STEP_COMPLETED, self._on_step_completed)
        bus.subscribe(EventType.ENTITY_CREATED, self._on_entity_created)
        bus.subscribe(EventType.ENTITY_UPDATED, self._on_entity_updated)
        bus.subscribe(EventType.DECISION_MADE, self._on_decision_made)
        bus.subscribe(EventType.FINDING_VERIFIED, self._on_finding_verified)
        bus.subscribe(EventType.BELIEF_STRENGTHENED, self._on_belief_strengthened)
        bus.subscribe(EventType.BELIEF_WEAKENED, self._on_belief_weakened)
        bus.subscribe(EventType.HYPOTHESIS_CONFIRMED, self._on_hypothesis_confirmed)
        bus.subscribe(EventType.HYPOTHESIS_REJECTED, self._on_hypothesis_rejected)

    def finalize(self, termination_reason: str = "") -> None:
        """Mark collection as complete."""
        self.status = "completed"
        self.termination_reason = termination_reason

    def finalize_training(
        self, report: ValidationReport, tracker: FindingTracker,
    ) -> None:
        """Attach training validation results."""
        self.finalize(termination_reason="training_complete")
        self.mode = "train"
        expected: list[dict[str, Any]] = []
        for tf in tracker.tracked:
            expected.append({
                "title": tf.expected.title,
                "severity": tf.expected.severity,
                "discovered": tf.discovered,
                "verified": tf.verified,
                "discovery_step": tf.discovery_step,
            })
        self.training = {
            "profile_name": report.profile_name,
            "coverage": report.coverage,
            "verification_rate": report.verification_rate,
            "passed": report.passed,
            "expected_findings": expected,
        }

    # --- Event handlers (sync, fast O(1) mutations) ---

    def _on_gap_detected(self, event: Event) -> None:
        self.gap_count = event.data.get("count", 0)

    def _on_plugin_started(self, event: Event) -> None:
        plugin = event.data.get("plugin", "")
        target = event.data.get("target", "")
        key = f"{plugin}:{target}:{event.data.get('step', 0)}"
        self._active_plugins[key] = time.monotonic()

    def _on_plugin_finished(self, event: Event) -> None:
        plugin = event.data.get("plugin", "")
        target = event.data.get("target", "")
        step = event.data.get("step", 0)
        duration = event.data.get("duration", 0.0)
        findings_count = event.data.get("findings_count", 0)

        key = f"{plugin}:{target}:{step}"
        if key in self._active_plugins:
            if duration == 0.0:
                duration = time.monotonic() - self._active_plugins[key]
            del self._active_plugins[key]

        self.plugins.append(ReportPlugin(
            name=plugin, target=target, duration=duration,
            findings_count=findings_count, step=step,
        ))

    def _on_step_completed(self, event: Event) -> None:
        self.step = event.data.get("step", self.step)
        self.total_entities = event.data.get("entities", self.total_entities)
        self.total_relations = event.data.get("relations", self.total_relations)

        gained = self.total_entities - self._prev_entities
        self.step_history.append(StepSnapshot(
            step=self.step,
            entities=self.total_entities,
            relations=self.total_relations,
            gaps=self.gap_count,
            entities_gained=max(gained, 0),
        ))
        self._prev_entities = self.total_entities

    def _on_entity_created(self, event: Event) -> None:
        entity_type = event.data.get("entity_type", "")
        if entity_type and entity_type in self.entity_counts:
            self.entity_counts[entity_type] += 1

        # If this is a finding, store full detail
        title = event.data.get("title", "")
        if entity_type == "finding" and title:
            self.findings.append(ReportFinding(
                title=title,
                severity=event.data.get("severity", "info"),
                host=event.data.get("host", ""),
                evidence=event.data.get("evidence", ""),
                description=event.data.get("description", ""),
                tags=event.data.get("tags", []),
                confidence=event.data.get("confidence", 0.0),
                step=event.data.get("step", self.step),
            ))

    def _on_entity_updated(self, event: Event) -> None:
        pass

    def _on_decision_made(self, event: Event) -> None:
        self.decisions.append(ReportDecision(
            step=event.data.get("step", self.step),
            plugin=event.data.get("plugin", ""),
            target=event.data.get("target", ""),
            score=event.data.get("score", 0.0),
            reasoning=event.data.get("reasoning", ""),
        ))

    def _on_finding_verified(self, event: Event) -> None:
        title = event.data.get("title", "")
        for f in self.findings:
            if f.title == title:
                f.verified = True
                break

    def _on_belief_strengthened(self, event: Event) -> None:
        self.beliefs_strengthened += 1
        self.reasoning_events.append(ReasoningEvent(
            event_type="belief_strengthened",
            data=dict(event.data),
            step=self.step,
        ))

    def _on_belief_weakened(self, event: Event) -> None:
        self.beliefs_weakened += 1
        self.reasoning_events.append(ReasoningEvent(
            event_type="belief_weakened",
            data=dict(event.data),
            step=self.step,
        ))

    def _on_hypothesis_confirmed(self, event: Event) -> None:
        self.hypotheses_confirmed += 1
        if self.hypotheses_active > 0:
            self.hypotheses_active -= 1
        self.reasoning_events.append(ReasoningEvent(
            event_type="hypothesis_confirmed",
            data=dict(event.data),
            step=self.step,
        ))

    def _on_hypothesis_rejected(self, event: Event) -> None:
        self.hypotheses_rejected += 1
        if self.hypotheses_active > 0:
            self.hypotheses_active -= 1
        self.reasoning_events.append(ReasoningEvent(
            event_type="hypothesis_rejected",
            data=dict(event.data),
            step=self.step,
        ))
