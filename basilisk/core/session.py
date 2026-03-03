"""ScanSession — coordination layer for a single audit execution.

Owns KnowledgeGraph (entity data source of truth) and EventBus (event routing).
Captures execution metadata (decisions, plugins, steps, reasoning) from events.
Entity data (findings, topology, counts) is always read from the graph at report time.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from basilisk.events.bus import Event, EventBus
    from basilisk.knowledge.graph import KnowledgeGraph
    from basilisk.training.validator import FindingTracker, ValidationReport


class SessionEventType(StrEnum):
    """Event types captured in the session timeline."""

    SCENARIO_STARTED = "scenario_started"
    SCENARIO_FINISHED = "scenario_finished"
    SCENARIO_FAILED = "scenario_failed"
    SURFACE_DISCOVERED = "surface_discovered"
    FINDING_CREATED = "finding_created"
    FINDING_CONFIRMED = "finding_confirmed"
    DECISION_MADE = "decision_made"
    DECISION_OUTCOME = "decision_outcome"
    STEP_COMPLETED = "step_completed"
    HYPOTHESIS_CONFIRMED = "hypothesis_confirmed"
    HYPOTHESIS_REJECTED = "hypothesis_rejected"
    BELIEF_CHANGED = "belief_changed"


@dataclass(frozen=True)
class SessionTimelineEvent:
    """Immutable event in the execution timeline."""

    timestamp: datetime
    event_type: SessionEventType
    step: int = 0
    scenario: str = ""
    target: str = ""
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class SessionDecision:
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
class SessionPlugin:
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


class ScanSession:
    """Coordination object for a single audit execution.

    Owns: KnowledgeGraph, EventBus, execution timeline.
    Entity data (findings, topology, counts) always comes from self.graph.
    Execution metadata (decisions, plugins, steps, reasoning) lives here.
    """

    def __init__(
        self,
        target: str,
        *,
        mode: str = "auto",
        max_steps: int = 100,
        graph: KnowledgeGraph | None = None,
        bus: EventBus | None = None,
    ) -> None:
        from basilisk.events.bus import EventBus
        from basilisk.knowledge.graph import KnowledgeGraph

        self.target = target
        self.mode = mode
        self.max_steps = max_steps
        self.graph: KnowledgeGraph = graph or KnowledgeGraph()
        self.bus: EventBus = bus or EventBus()

        # Timing
        self._started_at = time.monotonic()
        self._started_wall = datetime.now(UTC)
        self.scan_id = self._make_scan_id(target, self._started_at)

        # Execution metadata (NOT entity data — that lives in the graph)
        self.timeline_events: list[SessionTimelineEvent] = []
        self.decisions: list[SessionDecision] = []
        self.plugins: list[SessionPlugin] = []
        self.step_history: list[StepSnapshot] = []
        self.reasoning_events: list[ReasoningEvent] = []

        # Current step
        self.step: int = 0
        self.gap_count: int = 0

        # Reasoning counters
        self.hypotheses_confirmed: int = 0
        self.hypotheses_rejected: int = 0
        self.beliefs_strengthened: int = 0
        self.beliefs_weakened: int = 0

        # Plugin duration tracking (internal)
        self._active_plugins: dict[str, float] = {}
        self._prev_entities: int = 0

        # Status
        self.status: str = "running"
        self.termination_reason: str = ""

        # Training data (optional, set by finalize_training)
        self.training_data: dict[str, Any] | None = None

        # Subscribe to events
        self._subscribe()

    @property
    def elapsed(self) -> float:
        """Seconds since session started."""
        return time.monotonic() - self._started_at

    @property
    def started_at(self) -> datetime:
        """Wall-clock start time."""
        return self._started_wall

    def finalize(self, reason: str = "") -> None:
        """Mark session as completed."""
        self.status = "completed"
        self.termination_reason = reason

    def finalize_training(
        self, report: ValidationReport, tracker: FindingTracker,
    ) -> None:
        """Attach training validation results and finalize."""
        self.finalize("training_complete")
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
        self.training_data = {
            "profile_name": report.profile_name,
            "coverage": report.coverage,
            "verification_rate": report.verification_rate,
            "passed": report.passed,
            "expected_findings": expected,
        }

    @staticmethod
    def _make_scan_id(target: str, started_at: float) -> str:
        """Deterministic scan ID from target + start time."""
        raw = f"{target}:{started_at}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _subscribe(self) -> None:
        """Subscribe to all relevant EventBus events."""
        from basilisk.events.bus import EventType

        self.bus.subscribe(EventType.GAP_DETECTED, self._on_gap_detected)
        self.bus.subscribe(EventType.PLUGIN_STARTED, self._on_plugin_started)
        self.bus.subscribe(EventType.PLUGIN_FINISHED, self._on_plugin_finished)
        self.bus.subscribe(EventType.STEP_COMPLETED, self._on_step_completed)
        self.bus.subscribe(EventType.ENTITY_CREATED, self._on_entity_created)
        self.bus.subscribe(EventType.DECISION_MADE, self._on_decision_made)
        self.bus.subscribe(EventType.FINDING_VERIFIED, self._on_finding_verified)
        self.bus.subscribe(EventType.BELIEF_STRENGTHENED, self._on_belief_strengthened)
        self.bus.subscribe(EventType.BELIEF_WEAKENED, self._on_belief_weakened)
        self.bus.subscribe(EventType.HYPOTHESIS_CONFIRMED, self._on_hypothesis_confirmed)
        self.bus.subscribe(EventType.HYPOTHESIS_REJECTED, self._on_hypothesis_rejected)
        self.bus.subscribe(EventType.DECISION_OUTCOME, self._on_decision_outcome)

    # --- Event handlers (sync, fast O(1) mutations) ---

    def _on_gap_detected(self, event: Event) -> None:
        self.gap_count = event.data.get("count", 0)

    def _on_plugin_started(self, event: Event) -> None:
        plugin = event.data.get("plugin", "")
        target = event.data.get("target", "")
        step = event.data.get("step", 0)
        key = f"{plugin}:{target}:{step}"
        self._active_plugins[key] = time.monotonic()

        self.timeline_events.append(SessionTimelineEvent(
            timestamp=datetime.now(UTC),
            event_type=SessionEventType.SCENARIO_STARTED,
            step=step,
            scenario=plugin,
            target=target,
        ))

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

        self.plugins.append(SessionPlugin(
            name=plugin, target=target, duration=duration,
            findings_count=findings_count, step=step,
        ))

        event_type = (
            SessionEventType.SCENARIO_FAILED if findings_count < 0
            else SessionEventType.SCENARIO_FINISHED
        )
        self.timeline_events.append(SessionTimelineEvent(
            timestamp=datetime.now(UTC),
            event_type=event_type,
            step=step,
            scenario=plugin,
            target=target,
            data={"duration": duration, "findings_count": findings_count},
        ))

    def _on_step_completed(self, event: Event) -> None:
        self.step = event.data.get("step", self.step)
        entities = event.data.get("entities", 0)
        relations = event.data.get("relations", 0)

        gained = entities - self._prev_entities
        self.step_history.append(StepSnapshot(
            step=self.step,
            entities=entities,
            relations=relations,
            gaps=self.gap_count,
            entities_gained=max(gained, 0),
        ))
        self._prev_entities = entities

        self.timeline_events.append(SessionTimelineEvent(
            timestamp=datetime.now(UTC),
            event_type=SessionEventType.STEP_COMPLETED,
            step=self.step,
            data={"entities": entities, "entities_gained": max(gained, 0)},
        ))

    def _on_entity_created(self, event: Event) -> None:
        entity_type = event.data.get("entity_type", "")
        title = event.data.get("title", "")

        if entity_type == "finding" and title:
            self.timeline_events.append(SessionTimelineEvent(
                timestamp=datetime.now(UTC),
                event_type=SessionEventType.FINDING_CREATED,
                step=event.data.get("step", self.step),
                data={"title": title, "severity": event.data.get("severity", "info")},
            ))
        elif entity_type in ("service", "endpoint", "technology"):
            self.timeline_events.append(SessionTimelineEvent(
                timestamp=datetime.now(UTC),
                event_type=SessionEventType.SURFACE_DISCOVERED,
                step=event.data.get("step", self.step),
                data={"entity_type": entity_type, "host": event.data.get("host", "")},
            ))

    def _on_decision_made(self, event: Event) -> None:
        self.decisions.append(SessionDecision(
            step=event.data.get("step", self.step),
            plugin=event.data.get("plugin", ""),
            target=event.data.get("target", ""),
            score=event.data.get("score", 0.0),
            reasoning=event.data.get("reasoning", ""),
        ))

        self.timeline_events.append(SessionTimelineEvent(
            timestamp=datetime.now(UTC),
            event_type=SessionEventType.DECISION_MADE,
            step=event.data.get("step", self.step),
            data={
                "plugin": event.data.get("plugin", ""),
                "score": event.data.get("score", 0.0),
            },
        ))

    def _on_finding_verified(self, event: Event) -> None:
        self.timeline_events.append(SessionTimelineEvent(
            timestamp=datetime.now(UTC),
            event_type=SessionEventType.FINDING_CONFIRMED,
            step=self.step,
            data={"title": event.data.get("title", "")},
        ))

    def _on_belief_strengthened(self, event: Event) -> None:
        self.beliefs_strengthened += 1
        self.reasoning_events.append(ReasoningEvent(
            event_type="belief_strengthened",
            data=dict(event.data),
            step=self.step,
        ))
        self.timeline_events.append(SessionTimelineEvent(
            timestamp=datetime.now(UTC),
            event_type=SessionEventType.BELIEF_CHANGED,
            step=self.step,
            data=dict(event.data),
        ))

    def _on_belief_weakened(self, event: Event) -> None:
        self.beliefs_weakened += 1
        self.reasoning_events.append(ReasoningEvent(
            event_type="belief_weakened",
            data=dict(event.data),
            step=self.step,
        ))
        self.timeline_events.append(SessionTimelineEvent(
            timestamp=datetime.now(UTC),
            event_type=SessionEventType.BELIEF_CHANGED,
            step=self.step,
            data=dict(event.data),
        ))

    def _on_hypothesis_confirmed(self, event: Event) -> None:
        self.hypotheses_confirmed += 1
        self.reasoning_events.append(ReasoningEvent(
            event_type="hypothesis_confirmed",
            data=dict(event.data),
            step=self.step,
        ))
        self.timeline_events.append(SessionTimelineEvent(
            timestamp=datetime.now(UTC),
            event_type=SessionEventType.HYPOTHESIS_CONFIRMED,
            step=self.step,
            data=dict(event.data),
        ))

    def _on_hypothesis_rejected(self, event: Event) -> None:
        self.hypotheses_rejected += 1
        self.reasoning_events.append(ReasoningEvent(
            event_type="hypothesis_rejected",
            data=dict(event.data),
            step=self.step,
        ))
        self.timeline_events.append(SessionTimelineEvent(
            timestamp=datetime.now(UTC),
            event_type=SessionEventType.HYPOTHESIS_REJECTED,
            step=self.step,
            data=dict(event.data),
        ))

    def _on_decision_outcome(self, event: Event) -> None:
        """Update decision with outcome data from DECISION_OUTCOME event."""
        plugin = event.data.get("plugin", "")
        for d in self.decisions:
            if d.plugin == plugin and d.step == event.data.get("step", 0):
                d.productive = event.data.get("was_productive", False)
                d.duration = event.data.get("duration", 0.0)
                d.new_entities = event.data.get("new_entities", 0)
                break

        self.timeline_events.append(SessionTimelineEvent(
            timestamp=datetime.now(UTC),
            event_type=SessionEventType.DECISION_OUTCOME,
            step=event.data.get("step", self.step),
            data={
                "plugin": plugin,
                "was_productive": event.data.get("was_productive", False),
            },
        ))
