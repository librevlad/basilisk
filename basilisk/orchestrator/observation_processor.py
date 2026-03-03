"""Observation application — apply results to KG, emit events, update decisions."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from basilisk.decisions.decision import Decision
from basilisk.events.bus import Event, EventType
from basilisk.knowledge.entities import EntityType
from basilisk.observations.observation import Observation

if TYPE_CHECKING:
    from basilisk.events.bus import EventBus
    from basilisk.knowledge.state import KnowledgeState
    from basilisk.memory.history import History
    from basilisk.orchestrator.cost_tracker import CostTracker

logger = logging.getLogger(__name__)


def _enrich_finding(event_data: dict[str, Any], obs: Observation) -> None:
    """Enrich finding events with display data."""
    event_data["title"] = obs.entity_data.get("title", "")
    event_data["severity"] = obs.entity_data.get("severity", "")
    event_data["host"] = obs.key_fields.get("host", "")
    event_data["description"] = obs.entity_data.get("description", "")
    event_data["evidence"] = obs.entity_data.get("evidence", "")
    event_data["tags"] = obs.entity_data.get("tags", [])
    event_data["confidence"] = obs.confidence
    event_data["verified"] = obs.entity_data.get("verified", False)
    event_data["false_positive_risk"] = obs.entity_data.get("false_positive_risk", "low")
    event_data["remediation"] = obs.entity_data.get("remediation", "")


def _enrich_service(event_data: dict[str, Any], obs: Observation) -> None:
    """Enrich topology events for network map."""
    event_data["host"] = obs.key_fields.get("host", "")
    event_data["port"] = obs.entity_data.get("port", 0)
    event_data["protocol"] = obs.key_fields.get("protocol", "tcp")
    event_data["service"] = obs.entity_data.get("service", "")


def _enrich_endpoint(event_data: dict[str, Any], obs: Observation) -> None:
    event_data["host"] = obs.key_fields.get("host", "")
    event_data["path"] = obs.entity_data.get("path", "")


def _enrich_host(event_data: dict[str, Any], obs: Observation) -> None:
    event_data["host"] = obs.key_fields.get("host", "")
    event_data["host_type"] = obs.entity_data.get("type", "primary")
    event_data["parent"] = obs.entity_data.get("parent", "")


def _enrich_technology(event_data: dict[str, Any], obs: Observation) -> None:
    event_data["host"] = obs.key_fields.get("host", "")
    event_data["tech_name"] = obs.entity_data.get("name", "")
    event_data["tech_version"] = obs.entity_data.get("version", "")


_ENRICHERS: dict[EntityType, Callable[[dict[str, Any], Observation], None]] = {
    EntityType.FINDING: _enrich_finding,
    EntityType.SERVICE: _enrich_service,
    EntityType.ENDPOINT: _enrich_endpoint,
    EntityType.HOST: _enrich_host,
    EntityType.TECHNOLOGY: _enrich_technology,
}


class ObservationProcessor:
    """Apply observations to KG, emit events, update decisions."""

    def __init__(
        self,
        state: KnowledgeState,
        bus: EventBus,
        *,
        history: History | None = None,
        cost_tracker: CostTracker | None = None,
    ) -> None:
        self._state = state
        self._bus = bus
        self._history = history
        self._cost_tracker = cost_tracker

    def process_batch(
        self,
        results: list,
        decisions: list[Decision],
        step: int,
    ) -> int:
        """Apply observations to KG, emit events, update decisions.

        Returns total observation count for this batch.
        """
        step_obs_count = 0
        for idx, obs_list in enumerate(results):
            if isinstance(obs_list, BaseException):
                logger.warning("Execution error in step %d: %s", step, obs_list)
                continue

            decision = decisions[idx] if idx < len(decisions) else None
            obs_count = 0
            new_entities = 0
            total_confidence_delta = 0.0

            for obs in obs_list:
                outcome = self._state.apply_observation(obs)
                event_data: dict[str, Any] = {
                    "entity_id": outcome.entity_id,
                    "entity_type": obs.entity_type.value,
                    "key_data": " ".join(f"{k}={v}" for k, v in obs.key_fields.items()),
                    "confidence_delta": outcome.confidence_delta,
                }
                enricher = _ENRICHERS.get(obs.entity_type)
                if enricher is not None:
                    enricher(event_data, obs)
                self._bus.emit(Event(
                    EventType.ENTITY_UPDATED if not outcome.was_new
                    else EventType.ENTITY_CREATED,
                    event_data,
                ))
                obs_count += 1
                if outcome.was_new:
                    new_entities += 1
                total_confidence_delta += outcome.confidence_delta

            step_obs_count += obs_count

            # Update decision outcome
            if decision:
                decision.observed_entity_types = sorted({
                    obs.entity_type.value for obs in obs_list
                    if hasattr(obs, "entity_type")
                })
                decision.outcome_observations = obs_count
                decision.outcome_new_entities = new_entities
                decision.outcome_confidence_delta = total_confidence_delta
                decision.outcome_duration = decision.outcome_duration  # set by _execute_one
                decision.was_productive = (
                    new_entities > 0 or total_confidence_delta > 0.01
                )
                if self._history is not None:
                    self._history.update_outcome(
                        decision.id,
                        observations=obs_count,
                        new_entities=new_entities,
                        confidence_delta=total_confidence_delta,
                        duration=decision.outcome_duration,
                    )
                # Record stats for cost learning
                if self._cost_tracker is not None:
                    self._cost_tracker.record(
                        decision.chosen_plugin,
                        new_entities=new_entities,
                        findings=obs_count,
                        runtime=decision.outcome_duration,
                    )

                # Emit decision outcome for timeline / reporting
                self._bus.emit(Event(EventType.DECISION_OUTCOME, {
                    "decision_id": decision.id,
                    "plugin": decision.chosen_plugin,
                    "target": decision.chosen_target,
                    "step": step,
                    "observations": obs_count,
                    "new_entities": new_entities,
                    "duration": decision.outcome_duration,
                    "was_productive": decision.was_productive,
                }))

        return step_obs_count
