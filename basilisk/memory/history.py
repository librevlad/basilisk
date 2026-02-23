"""Decision history — log, repetition penalty, and persistence."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from basilisk.decisions.decision import Decision


class History:
    """In-memory decision log with repetition penalty and JSON persistence.

    Records every autonomous decision, tracks outcomes, and computes
    penalties for repeated or unproductive actions.
    """

    def __init__(self) -> None:
        self._decisions: list[Decision] = []
        self._by_id: dict[str, Decision] = {}
        # Index: plugin_name → list of decisions for O(1) penalty lookup
        self._by_plugin: dict[str, list[Decision]] = defaultdict(list)

    def record(self, decision: Decision) -> None:
        """Record a new decision (before execution)."""
        self._decisions.append(decision)
        self._by_id[decision.id] = decision
        self._by_plugin[decision.chosen_plugin].append(decision)

    def update_outcome(
        self,
        decision_id: str,
        *,
        observations: int = 0,
        new_entities: int = 0,
        confidence_delta: float = 0.0,
        duration: float = 0.0,
    ) -> None:
        """Update a decision with post-execution outcome metrics."""
        decision = self._by_id.get(decision_id)
        if not decision:
            return
        decision.outcome_observations = observations
        decision.outcome_new_entities = new_entities
        decision.outcome_confidence_delta = confidence_delta
        decision.outcome_duration = duration
        decision.was_productive = new_entities > 0 or confidence_delta > 0.01

    def repetition_penalty(
        self,
        plugin_name: str,
        target_entity_id: str,
        *,
        base_penalty: float = 5.0,
        unproductive_multiplier: float = 2.0,
    ) -> float:
        """Compute repetition penalty for a (plugin, target) pair.

        Formula: base * (2x if prior was unproductive) * time_decay
        where time_decay = 1 / (1 + 0.1 * steps_since).
        Returns 0.0 if never executed before.
        """
        past = self._by_plugin.get(plugin_name)
        if not past:
            return 0.0

        # Find most recent decision for this (plugin, target)
        relevant = [d for d in past if d.triggering_entity_id == target_entity_id]
        if not relevant:
            return 0.0

        latest = relevant[-1]
        steps_since = max(len(self._decisions) - self._decisions.index(latest) - 1, 0)
        time_decay = 1.0 / (1.0 + 0.1 * steps_since)

        penalty = base_penalty * time_decay
        if not latest.was_productive:
            penalty *= unproductive_multiplier

        return penalty

    def save(self, path: Path) -> None:
        """Persist decision history to JSON file."""
        data = [d.model_dump(mode="json") for d in self._decisions]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> History:
        """Load decision history from JSON file."""
        history = cls()
        if not path.exists():
            return history
        raw = json.loads(path.read_text(encoding="utf-8"))
        for item in raw:
            decision = Decision.model_validate(item)
            history.record(decision)
            # Restore was_productive based on loaded data
            if decision.outcome_new_entities > 0 or decision.outcome_confidence_delta > 0.01:
                decision.was_productive = True
        return history

    @property
    def decisions(self) -> list[Decision]:
        return list(self._decisions)

    @property
    def productive_count(self) -> int:
        return sum(1 for d in self._decisions if d.was_productive)

    @property
    def total_confidence_gained(self) -> float:
        return sum(d.outcome_confidence_delta for d in self._decisions)

    def summary(self) -> str:
        """Human-readable summary of the decision history."""
        total = len(self._decisions)
        productive = self.productive_count
        confidence = self.total_confidence_gained
        if total == 0:
            return "No decisions recorded."
        ratio = productive / total * 100
        return (
            f"{total} decisions, {productive} productive ({ratio:.0f}%), "
            f"total confidence gained: {confidence:.3f}"
        )

    def __len__(self) -> int:
        return len(self._decisions)
