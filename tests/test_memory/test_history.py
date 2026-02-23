"""Tests for the decision history and repetition penalty."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from basilisk.decisions.decision import Decision
from basilisk.memory.history import History


def _decision(
    step: int = 1,
    plugin: str = "port_scan",
    target: str = "example.com",
    entity_id: str = "ent1",
    productive: bool = False,
) -> Decision:
    ts = datetime(2026, 1, 1, step, 0, tzinfo=UTC)
    d = Decision(
        id=Decision.make_id(step, ts, plugin, target),
        timestamp=ts,
        step=step,
        goal="services",
        goal_description="test gap",
        goal_priority=10.0,
        triggering_entity_id=entity_id,
        chosen_capability=plugin,
        chosen_plugin=plugin,
        chosen_target=target,
        chosen_score=0.5,
        reasoning_trace="test trace",
    )
    if productive:
        d.outcome_new_entities = 3
        d.outcome_confidence_delta = 0.2
        d.was_productive = True
    return d


class TestHistoryRecord:
    def test_record_increases_count(self):
        h = History()
        h.record(_decision())
        assert len(h) == 1
        h.record(_decision(step=2))
        assert len(h) == 2

    def test_decisions_property(self):
        h = History()
        d = _decision()
        h.record(d)
        assert h.decisions[0].id == d.id

    def test_decisions_is_copy(self):
        h = History()
        h.record(_decision())
        lst = h.decisions
        lst.clear()
        assert len(h) == 1


class TestHistoryOutcome:
    def test_update_outcome(self):
        h = History()
        d = _decision()
        h.record(d)
        h.update_outcome(
            d.id,
            observations=5,
            new_entities=2,
            confidence_delta=0.15,
            duration=3.5,
        )
        assert d.outcome_observations == 5
        assert d.outcome_new_entities == 2
        assert d.outcome_confidence_delta == 0.15
        assert d.outcome_duration == 3.5
        assert d.was_productive is True

    def test_update_unproductive(self):
        h = History()
        d = _decision()
        h.record(d)
        h.update_outcome(d.id, observations=0, new_entities=0, confidence_delta=0.0)
        assert d.was_productive is False

    def test_update_nonexistent_id(self):
        h = History()
        # Should not raise
        h.update_outcome("nonexistent", observations=1)

    def test_productive_count(self):
        h = History()
        h.record(_decision(step=1, productive=True))
        h.record(_decision(step=2, productive=False))
        h.record(_decision(step=3, productive=True))
        assert h.productive_count == 2

    def test_total_confidence_gained(self):
        h = History()
        d1 = _decision(step=1)
        d2 = _decision(step=2)
        h.record(d1)
        h.record(d2)
        h.update_outcome(d1.id, confidence_delta=0.1, new_entities=1)
        h.update_outcome(d2.id, confidence_delta=0.25, new_entities=1)
        assert abs(h.total_confidence_gained - 0.35) < 0.001


class TestRepetitionPenalty:
    def test_no_history_zero_penalty(self):
        h = History()
        p = h.repetition_penalty("port_scan", "ent1")
        assert p == 0.0

    def test_different_plugin_zero_penalty(self):
        h = History()
        h.record(_decision(plugin="dns_enum", entity_id="ent1"))
        p = h.repetition_penalty("port_scan", "ent1")
        assert p == 0.0

    def test_different_target_zero_penalty(self):
        h = History()
        h.record(_decision(plugin="port_scan", entity_id="ent1"))
        p = h.repetition_penalty("port_scan", "ent2")
        assert p == 0.0

    def test_same_plugin_target_has_penalty(self):
        h = History()
        h.record(_decision(plugin="port_scan", entity_id="ent1"))
        p = h.repetition_penalty("port_scan", "ent1")
        assert p > 0

    def test_unproductive_higher_penalty(self):
        h = History()
        d = _decision(plugin="port_scan", entity_id="ent1", productive=False)
        h.record(d)
        p_unproductive = h.repetition_penalty("port_scan", "ent1")

        h2 = History()
        d2 = _decision(plugin="port_scan", entity_id="ent1", productive=True)
        h2.record(d2)
        p_productive = h2.repetition_penalty("port_scan", "ent1")

        assert p_unproductive > p_productive

    def test_penalty_decays_with_steps(self):
        h = History()
        h.record(_decision(step=1, plugin="port_scan", entity_id="ent1"))
        p_immediate = h.repetition_penalty("port_scan", "ent1")

        # Add many decisions after to simulate time passing
        for i in range(2, 22):
            h.record(_decision(step=i, plugin="dns_enum", entity_id=f"other_{i}"))

        p_later = h.repetition_penalty("port_scan", "ent1")
        assert p_later < p_immediate


class TestHistoryPersistence:
    def test_save_and_load(self, tmp_path: Path):
        h = History()
        d = _decision(step=1, productive=True)
        h.record(d)
        h.update_outcome(d.id, observations=3, new_entities=2, confidence_delta=0.1, duration=1.0)

        path = tmp_path / "history.json"
        h.save(path)
        assert path.exists()

        loaded = History.load(path)
        assert len(loaded) == 1
        assert loaded.decisions[0].id == d.id
        assert loaded.decisions[0].outcome_observations == 3
        assert loaded.decisions[0].was_productive is True

    def test_load_nonexistent_returns_empty(self, tmp_path: Path):
        path = tmp_path / "missing.json"
        loaded = History.load(path)
        assert len(loaded) == 0

    def test_roundtrip_preserves_all_fields(self, tmp_path: Path):
        h = History()
        d = _decision(step=5, plugin="ssl_check", target="t.com", entity_id="e5")
        d.reasoning_trace = "Custom reasoning"
        h.record(d)
        h.update_outcome(d.id, observations=10, new_entities=5, confidence_delta=0.3, duration=2.5)

        path = tmp_path / "rt.json"
        h.save(path)
        loaded = History.load(path)

        rd = loaded.decisions[0]
        assert rd.step == 5
        assert rd.chosen_plugin == "ssl_check"
        assert rd.reasoning_trace == "Custom reasoning"
        assert rd.outcome_observations == 10
        assert rd.outcome_confidence_delta == 0.3


class TestHistorySummary:
    def test_empty_summary(self):
        h = History()
        assert "No decisions" in h.summary()

    def test_summary_format(self):
        h = History()
        h.record(_decision(step=1, productive=True))
        h.record(_decision(step=2, productive=False))
        s = h.summary()
        assert "2 decisions" in s
        assert "1 productive" in s
        assert "50%" in s
