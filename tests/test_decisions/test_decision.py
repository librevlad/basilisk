"""Tests for the decision model."""

from __future__ import annotations

from datetime import UTC, datetime

from basilisk.decisions.decision import ContextSnapshot, Decision, EvaluatedOption


class TestContextSnapshot:
    def test_defaults(self):
        snap = ContextSnapshot()
        assert snap.entity_count == 0
        assert snap.step == 0
        assert snap.elapsed_seconds == 0.0

    def test_json_roundtrip(self):
        snap = ContextSnapshot(entity_count=10, host_count=3, step=5)
        data = snap.model_dump_json()
        restored = ContextSnapshot.model_validate_json(data)
        assert restored.entity_count == 10
        assert restored.host_count == 3


class TestEvaluatedOption:
    def test_creation(self):
        opt = EvaluatedOption(
            capability_name="port_scan",
            plugin_name="port_scan",
            target_entity_id="abc123",
            target_host="example.com",
            score=0.75,
            score_breakdown={"novelty": 1.0, "cost": 2.0},
            was_chosen=True,
        )
        assert opt.capability_name == "port_scan"
        assert opt.was_chosen is True
        assert opt.score_breakdown["novelty"] == 1.0

    def test_defaults(self):
        opt = EvaluatedOption(
            capability_name="test",
            plugin_name="test",
            target_entity_id="id1",
            target_host="host",
            score=0.5,
        )
        assert opt.score_breakdown == {}
        assert opt.reason == ""
        assert opt.was_chosen is False


class TestDecision:
    def test_make_id_deterministic(self):
        ts = datetime(2026, 1, 1, tzinfo=UTC)
        id1 = Decision.make_id(1, ts, "port_scan", "example.com")
        id2 = Decision.make_id(1, ts, "port_scan", "example.com")
        assert id1 == id2
        assert len(id1) == 16

    def test_make_id_different_inputs(self):
        ts = datetime(2026, 1, 1, tzinfo=UTC)
        id1 = Decision.make_id(1, ts, "port_scan", "a.com")
        id2 = Decision.make_id(1, ts, "port_scan", "b.com")
        assert id1 != id2

    def test_make_id_different_steps(self):
        ts = datetime(2026, 1, 1, tzinfo=UTC)
        id1 = Decision.make_id(1, ts, "port_scan", "a.com")
        id2 = Decision.make_id(2, ts, "port_scan", "a.com")
        assert id1 != id2

    def test_creation_with_defaults(self):
        d = Decision(id="test_id")
        assert d.id == "test_id"
        assert d.step == 0
        assert d.outcome_observations == 0
        assert d.was_productive is False
        assert d.evaluated_options == []

    def test_full_creation(self):
        ts = datetime(2026, 2, 1, 12, 0, tzinfo=UTC)
        d = Decision(
            id=Decision.make_id(3, ts, "ssl_check", "target.com"),
            timestamp=ts,
            step=3,
            goal="services",
            goal_description="Host needs service scan",
            goal_priority=10.0,
            triggering_entity_id="ent_123",
            context=ContextSnapshot(entity_count=5, step=3),
            chosen_capability="ssl_check",
            chosen_plugin="ssl_check",
            chosen_target="target.com",
            chosen_score=0.85,
            reasoning_trace="High priority gap; ssl_check produces Service knowledge",
        )
        assert d.step == 3
        assert d.context.entity_count == 5
        assert d.reasoning_trace != ""

    def test_json_roundtrip(self):
        ts = datetime(2026, 2, 1, tzinfo=UTC)
        d = Decision(
            id=Decision.make_id(1, ts, "dns_enum", "ex.com"),
            timestamp=ts,
            step=1,
            goal="dns",
            chosen_capability="dns_enum",
            chosen_plugin="dns_enum",
            chosen_target="ex.com",
            chosen_score=0.9,
            evaluated_options=[
                EvaluatedOption(
                    capability_name="dns_enum",
                    plugin_name="dns_enum",
                    target_entity_id="h1",
                    target_host="ex.com",
                    score=0.9,
                    was_chosen=True,
                ),
            ],
            outcome_observations=5,
            outcome_new_entities=3,
            outcome_confidence_delta=0.15,
            was_productive=True,
        )
        data = d.model_dump_json()
        restored = Decision.model_validate_json(data)
        assert restored.id == d.id
        assert restored.step == 1
        assert restored.chosen_score == 0.9
        assert len(restored.evaluated_options) == 1
        assert restored.evaluated_options[0].was_chosen is True
        assert restored.outcome_new_entities == 3
        assert restored.was_productive is True

    def test_no_plugin_imports(self):
        """Decision module must not import from plugin layer."""
        import basilisk.decisions.decision as mod
        source = mod.__file__
        with open(source) as f:
            content = f.read()
        assert "basilisk.plugins" not in content
        assert "BasePlugin" not in content

    def test_outcome_update(self):
        d = Decision(id="up_test", step=1)
        assert d.was_productive is False
        d.outcome_observations = 10
        d.outcome_new_entities = 4
        d.outcome_confidence_delta = 0.2
        d.was_productive = True
        assert d.was_productive is True
        assert d.outcome_confidence_delta == 0.2
