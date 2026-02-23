"""Tests for autonomous mode report data preparation."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import MagicMock

from basilisk.core.pipeline import PipelineState
from basilisk.decisions.decision import ContextSnapshot, Decision, EvaluatedOption
from basilisk.knowledge.entities import Entity
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.knowledge.relations import Relation, RelationType
from basilisk.reporting.autonomous import (
    _build_decision_timeline,
    _build_entity_map,
    _build_full_decisions,
    _build_graph_summary,
    _build_growth_data,
    _build_scoring_insights,
    prepare_autonomous_data,
)


def _make_decision(
    step: int = 1,
    plugin: str = "port_scan",
    target: str = "example.com",
    score: float = 0.5,
    productive: bool = True,
    n_options: int = 3,
    entity_count: int = 5,
) -> Decision:
    now = datetime.now(UTC)
    options = []
    for i in range(n_options):
        options.append(EvaluatedOption(
            capability_name=f"cap_{i}",
            plugin_name=f"plugin_{i}" if i > 0 else plugin,
            target_entity_id=f"eid_{i}",
            target_host=target if i == 0 else f"host_{i}.com",
            score=score - i * 0.1,
            score_breakdown={
                "novelty": 0.8, "knowledge_gain": 0.6,
                "cost": 0.3, "noise": 0.1, "repetition_penalty": 0.0,
            },
            was_chosen=(i == 0),
        ))
    return Decision(
        id=Decision.make_id(step, now, plugin, target),
        timestamp=now,
        step=step,
        goal="services",
        goal_description=f"Host {target} has no known services",
        chosen_capability="cap_0",
        chosen_plugin=plugin,
        chosen_target=target,
        chosen_score=score,
        reasoning_trace=f"Gap: services. Selected {plugin}.",
        context=ContextSnapshot(
            entity_count=entity_count,
            relation_count=entity_count - 1,
            host_count=1,
            service_count=0,
            finding_count=0,
            gap_count=2,
            elapsed_seconds=step * 1.5,
            step=step,
        ),
        evaluated_options=options,
        outcome_observations=3,
        outcome_new_entities=2,
        outcome_confidence_delta=0.15,
        outcome_duration=1.2,
        was_productive=productive,
    )


def _make_graph() -> KnowledgeGraph:
    graph = KnowledgeGraph()
    host = Entity.host("example.com")
    graph.add_entity(host)
    svc = Entity.service("example.com", 80, "tcp")
    graph.add_entity(svc)
    graph.add_relation(Relation(
        source_id=host.id, target_id=svc.id, type=RelationType.EXPOSES,
    ))
    tech = Entity.technology("example.com", "nginx", "1.22")
    graph.add_entity(tech)
    graph.add_relation(Relation(
        source_id=svc.id, target_id=tech.id, type=RelationType.RUNS,
    ))
    ep = Entity.endpoint("example.com", "/api/v1")
    graph.add_entity(ep)
    graph.add_relation(Relation(
        source_id=svc.id, target_id=ep.id, type=RelationType.HAS_ENDPOINT,
    ))
    finding = Entity.finding("example.com", "XSS in /search", "high")
    graph.add_entity(finding)
    return graph


def _make_loop_result(
    graph: KnowledgeGraph | None = None,
    decisions: list[Decision] | None = None,
    steps: int = 3,
) -> SimpleNamespace:
    g = graph or _make_graph()
    d = decisions or []
    return SimpleNamespace(
        graph=g,
        decisions=d,
        history=None,
        steps=steps,
        total_observations=10,
        termination_reason="no_gaps",
        plugin_results={},
    )


class TestPrepareAutonomousData:
    def test_with_empty_result(self):
        result = _make_loop_result(
            graph=KnowledgeGraph(), decisions=[], steps=0,
        )
        data = prepare_autonomous_data(result)
        assert data["steps"] == 0
        assert data["total_observations"] == 10
        assert data["productive_count"] == 0
        assert data["productive_pct"] == 0.0
        assert data["graph_summary"]["entities"] == 0
        assert data["decision_timeline"] == []
        assert data["decisions"] == []
        assert data["scoring_insights"]["total_evaluated"] == 0

    def test_with_decisions(self):
        decisions = [_make_decision(step=1), _make_decision(step=2)]
        result = _make_loop_result(decisions=decisions, steps=2)
        data = prepare_autonomous_data(result)
        assert data["steps"] == 2
        assert data["productive_count"] == 2
        assert data["productive_pct"] == 100.0
        assert len(data["decision_timeline"]) == 2
        assert len(data["decisions"]) == 2

    def test_with_history(self):
        decisions = [_make_decision(step=1, productive=True)]
        history = MagicMock()
        history.productive_count = 1
        history.total_confidence_gained = 0.42
        result = _make_loop_result(decisions=decisions)
        result.history = history
        data = prepare_autonomous_data(result)
        assert data["productive_count"] == 1
        assert data["total_confidence_gained"] == 0.42


class TestGraphSummary:
    def test_counts(self):
        graph = _make_graph()
        summary = _build_graph_summary(graph)
        assert summary["entities"] == 5
        assert summary["hosts"] == 1
        assert summary["services"] == 1
        assert summary["technologies"] == 1
        assert summary["endpoints"] == 1
        assert summary["findings"] == 1
        assert summary["relations"] == 3


class TestEntityMap:
    def test_structure(self):
        graph = _make_graph()
        entity_map = _build_entity_map(graph)
        assert len(entity_map) == 1
        host = entity_map[0]
        assert host["host"] == "example.com"
        assert len(host["services"]) == 1
        assert host["services"][0]["port"] == 80
        assert len(host["technologies"]) == 1
        assert host["technologies"][0]["name"] == "nginx"
        assert len(host["endpoints"]) == 1
        assert host["endpoints"][0]["path"] == "/api/v1"


class TestGrowthData:
    def test_progression(self):
        decisions = [
            _make_decision(step=1, entity_count=2),
            _make_decision(step=2, entity_count=5),
            _make_decision(step=3, entity_count=8),
        ]
        graph = _make_graph()  # final state: 5 entities
        growth = _build_growth_data(decisions, graph)
        # 3 decision steps + 1 final = 4 points
        assert len(growth) == 4
        assert growth[0]["entities"] == 2
        assert growth[1]["entities"] == 5
        assert growth[2]["entities"] == 8
        # Final point is actual graph state
        assert growth[3]["entities"] == graph.entity_count


class TestDecisionTimeline:
    def test_length(self):
        decisions = [_make_decision(step=i) for i in range(1, 6)]
        timeline = _build_decision_timeline(decisions)
        assert len(timeline) == 5
        assert timeline[0]["step"] == 1
        assert timeline[4]["step"] == 5
        assert timeline[0]["plugin"] == "port_scan"

    def test_fields(self):
        d = _make_decision(step=1, plugin="ssl_check", target="test.com", score=0.75)
        timeline = _build_decision_timeline([d])
        entry = timeline[0]
        assert entry["plugin"] == "ssl_check"
        assert entry["target"] == "test.com"
        assert entry["score"] == 0.75
        assert entry["was_productive"] is True


class TestFullDecisions:
    def test_cap_options(self):
        d = _make_decision(n_options=15)
        result = _build_full_decisions([d])
        assert len(result) == 1
        assert len(result[0]["evaluated_options"]) == 10  # capped at 10

    def test_structure(self):
        d = _make_decision(step=1, plugin="dns_enum")
        result = _build_full_decisions([d])
        dec = result[0]
        assert dec["chosen_plugin"] == "dns_enum"
        assert "context" in dec
        assert "evaluated_options" in dec
        assert "outcome" in dec
        assert dec["outcome"]["observations"] == 3


class TestScoringInsights:
    def test_avg_score(self):
        decisions = [
            _make_decision(step=1, score=0.4),
            _make_decision(step=2, score=0.6),
            _make_decision(step=3, score=0.8),
        ]
        insights = _build_scoring_insights(decisions)
        assert insights["avg_score"] == 0.6
        assert insights["max_score"] == 0.8
        assert insights["min_score"] == 0.4

    def test_empty(self):
        insights = _build_scoring_insights([])
        assert insights["avg_score"] == 0.0
        assert insights["total_evaluated"] == 0

    def test_goal_distribution(self):
        decisions = [_make_decision(step=i) for i in range(1, 4)]
        insights = _build_scoring_insights(decisions)
        assert "services" in insights["goal_distribution"]
        assert insights["goal_distribution"]["services"] == 3


class TestPipelineStateAutonomousNone:
    def test_default_none(self):
        state = PipelineState()
        assert state.autonomous is None


class TestTemplateRendersAutonomous:
    def test_no_jinja_errors(self, tmp_path):
        from jinja2 import Environment, FileSystemLoader

        from basilisk.reporting.live_html import TEMPLATES_DIR

        env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=True,
        )
        from basilisk.reporting.rendering import filesize
        env.filters["filesize"] = filesize

        decisions = [_make_decision(step=1), _make_decision(step=2)]
        result = _make_loop_result(decisions=decisions, steps=2)
        auto_data = prepare_autonomous_data(result)

        template = env.get_template("report.html.j2")
        html = template.render(
            title="Test Report",
            timestamp="2026-02-19 12:00:00",
            status="completed",
            is_running=False,
            refresh_interval=None,
            total_findings=0,
            severity_counts={},
            phases=[],
            findings=[],
            aggregated_findings=[],
            total_aggregated_count=0,
            total_raw_count=0,
            top_findings=[],
            risk_score=0,
            risk_label="LOW",
            noise_count=0,
            elapsed_total=1.0,
            targets_scanned=1,
            plugins_run=2,
            duration=1.0,
            attack_surface={"hosts": {}, "subdomains": [], "emails": []},
            plugin_stats=[],
            ssl_details=None,
            dns_details=None,
            whois_details=None,
            timeline=[],
            vuln_categories={},
            radar_points=[],
            exploit_chains=[],
            site_tree=[],
            plugin_matrix=None,
            js_intelligence=None,
            port_findings=[],
            remediation_priority=[],
            quality_metrics=None,
            skipped_plugins=[],
            host_schemes={},
            autonomous=auto_data,
        )
        assert "Decision Timeline" in html
        assert "Knowledge Graph Growth" in html
        assert "Decision Audit Trail" in html
        assert "Entity Discovery Map" in html
        assert "Scoring Insights" in html
        assert "Kill Chain Progress" not in html
        assert "Autonomous Engine v3.1" in html
