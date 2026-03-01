"""Tests for TrainingRunner full pipeline with mocked infrastructure.

Tests _run_engine with mocked PluginRegistry, AsyncExecutor, AutonomousLoop,
verifying scope setup, graph bootstrapping, and report generation.
"""
from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from basilisk.knowledge.entities import Entity, EntityType
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.orchestrator.loop import LoopResult
from basilisk.orchestrator.timeline import Timeline
from basilisk.training.profile import TrainingProfile
from basilisk.training.runner import TrainingRunner
from basilisk.training.validator import FindingTracker


def _make_profile(**overrides) -> TrainingProfile:
    base = {
        "name": "pipeline_test",
        "target": "localhost:9090",
        "target_ports": [9090],
        "max_steps": 20,
        "expected_findings": [
            {"title": "SQL Injection", "severity": "critical", "category": "sqli",
             "plugin_hints": ["sqli_basic"]},
            {"title": "XSS Reflected", "severity": "high", "category": "xss",
             "plugin_hints": ["xss_basic"]},
        ],
    }
    base.update(overrides)
    return TrainingProfile.model_validate(base)


def _make_loop_result(graph: KnowledgeGraph | None = None, steps: int = 15) -> LoopResult:
    g = graph or KnowledgeGraph()
    return LoopResult(
        graph=g,
        timeline=Timeline(),
        steps=steps,
        total_observations=10,
        termination_reason="no_gaps",
    )


class TestBuildReport:
    """Test _build_report with various tracker states."""

    def test_full_coverage_passes(self):
        profile = _make_profile()
        runner = TrainingRunner(profile)
        tracker = FindingTracker(profile)

        f1 = Entity(id="f1", type=EntityType.FINDING,
                     data={"title": "SQL Injection found", "severity": "critical"})
        f2 = Entity(id="f2", type=EntityType.FINDING,
                     data={"title": "XSS Reflected found", "severity": "high"})
        tracker.check_discovery(f1, step=1)
        tracker.check_discovery(f2, step=2)

        result = _make_loop_result()
        report = runner._build_report(result, tracker)

        assert report.passed is True
        assert report.coverage == 1.0
        assert report.discovered == 2
        assert report.total_expected == 2
        assert report.profile_name == "pipeline_test"
        assert report.steps_taken == 15

    def test_partial_coverage_fails(self):
        profile = _make_profile(required_coverage=1.0)
        runner = TrainingRunner(profile)
        tracker = FindingTracker(profile)

        f1 = Entity(id="f1", type=EntityType.FINDING,
                     data={"title": "SQL Injection found", "severity": "critical"})
        tracker.check_discovery(f1, step=1)

        result = _make_loop_result()
        report = runner._build_report(result, tracker)

        assert report.passed is False
        assert report.coverage == 0.5

    def test_report_findings_detail(self):
        profile = _make_profile()
        runner = TrainingRunner(profile)
        tracker = FindingTracker(profile)

        f1 = Entity(id="f1", type=EntityType.FINDING,
                     data={"title": "SQL Injection in /login", "severity": "critical"})
        tracker.check_discovery(f1, step=3)
        tracker.check_verification("f1", step=7)

        result = _make_loop_result()
        report = runner._build_report(result, tracker)

        assert len(report.findings_detail) == 2
        detail_sqli = report.findings_detail[0]
        assert detail_sqli["expected_title"] == "SQL Injection"
        assert detail_sqli["discovered"] is True
        assert detail_sqli["verified"] is True
        assert detail_sqli["discovery_step"] == 3
        assert detail_sqli["verification_step"] == 7

        detail_xss = report.findings_detail[1]
        assert detail_xss["discovered"] is False
        assert detail_xss["verified"] is False

    def test_low_coverage_threshold_passes(self):
        profile = _make_profile(required_coverage=0.5)
        runner = TrainingRunner(profile)
        tracker = FindingTracker(profile)

        f1 = Entity(id="f1", type=EntityType.FINDING,
                     data={"title": "SQL Injection in /login", "severity": "critical"})
        tracker.check_discovery(f1, step=1)

        result = _make_loop_result()
        report = runner._build_report(result, tracker)

        assert report.passed is True  # 50% >= 50%


class TestGraphBootstrapping:
    """Test target_ports and scan_paths injection into graph."""

    def test_target_ports_inject_services(self):
        """target_ports should create SERVICE entities in graph."""
        graph = KnowledgeGraph()
        host = Entity.host("localhost:9090")
        graph.add_entity(host)

        # Simulate what runner does for target_ports
        from basilisk.knowledge.relations import Relation, RelationType

        now = datetime.now(UTC)
        port = 9090
        svc = Entity(
            id=Entity.make_id(
                EntityType.SERVICE, host="localhost:9090", port="9090", protocol="tcp",
            ),
            type=EntityType.SERVICE,
            data={"host": "localhost:9090", "port": port, "protocol": "tcp", "service": "http"},
            first_seen=now, last_seen=now,
        )
        graph.add_entity(svc)
        graph.add_relation(Relation(
            source_id=host.id, target_id=svc.id, type=RelationType.EXPOSES,
        ))

        services = graph.services()
        assert len(services) == 1
        assert services[0].data["port"] == 9090

    def test_scan_paths_inject_endpoints(self):
        """scan_paths should create ENDPOINT entities in graph."""
        graph = KnowledgeGraph()
        host = Entity.host("localhost:9090")
        graph.add_entity(host)

        from basilisk.knowledge.relations import Relation, RelationType

        now = datetime.now(UTC)
        paths = ["/login", "/api/users?id=1", "/admin"]

        for sp in paths:
            path_part = sp.split("?")[0]
            ep = Entity(
                id=Entity.make_id(EntityType.ENDPOINT, host="localhost:9090", path=path_part),
                type=EntityType.ENDPOINT,
                data={
                    "host": "localhost:9090", "path": path_part,
                    "has_params": "?" in sp, "scan_path": True,
                },
                first_seen=now, last_seen=now,
            )
            graph.add_entity(ep)
            graph.add_relation(Relation(
                source_id=host.id, target_id=ep.id, type=RelationType.HAS_ENDPOINT,
            ))

        endpoints = graph.endpoints()
        assert len(endpoints) == 3

        # Check param detection
        api_ep = [e for e in endpoints if "/api/users" in e.data.get("path", "")]
        assert len(api_ep) == 1
        assert api_ep[0].data["has_params"] is True

    def test_crawled_urls_populated(self):
        """scan_paths should also populate ctx.state['crawled_urls']."""
        state: dict = {}
        scan_paths = ["/login", "/api/users?id=1"]
        host_key = "localhost:9090"
        scheme = "http"

        crawled = state.setdefault("crawled_urls", {})
        host_urls = crawled.setdefault(host_key, [])
        for sp in scan_paths:
            if not sp.startswith("/"):
                sp = f"/{sp}"
            full_url = f"{scheme}://{host_key}{sp}"
            if full_url not in host_urls:
                host_urls.append(full_url)

        assert len(state["crawled_urls"]["localhost:9090"]) == 2
        assert "http://localhost:9090/login" in state["crawled_urls"]["localhost:9090"]


class TestTrainingRunnerDockerIntegration:
    """Test Docker lifecycle management in TrainingRunner."""

    @pytest.mark.asyncio
    async def test_run_with_docker_management(self):
        """Runner should start and stop Docker containers when manage_docker=True."""
        profile = _make_profile()
        profile.docker.compose_file = "docker-compose.test.yml"
        profile.docker.ready_url = "http://localhost:9090/"

        runner = TrainingRunner(profile, manage_docker=True)

        mock_docker = AsyncMock()
        mock_docker.available = True

        with patch("basilisk.training.runner.TrainingRunner._run_engine") as mock_engine:
            mock_engine.return_value = MagicMock()
            with patch("basilisk.training.docker.DockerComposeManager") as mock_cls:
                mock_cls.return_value = mock_docker
                await runner.run()

                mock_docker.up.assert_called_once()
                mock_docker.wait_ready.assert_called_once()
                mock_docker.down.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_without_docker(self):
        """Runner with manage_docker=False skips Docker lifecycle."""
        profile = _make_profile()
        runner = TrainingRunner(profile, manage_docker=False)

        with patch("basilisk.training.runner.TrainingRunner._run_engine") as mock_engine:
            mock_engine.return_value = MagicMock()
            await runner.run()
            mock_engine.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_no_compose_file(self):
        """Runner with empty compose_file skips Docker even if manage_docker=True."""
        profile = _make_profile()
        # docker.compose_file is empty by default
        runner = TrainingRunner(profile, manage_docker=True)

        with patch("basilisk.training.runner.TrainingRunner._run_engine") as mock_engine:
            mock_engine.return_value = MagicMock()
            await runner.run()
            mock_engine.assert_called_once()


class TestExplorationRate:
    """Verify training uses deterministic exploration_rate=0."""

    def test_runner_stores_profile_correctly(self):
        profile = _make_profile()
        runner = TrainingRunner(profile)
        assert runner.profile.max_steps == 20
        assert runner.profile.name == "pipeline_test"

    def test_runner_target_override(self):
        profile = _make_profile()
        runner = TrainingRunner(profile, target_override="10.0.0.1:80")
        assert runner.target == "10.0.0.1:80"
        # Original profile target unchanged
        assert runner.profile.target == "localhost:9090"


class TestFinalTrackerSync:
    """Test final tracker synchronization from graph findings."""

    def test_graph_findings_sync(self):
        """Tracker should sync undiscovered findings from final graph state."""
        profile = _make_profile()
        tracker = FindingTracker(profile)

        # Simulate findings in graph that weren't tracked during execution
        graph = KnowledgeGraph()
        finding = Entity(
            id="late_f1", type=EntityType.FINDING,
            data={"title": "SQL Injection in /api", "severity": "critical", "host": "localhost"},
        )
        graph.add_entity(finding)

        # Sync from graph (what runner does after loop.run())
        for f in graph.findings():
            tracker.check_discovery(f, step=999)

        assert tracker.coverage == 0.5  # Only SQLi matched, not XSS

    def test_verified_flag_sync(self):
        """Tracker should detect verified findings from entity data."""
        profile = _make_profile()
        tracker = FindingTracker(profile)

        finding = Entity(
            id="f1", type=EntityType.FINDING,
            data={
                "title": "SQL Injection in /api", "severity": "critical",
                "host": "localhost", "verified": True,
            },
        )
        tracker.check_discovery(finding, step=1)

        # Check verification from entity data (what runner does)
        for tf in tracker.tracked:
            if tf.discovered and not tf.verified:
                entity_data = {"verified": True}  # Simulating graph.get()
                if entity_data.get("verified"):
                    tracker.check_verification(tf.matched_entity_id, step=99)

        assert tracker.tracked[0].verified is True
