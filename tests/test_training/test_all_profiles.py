"""Tests for loading and validating all 20 training profile YAML files.

Each profile is loaded from training/profiles/ and checked for:
- Required fields (name, target, expected_findings)
- Structural integrity (ports, coverage, max_steps)
- Docker configuration consistency
- Auth configuration validity
- Expected findings structure
"""
from __future__ import annotations

import random
from pathlib import Path

import pytest

from basilisk.reporting.collector import (
    ReportCollector,
    ReportDecision,
    ReportFinding,
    ReportPlugin,
    StepSnapshot,
)
from basilisk.reporting.renderer import assemble_data, render_html
from basilisk.training.profile import TrainingProfile

PROFILES_DIR = Path(__file__).resolve().parents[2] / "training" / "profiles"

# All 20 profiles in alphabetical order
ALL_PROFILES = sorted(p.stem for p in PROFILES_DIR.glob("*.yaml"))


@pytest.fixture(params=ALL_PROFILES)
def profile_path(request: pytest.FixtureRequest) -> Path:
    """Parametrize over every YAML profile file."""
    return PROFILES_DIR / f"{request.param}.yaml"


@pytest.fixture
def profile(profile_path: Path) -> TrainingProfile:
    """Load a single training profile."""
    return TrainingProfile.load(profile_path)


class TestAllProfilesLoad:
    """Verify every profile YAML can be loaded without errors."""

    def test_profile_loads_successfully(self, profile: TrainingProfile):
        assert profile.name
        assert profile.target

    def test_has_expected_findings(self, profile: TrainingProfile):
        assert len(profile.expected_findings) > 0

    def test_target_has_port(self, profile: TrainingProfile):
        assert ":" in profile.target, f"{profile.name}: target should include port"

    def test_target_ports_list(self, profile: TrainingProfile):
        assert len(profile.target_ports) > 0, f"{profile.name}: missing target_ports"
        for port in profile.target_ports:
            assert 1 <= port <= 65535

    def test_max_steps_positive(self, profile: TrainingProfile):
        assert profile.max_steps > 0
        assert profile.max_steps <= 1000

    def test_required_coverage_valid(self, profile: TrainingProfile):
        assert 0.0 < profile.required_coverage <= 1.0


class TestExpectedFindings:
    """Validate expected findings in each profile."""

    def test_findings_have_title(self, profile: TrainingProfile):
        for ef in profile.expected_findings:
            assert ef.title, f"{profile.name}: finding without title"

    def test_findings_have_valid_severity(self, profile: TrainingProfile):
        valid = {"info", "low", "medium", "high", "critical"}
        for ef in profile.expected_findings:
            assert ef.severity in valid, (
                f"{profile.name}: invalid severity '{ef.severity}' for '{ef.title}'"
            )

    def test_findings_have_plugin_hints(self, profile: TrainingProfile):
        for ef in profile.expected_findings:
            assert len(ef.plugin_hints) > 0, (
                f"{profile.name}: '{ef.title}' has no plugin_hints"
            )

    def test_high_critical_count(self, profile: TrainingProfile):
        """Every profile should have at least one HIGH or CRITICAL finding."""
        high_crit = [
            ef for ef in profile.expected_findings
            if ef.severity in ("high", "critical")
        ]
        assert len(high_crit) > 0, f"{profile.name}: no HIGH/CRITICAL findings"


class TestDockerConfig:
    """Validate Docker configuration per profile."""

    DOCKER_EXEMPT: set[str] = set()  # All 20 containers now Docker-ready

    def test_docker_compose_file(self, profile: TrainingProfile):
        if profile.name in self.DOCKER_EXEMPT:
            pytest.skip(f"{profile.name} has no Docker config")
        assert profile.docker.compose_file, (
            f"{profile.name}: missing docker.compose_file"
        )

    def test_docker_service_name(self, profile: TrainingProfile):
        if profile.name in self.DOCKER_EXEMPT:
            pytest.skip(f"{profile.name} has no Docker config")
        assert profile.docker.service_name, (
            f"{profile.name}: missing docker.service_name"
        )

    def test_docker_ready_url(self, profile: TrainingProfile):
        if profile.name in self.DOCKER_EXEMPT:
            pytest.skip(f"{profile.name} has no Docker config")
        assert profile.docker.ready_url, (
            f"{profile.name}: missing docker.ready_url"
        )
        assert profile.docker.ready_url.startswith("http")

    def test_compose_file_exists(self, profile: TrainingProfile):
        if profile.name in self.DOCKER_EXEMPT:
            pytest.skip(f"{profile.name} has no Docker config")
        compose_path = PROFILES_DIR.parent.parent / profile.docker.compose_file
        assert compose_path.exists(), (
            f"{profile.name}: compose file not found: {profile.docker.compose_file}"
        )


class TestAuthConfig:
    """Validate auth configuration consistency."""

    def test_json_api_has_login_url(self, profile: TrainingProfile):
        if profile.auth.auth_type != "json_api":
            pytest.skip("not json_api auth")
        assert profile.auth.login_url, (
            f"{profile.name}: json_api auth without login_url"
        )

    def test_json_api_has_token_path(self, profile: TrainingProfile):
        if profile.auth.auth_type != "json_api":
            pytest.skip("not json_api auth")
        assert profile.auth.token_path, (
            f"{profile.name}: json_api auth without token_path"
        )

    def test_form_login_has_credentials(self, profile: TrainingProfile):
        if profile.auth.auth_type != "form":
            pytest.skip("not form auth")
        if not profile.auth.login_url:
            pytest.skip("no login_url")
        has_creds = profile.auth.username or profile.auth.login_fields
        assert has_creds, (
            f"{profile.name}: form auth without credentials"
        )

    def test_register_has_data(self, profile: TrainingProfile):
        if not profile.auth.register_url:
            pytest.skip("no registration")
        has_data = profile.auth.register_data or profile.auth.username
        assert has_data, (
            f"{profile.name}: register_url without data or username"
        )


class TestProfileConsistency:
    """Cross-cutting consistency checks."""

    def test_target_port_in_target_string(self, profile: TrainingProfile):
        """Port in target string should match target_ports list."""
        if ":" in profile.target:
            port_str = profile.target.rsplit(":", 1)[1]
            port = int(port_str)
            assert port in profile.target_ports, (
                f"{profile.name}: target port {port} not in target_ports {profile.target_ports}"
            )

    def test_no_duplicate_finding_titles(self, profile: TrainingProfile):
        """Finding titles should be unique within a profile."""
        titles = [ef.title.lower() for ef in profile.expected_findings]
        assert len(titles) == len(set(titles)), (
            f"{profile.name}: duplicate finding titles"
        )


class TestProfileCounts:
    """Verify we have exactly 20 profiles."""

    def test_total_profile_count(self):
        profiles = list(PROFILES_DIR.glob("*.yaml"))
        assert len(profiles) == 20, (
            f"Expected 20 profiles, found {len(profiles)}: "
            f"{sorted(p.stem for p in profiles)}"
        )

    def test_expected_profile_names(self):
        expected = {
            "altoro_mutual", "badstore", "bwapp", "crapi", "dsvw",
            "dvga", "dvwa", "dvws", "gruyere", "hackazon",
            "juice_shop", "mutillidae", "nodegoat", "pixi", "railsgoat",
            "vampi", "vapi", "wackopicko", "webgoat", "xvwa",
        }
        actual = {p.stem for p in PROFILES_DIR.glob("*.yaml")}
        assert actual == expected, (
            f"Missing: {expected - actual}, Extra: {actual - expected}"
        )

    def test_total_expected_findings(self):
        """Sanity check: total findings across all profiles."""
        total = 0
        for p in PROFILES_DIR.glob("*.yaml"):
            tp = TrainingProfile.load(p)
            total += len(tp.expected_findings)
        # Should be at least 200 (currently ~246)
        assert total >= 200, f"Only {total} total expected findings across all profiles"

    def test_docker_container_count(self):
        """All 20 profiles should have Docker config."""
        docker_count = 0
        for p in PROFILES_DIR.glob("*.yaml"):
            tp = TrainingProfile.load(p)
            if tp.docker.compose_file:
                docker_count += 1
        assert docker_count == 20

    def test_no_port_conflicts(self):
        """All profiles should use unique ports."""
        ports: dict[int, str] = {}
        for p in PROFILES_DIR.glob("*.yaml"):
            tp = TrainingProfile.load(p)
            for port in tp.target_ports:
                assert port not in ports, (
                    f"Port {port} conflict: {tp.name} and {ports[port]}"
                )
                ports[port] = tp.name

    def test_container_findings_present(self):
        """All 20 profiles should have at least one container finding."""
        for p in PROFILES_DIR.glob("*.yaml"):
            tp = TrainingProfile.load(p)
            container_findings = [
                ef for ef in tp.expected_findings
                if ef.category == "container"
            ]
            assert container_findings, (
                f"{tp.name}: missing container security findings"
            )

    def test_container_runs_as_root_universal(self):
        """All 20 profiles should have 'Container runs as root' finding."""
        for p in PROFILES_DIR.glob("*.yaml"):
            tp = TrainingProfile.load(p)
            titles = [ef.title.lower() for ef in tp.expected_findings]
            assert "container runs as root" in titles, (
                f"{tp.name}: missing 'Container runs as root' finding"
            )

    def test_secret_in_env_var_for_known_profiles(self):
        """Profiles with env secrets should have 'Secret in env var' finding."""
        secret_profiles = {"crapi", "vapi", "mutillidae"}
        for p in PROFILES_DIR.glob("*.yaml"):
            tp = TrainingProfile.load(p)
            if tp.name in secret_profiles:
                titles = [ef.title.lower() for ef in tp.expected_findings]
                assert "secret in env var" in titles, (
                    f"{tp.name}: missing 'Secret in env var' finding"
                )


# ---------------------------------------------------------------------------
# Report generation tests — simulate training for all 20 containers
# ---------------------------------------------------------------------------


def _simulate_training_collector(
    tp: TrainingProfile,
    *,
    coverage: float = 0.7,
    seed: int = 42,
) -> ReportCollector:
    """Build a ReportCollector simulating a training run for a profile.

    Deterministic: same profile + seed always produces same output.
    """
    rng = random.Random(seed)
    target = tp.target.split(":")[0]
    max_steps = min(tp.max_steps, 30)  # cap for test speed

    c = ReportCollector(target=target, mode="auto", max_steps=tp.max_steps)
    c.step = max_steps
    c.total_entities = rng.randint(30, 200)
    c.total_relations = rng.randint(15, 100)
    c.gap_count = rng.randint(1, 15)
    c.entity_counts["host"] = rng.randint(1, 5)
    c.entity_counts["service"] = rng.randint(2, 10)
    c.entity_counts["endpoint"] = rng.randint(5, 50)
    c.entity_counts["technology"] = rng.randint(1, 10)

    # Generate findings from expected_findings
    n_discovered = max(1, int(len(tp.expected_findings) * coverage))
    discovered_indices = set(rng.sample(
        range(len(tp.expected_findings)),
        min(n_discovered, len(tp.expected_findings)),
    ))

    findings: list[ReportFinding] = []
    for i in discovered_indices:
        ef = tp.expected_findings[i]
        step = rng.randint(1, max_steps)
        findings.append(ReportFinding(
            title=ef.title,
            severity=ef.severity,
            host=target,
            step=step,
            confidence=rng.uniform(0.5, 0.99),
            verified=rng.random() > 0.4,
            evidence="test evidence" if ef.severity in ("high", "critical") else "",
        ))
    c.findings = findings

    # Generate decisions
    c.decisions = [
        ReportDecision(
            step=s, plugin="container_config_audit" if s % 3 == 0 else "sqli_basic",
            target=target, score=rng.uniform(0.5, 1.0),
            reasoning="training gap fill", productive=rng.random() > 0.3,
            new_entities=rng.randint(0, 5), duration=rng.uniform(0.5, 5.0),
        )
        for s in range(1, min(max_steps + 1, 11))
    ]

    # Generate plugins
    c.plugins = [
        ReportPlugin(
            name=d.plugin, target=target,
            duration=d.duration or 1.0,
            findings_count=rng.randint(0, 2), step=d.step,
        )
        for d in c.decisions[:5]
    ]

    # Step history
    c.step_history = [
        StepSnapshot(
            step=s,
            entities=int(c.total_entities * s / max_steps),
            relations=int(c.total_relations * s / max_steps),
            gaps=max(1, 20 - s),
            entities_gained=max(1, rng.randint(1, 20)),
        )
        for s in range(1, min(max_steps + 1, 11))
    ]

    c.hypotheses_confirmed = rng.randint(0, 5)
    c.hypotheses_rejected = rng.randint(0, 2)
    c.beliefs_strengthened = rng.randint(0, 8)
    c.beliefs_weakened = rng.randint(0, 2)

    # Training data
    expected_findings = []
    for i, ef in enumerate(tp.expected_findings):
        disc = i in discovered_indices
        step_val = rng.randint(1, max_steps) if disc else None
        expected_findings.append({
            "title": ef.title,
            "severity": ef.severity,
            "discovered": disc,
            "verified": disc and rng.random() > 0.4,
            "discovery_step": step_val,
        })

    disc_count = sum(1 for e in expected_findings if e["discovered"])
    verif_count = sum(1 for e in expected_findings if e["verified"])
    actual_coverage = disc_count / len(expected_findings) if expected_findings else 0
    verif_rate = verif_count / disc_count if disc_count else 0

    c.training = {
        "profile_name": tp.name,
        "coverage": actual_coverage,
        "verification_rate": verif_rate,
        "passed": actual_coverage >= tp.required_coverage,
        "expected_findings": expected_findings,
    }

    return c


class TestReportGeneration:
    """Verify all 20 profiles generate valid HTML reports."""

    def test_report_renders_without_error(self, profile: TrainingProfile):
        c = _simulate_training_collector(profile)
        data = assemble_data(c)
        result = render_html(data)
        assert "<!DOCTYPE html>" in result
        assert "</html>" in result

    def test_report_has_training_section(self, profile: TrainingProfile):
        c = _simulate_training_collector(profile)
        data = assemble_data(c)
        result = render_html(data)
        assert 'id="training"' in result
        assert profile.name in result

    def test_report_has_training_rows(self, profile: TrainingProfile):
        c = _simulate_training_collector(profile)
        data = assemble_data(c)
        result = render_html(data)
        assert "training-row-yes" in result or "training-row-no" in result

    def test_report_has_pass_badge(self, profile: TrainingProfile):
        c = _simulate_training_collector(profile)
        data = assemble_data(c)
        result = render_html(data)
        assert "PASSED" in result or "FAILED" in result

    def test_report_has_footer(self, profile: TrainingProfile):
        c = _simulate_training_collector(profile)
        data = assemble_data(c)
        result = render_html(data)
        assert "footer-stats" in result
        assert "Findings:" in result

    def test_report_has_findings(self, profile: TrainingProfile):
        c = _simulate_training_collector(profile)
        data = assemble_data(c)
        result = render_html(data)
        assert 'id="findings"' in result

    def test_report_has_command_center(self, profile: TrainingProfile):
        c = _simulate_training_collector(profile)
        data = assemble_data(c)
        result = render_html(data)
        assert 'id="command-center"' in result

    def test_report_container_finding_in_training(self, profile: TrainingProfile):
        """Container finding should appear in training table."""
        c = _simulate_training_collector(profile)
        data = assemble_data(c)
        result = render_html(data)
        assert "Container runs as root" in result

    def test_report_step_badge_for_discovered(self, profile: TrainingProfile):
        """Discovered findings should have step badges."""
        c = _simulate_training_collector(profile, coverage=0.9)
        data = assemble_data(c)
        result = render_html(data)
        assert "step-badge" in result

    def test_report_json_data_valid(self, profile: TrainingProfile):
        """Embedded JSON data should be parseable."""
        import json

        c = _simulate_training_collector(profile)
        data = assemble_data(c)
        # The data dict should be JSON serializable
        json_str = json.dumps(data, default=str)
        parsed = json.loads(json_str)
        assert parsed["training"]["profile_name"] == profile.name


class TestReportGenerationEdgeCases:
    """Test report rendering with extreme training data."""

    def test_zero_coverage_report(self, profile: TrainingProfile):
        """Profile with 0% coverage should still render."""
        c = _simulate_training_collector(profile, coverage=0.0)
        data = assemble_data(c)
        result = render_html(data)
        assert 'id="training"' in result
        assert "FAILED" in result

    def test_full_coverage_report(self, profile: TrainingProfile):
        """Profile with 100% coverage should render PASSED."""
        c = _simulate_training_collector(profile, coverage=1.0)
        c.training["passed"] = True
        data = assemble_data(c)
        result = render_html(data)
        assert "PASSED" in result

    def test_report_size_reasonable(self, profile: TrainingProfile):
        """Report should not be empty or absurdly small."""
        c = _simulate_training_collector(profile)
        data = assemble_data(c)
        result = render_html(data)
        # A real report should be at least 10KB
        assert len(result) > 10_000, (
            f"{profile.name}: report too small ({len(result)} bytes)"
        )
