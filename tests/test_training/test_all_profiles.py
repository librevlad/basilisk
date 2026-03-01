"""Tests for loading and validating all 20 training profile YAML files.

Each profile is loaded from training_profiles/ and checked for:
- Required fields (name, target, expected_findings)
- Structural integrity (ports, coverage, max_steps)
- Docker configuration consistency
- Auth configuration validity
- Expected findings structure
"""
from __future__ import annotations

from pathlib import Path

import pytest

from basilisk.training.profile import TrainingProfile

PROFILES_DIR = Path(__file__).resolve().parents[2] / "training_profiles"

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
        compose_path = PROFILES_DIR.parent / profile.docker.compose_file
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
