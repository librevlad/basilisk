"""Tests for target loader."""

from __future__ import annotations

from basilisk.domain.target import LiveTarget, TrainingTarget
from basilisk.engine.target_loader import TargetLoader


class TestTargetLoader:
    def test_load_domain(self):
        targets = TargetLoader.load(["example.com"])
        assert len(targets) == 1
        assert isinstance(targets[0], LiveTarget)
        assert targets[0].host == "example.com"
        assert targets[0].host_type == "domain"

    def test_load_ip(self):
        targets = TargetLoader.load(["192.168.1.1"])
        assert len(targets) == 1
        assert targets[0].host_type == "ip"

    def test_load_ip_with_port(self):
        targets = TargetLoader.load(["192.168.1.1:8080"])
        assert len(targets) == 1
        assert targets[0].ports == [8080]

    def test_load_localhost(self):
        targets = TargetLoader.load(["localhost"])
        assert len(targets) == 1
        assert targets[0].host_type == "ip"

    def test_load_url(self):
        targets = TargetLoader.load(["https://example.com/app"])
        assert len(targets) == 1
        assert targets[0].host_type == "url"

    def test_load_multiple(self):
        targets = TargetLoader.load(["example.com", "192.168.1.1", "test.org"])
        assert len(targets) == 3

    def test_load_training(self, tmp_path):
        profile = tmp_path / "test.yaml"
        profile.write_text(
            "name: test\n"
            "target: localhost\n"
            "target_ports: [80]\n"
            "expected_findings:\n"
            "  - title: XSS\n"
            "    severity: high\n"
        )
        t = TargetLoader.load_training(profile)
        assert isinstance(t, TrainingTarget)
        assert t.host == "localhost"

    def test_load_training_with_override(self, tmp_path):
        profile = tmp_path / "test.yaml"
        profile.write_text(
            "name: test\n"
            "target: localhost\n"
            "expected_findings:\n"
            "  - title: XSS\n"
            "    severity: high\n"
        )
        t = TargetLoader.load_training(profile, target_override="10.0.0.1")
        assert t.host == "10.0.0.1"
