"""Tests for domain target models."""

from __future__ import annotations

from basilisk.domain.target import (
    AuthConfig,
    ExpectedFinding,
    LiveTarget,
    TrainingTarget,
)


class TestLiveTarget:
    def test_domain_factory(self):
        t = LiveTarget.domain("example.com")
        assert t.host == "example.com"
        assert t.host_type == "domain"
        assert t.target_type == "live"
        assert not t.is_training

    def test_ip_factory(self):
        t = LiveTarget.ip("192.168.1.1")
        assert t.host == "192.168.1.1"
        assert t.host_type == "ip"

    def test_url_factory(self):
        t = LiveTarget.url("https://example.com/app")
        assert t.host == "https://example.com/app"
        assert t.host_type == "url"

    def test_base_url_https(self):
        t = LiveTarget.domain("example.com", ports=[443])
        assert t.base_url == "https://example.com"

    def test_base_url_http_default(self):
        t = LiveTarget.domain("example.com")
        assert t.base_url == "http://example.com"

    def test_base_url_custom_port(self):
        t = LiveTarget.domain("example.com", ports=[8080])
        assert t.base_url == "http://example.com:8080"

    def test_base_url_from_url_host(self):
        t = LiveTarget.url("https://example.com/app")
        assert t.base_url == "https://example.com/app"

    def test_equality(self):
        a = LiveTarget.domain("example.com")
        b = LiveTarget.domain("example.com")
        assert a == b

    def test_hash(self):
        a = LiveTarget.domain("example.com")
        b = LiveTarget.domain("example.com")
        assert hash(a) == hash(b)


class TestTrainingTarget:
    def test_is_training(self):
        t = TrainingTarget(host="localhost", expected_findings=[])
        assert t.is_training
        assert t.target_type == "training"

    def test_expected_findings(self):
        t = TrainingTarget(
            host="localhost",
            expected_findings=[
                ExpectedFinding(title="XSS", severity="high"),
                ExpectedFinding(title="SQLi", severity="critical"),
            ],
        )
        assert len(t.expected_findings) == 2
        assert t.expected_findings[0].title == "XSS"

    def test_auth_config(self):
        auth = AuthConfig(username="admin", password="pass", login_url="/login")
        t = TrainingTarget(host="localhost", auth=auth)
        assert t.auth.username == "admin"

    def test_from_profile(self, tmp_path):
        profile = tmp_path / "test.yaml"
        profile.write_text(
            "name: test\n"
            "target: localhost\n"
            "target_ports: [80, 443]\n"
            "max_steps: 50\n"
            "expected_findings:\n"
            "  - title: XSS\n"
            "    severity: high\n"
            "scan_paths:\n"
            "  - /admin\n"
        )
        t = TrainingTarget.from_profile(profile)
        assert t.host == "localhost"
        assert t.ports == [80, 443]
        assert t.max_steps == 50
        assert len(t.expected_findings) == 1
        assert t.scan_paths == ["/admin"]

    def test_inequality_live_vs_training(self):
        live = LiveTarget.domain("localhost")
        train = TrainingTarget(host="localhost")
        assert live != train
