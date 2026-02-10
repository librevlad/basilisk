"""Tests for Finding, PluginResult, and Severity models."""

from basilisk.models.result import Finding, PluginResult, Severity


class TestSeverity:
    def test_ordering(self):
        assert Severity.INFO < Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL

    def test_label(self):
        assert Severity.CRITICAL.label == "CRITICAL"
        assert Severity.INFO.label == "INFO"

    def test_color(self):
        assert Severity.CRITICAL.color == "bold red"
        assert Severity.INFO.color == "blue"


class TestFinding:
    def test_factory_methods(self):
        f = Finding.critical("RCE", description="Remote code execution")
        assert f.severity == Severity.CRITICAL
        assert f.title == "RCE"

        f = Finding.high("SQLi")
        assert f.severity == Severity.HIGH

        f = Finding.medium("Missing CSP")
        assert f.severity == Severity.MEDIUM

        f = Finding.low("Server header")
        assert f.severity == Severity.LOW

        f = Finding.info("Open port")
        assert f.severity == Severity.INFO

    def test_tags(self):
        f = Finding.high("XSS", tags=["xss", "owasp:a07"])
        assert "xss" in f.tags
        assert len(f.tags) == 2

    def test_default_fields(self):
        f = Finding.info("test")
        assert f.description == ""
        assert f.evidence == ""
        assert f.remediation == ""
        assert f.tags == []


class TestPluginResult:
    def test_success_factory(self):
        r = PluginResult.success("ssl_check", "example.com", duration=1.5)
        assert r.status == "success"
        assert r.ok is True
        assert r.error is None

    def test_fail_factory(self):
        r = PluginResult.fail("ssl_check", "example.com", error="Connection refused")
        assert r.status == "error"
        assert r.ok is False
        assert r.error == "Connection refused"

    def test_skipped_factory(self):
        r = PluginResult.skipped("ssl_check", "example.com", reason="No port 443")
        assert r.status == "skipped"
        assert r.ok is False

    def test_max_severity(self):
        r = PluginResult.success(
            "test", "example.com",
            findings=[
                Finding.info("info"),
                Finding.high("high"),
                Finding.medium("medium"),
            ]
        )
        assert r.max_severity == Severity.HIGH

    def test_max_severity_empty(self):
        r = PluginResult.success("test", "example.com")
        assert r.max_severity is None

    def test_findings_by_severity(self):
        r = PluginResult.success(
            "test", "example.com",
            findings=[
                Finding.info("a"),
                Finding.high("b"),
                Finding.high("c"),
                Finding.medium("d"),
            ]
        )
        highs = r.findings_by_severity(Severity.HIGH)
        assert len(highs) == 2
        assert all(f.severity == Severity.HIGH for f in highs)

    def test_data_field(self):
        r = PluginResult.success(
            "ssl_check", "example.com",
            data={"protocol": "TLSv1.3", "cipher": "AES256"}
        )
        assert r.data["protocol"] == "TLSv1.3"
