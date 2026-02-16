"""Tests for live HTML report renderer."""

from unittest.mock import MagicMock

from basilisk.reporting.live_html import (
    LiveHtmlRenderer,
    _extract_attack_surface,
    _is_noise,
)


class TestIsNoise:
    def test_info_not_found_is_noise(self):
        assert _is_noise({"severity": "INFO", "title": "XSS not found"})

    def test_info_not_detected_is_noise(self):
        assert _is_noise({"severity": "INFO", "title": "WAF not detected"})

    def test_info_no_issues_is_noise(self):
        assert _is_noise({"severity": "INFO", "title": "No issues with CSP"})

    def test_info_not_vulnerable_is_noise(self):
        assert _is_noise({"severity": "INFO", "title": "Host not vulnerable"})

    def test_info_not_reachable_is_noise(self):
        assert _is_noise({"severity": "INFO", "title": "Host not reachable"})

    def test_info_real_finding_not_noise(self):
        assert not _is_noise({"severity": "INFO", "title": "Server: Apache/2.4.52"})

    def test_high_never_noise(self):
        assert not _is_noise({"severity": "HIGH", "title": "XSS not found"})

    def test_medium_never_noise(self):
        assert not _is_noise({"severity": "MEDIUM", "title": "No issues"})


class TestExtractAttackSurface:
    def test_empty_results(self):
        surface = _extract_attack_surface([])
        assert surface["hosts"] == {}
        assert surface["subdomains"] == []
        assert surface["emails"] == []

    def test_ports_and_services(self):
        result = MagicMock()
        result.target = "example.com"
        result.data = {
            "open_ports": [{"port": 80, "state": "open"}],
            "services": [{"port": 80, "service": "http"}],
        }
        surface = _extract_attack_surface([result])
        assert len(surface["hosts"]["example.com"]["ports"]) == 1
        assert len(surface["hosts"]["example.com"]["services"]) == 1

    def test_technologies(self):
        result = MagicMock()
        result.target = "example.com"
        result.data = {"technologies": ["PHP", "Apache"]}
        surface = _extract_attack_surface([result])
        assert "PHP" in surface["hosts"]["example.com"]["tech"]
        assert "Apache" in surface["hosts"]["example.com"]["tech"]

    def test_subdomains(self):
        result = MagicMock()
        result.target = "example.com"
        result.data = {"subdomains": ["api.example.com", "mail.example.com"]}
        surface = _extract_attack_surface([result])
        assert "api.example.com" in surface["subdomains"]
        assert "mail.example.com" in surface["subdomains"]

    def test_emails(self):
        result = MagicMock()
        result.target = "example.com"
        result.data = {
            "domain_emails": ["admin@example.com"],
            "other_emails": ["test@gmail.com"],
        }
        surface = _extract_attack_surface([result])
        assert "admin@example.com" in surface["emails"]
        assert "test@gmail.com" in surface["emails"]

    def test_dedup_across_results(self):
        r1 = MagicMock()
        r1.target = "example.com"
        r1.data = {"technologies": ["PHP"]}

        r2 = MagicMock()
        r2.target = "example.com"
        r2.data = {"technologies": ["PHP", "Apache"]}

        surface = _extract_attack_surface([r1, r2])
        assert surface["hosts"]["example.com"]["tech"] == ["PHP", "Apache"]

    def test_multiple_hosts(self):
        r1 = MagicMock()
        r1.target = "a.com"
        r1.data = {"open_ports": [{"port": 80}]}

        r2 = MagicMock()
        r2.target = "b.com"
        r2.data = {"open_ports": [{"port": 443}]}

        surface = _extract_attack_surface([r1, r2])
        assert "a.com" in surface["hosts"]
        assert "b.com" in surface["hosts"]

    def test_admin_panels(self):
        result = MagicMock()
        result.target = "example.com"
        result.data = {"admin_panels": [{"url": "/admin", "status": 200}]}
        surface = _extract_attack_surface([result])
        assert len(surface["hosts"]["example.com"]["admin_panels"]) == 1

    def test_backup_files(self):
        result = MagicMock()
        result.target = "example.com"
        result.data = {"backup_files": [{"path": "/backup.zip"}]}
        surface = _extract_attack_surface([result])
        assert len(surface["hosts"]["example.com"]["backup_files"]) == 1


class TestLiveHtmlRenderer:
    def test_init(self, tmp_path):
        path = tmp_path / "report.html"
        renderer = LiveHtmlRenderer(path)
        assert renderer.html_path == path

    def test_update_creates_file(self, tmp_path):
        path = tmp_path / "report.html"
        renderer = LiveHtmlRenderer(path)

        state = MagicMock()
        state.status = "completed"
        state.total_findings = 0
        state.results = []
        state.phases = {}

        renderer.update(state)
        assert path.exists()
        content = path.read_text(encoding="utf-8")
        assert "Basilisk" in content

    def test_update_with_findings(self, tmp_path):
        from basilisk.models.result import Finding, PluginResult

        path = tmp_path / "report.html"
        renderer = LiveHtmlRenderer(path)

        finding = Finding.high("Test Finding", description="A test", evidence="proof")
        result = PluginResult.success(
            "test_plugin", "example.com", findings=[finding],
        )

        state = MagicMock()
        state.status = "completed"
        state.total_findings = 1
        state.results = [result]
        state.phases = {}

        renderer.update(state)
        content = path.read_text(encoding="utf-8")
        assert "Test Finding" in content

    def test_update_running(self, tmp_path):
        path = tmp_path / "report.html"
        renderer = LiveHtmlRenderer(path)

        state = MagicMock()
        state.status = "running"
        state.total_findings = 0
        state.results = []
        state.phases = {}

        renderer.update(state)
        assert path.exists()
        assert path.read_text(encoding="utf-8")


class TestLiveReportEngine:
    def test_creates_both_files(self, tmp_path):
        from basilisk.reporting.live_html import LiveReportEngine

        engine = LiveReportEngine(tmp_path)

        state = MagicMock()
        state.status = "completed"
        state.total_findings = 0
        state.results = []
        state.phases = {}

        engine.update(state)
        assert engine.html_path.exists()
        assert engine.json_path.exists()

    def test_json_has_status(self, tmp_path):
        import json

        from basilisk.reporting.live_html import LiveReportEngine

        engine = LiveReportEngine(tmp_path)

        state = MagicMock()
        state.status = "running"
        state.total_findings = 5
        state.results = []
        state.phases = {}

        engine.update(state)
        data = json.loads(engine.json_path.read_text(encoding="utf-8"))
        assert data["status"] == "running"
        assert data["total_findings"] == 5
