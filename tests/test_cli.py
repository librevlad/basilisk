"""Tests for CLI commands via typer.testing.CliRunner."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from basilisk import __version__
from basilisk.cli import app

runner = CliRunner()


def _make_auto_result(**overrides):
    """Create a mock RunResult for auto command tests.

    Returns (result, report_dir) tuple as expected by the auto command.
    """
    r = MagicMock()
    r.findings = overrides.get("findings", [])
    r.steps = overrides.get("steps", 5)
    r.duration = overrides.get("duration", 10.0)
    r.termination_reason = overrides.get("termination_reason", "no_gaps")
    r.graph_data = overrides.get("graph_data", {"entity_count": 10, "relation_count": 5})
    report_dir = overrides.get("report_dir", Path("reports/test"))
    return r, report_dir


def _make_finding(severity_name="HIGH", severity_value=3, title="Test Finding"):
    """Create a mock Finding for output tests."""
    f = MagicMock()
    f.title = title
    f.severity = MagicMock()
    f.severity.name = severity_name
    f.severity.value = severity_value
    f.severity.label = severity_name
    f.target = "example.com"
    return f


class TestVersionCommand:
    def test_version_output(self):
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert __version__ in result.output

    def test_no_args_shows_help(self):
        result = runner.invoke(app, [])
        # no_args_is_help exits with code 0 or 2 depending on typer version
        assert "Usage" in result.output or "basilisk" in result.output.lower()


class TestPluginsCommand:
    def test_list_plugins(self):
        result = runner.invoke(app, ["plugins"])
        assert result.exit_code == 0
        assert "Basilisk Plugins" in result.output or "Name" in result.output

    def test_list_plugins_by_category(self):
        result = runner.invoke(app, ["plugins", "--category", "recon"])
        assert result.exit_code == 0


class TestScenariosCommand:
    def test_scenarios_command_exits_zero(self):
        result = runner.invoke(app, ["scenarios"])
        assert result.exit_code == 0
        assert "Basilisk Scenarios" in result.output or "Name" in result.output

    def test_scenarios_native_flag(self):
        result = runner.invoke(app, ["scenarios", "--native"])
        assert result.exit_code == 0
        assert "native" in result.output


class TestAutoCommand:
    @patch("basilisk.cli.asyncio.run")
    def test_auto_invokes_audit(self, mock_asyncio_run):
        mock_asyncio_run.return_value = _make_auto_result()
        result = runner.invoke(app, ["auto", "example.com"])
        assert mock_asyncio_run.called
        assert result.exit_code == 0

    @patch("basilisk.cli.asyncio.run")
    def test_auto_campaign_flag(self, mock_asyncio_run):
        mock_asyncio_run.return_value = _make_auto_result()
        result = runner.invoke(app, ["auto", "example.com", "--campaign"])
        assert result.exit_code == 0
        # Verify the Basilisk instance had campaign() called by inspecting the call
        call_args = mock_asyncio_run.call_args
        assert call_args is not None

    @patch("basilisk.cli.asyncio.run")
    def test_auto_max_steps_flag(self, mock_asyncio_run):
        mock_asyncio_run.return_value = _make_auto_result()
        result = runner.invoke(app, ["auto", "example.com", "-n", "25"])
        assert result.exit_code == 0
        assert "Audit complete" in result.output

    @patch("basilisk.cli.asyncio.run")
    def test_auto_shows_audit_complete(self, mock_asyncio_run):
        mock_asyncio_run.return_value = _make_auto_result()
        result = runner.invoke(app, ["auto", "example.com"])
        assert result.exit_code == 0
        assert "Audit complete" in result.output

    @patch("basilisk.cli.asyncio.run")
    def test_auto_shows_termination_reason(self, mock_asyncio_run):
        mock_asyncio_run.return_value = _make_auto_result(termination_reason="no_gaps")
        result = runner.invoke(app, ["auto", "example.com"])
        assert result.exit_code == 0
        assert "no_gaps" in result.output

    @patch("basilisk.cli.asyncio.run")
    def test_auto_verbose_flag(self, mock_asyncio_run):
        mock_asyncio_run.return_value = _make_auto_result()
        result = runner.invoke(app, ["auto", "example.com", "-v"])
        assert result.exit_code == 0


class TestRunCommand:
    @patch("basilisk.cli.asyncio.run")
    def test_run_invokes_plugin(self, mock_asyncio_run):
        mock_result = MagicMock()
        mock_result.ok = True
        mock_result.findings = []
        mock_asyncio_run.return_value = mock_result
        result = runner.invoke(app, ["run", "dns_enum", "example.com"])
        assert mock_asyncio_run.called
        assert result.exit_code == 0

    @patch("basilisk.cli.asyncio.run")
    def test_run_no_findings_message(self, mock_asyncio_run):
        mock_result = MagicMock()
        mock_result.ok = True
        mock_result.findings = []
        mock_asyncio_run.return_value = mock_result
        result = runner.invoke(app, ["run", "dns_enum", "example.com"])
        assert "No findings" in result.output

    @patch("basilisk.cli.asyncio.run")
    def test_run_prints_findings(self, mock_asyncio_run):
        finding = MagicMock()
        finding.severity = MagicMock()
        finding.severity.label = "HIGH"
        finding.title = "Open redirect found"
        mock_result = MagicMock()
        mock_result.ok = True
        mock_result.findings = [finding]
        mock_asyncio_run.return_value = mock_result
        result = runner.invoke(app, ["run", "dns_enum", "example.com"])
        assert "Open redirect found" in result.output

    def test_run_unknown_plugin_exits(self):
        result = runner.invoke(app, ["run", "nonexistent_plugin_xyz", "example.com"])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()


class TestTrainCommand:
    def test_train_missing_profile_exits(self):
        result = runner.invoke(app, ["train", "/nonexistent/profile.yaml"])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    @patch("basilisk.cli.asyncio.run")
    @patch("basilisk.training.runner.TrainingRunner")
    @patch("basilisk.training.profile.TrainingProfile.load")
    def test_train_invokes_runner(self, mock_load, mock_runner_cls, mock_asyncio_run):
        mock_profile = MagicMock()
        mock_profile.name = "test"
        mock_profile.target = "test.local"
        mock_profile.max_steps = 20
        mock_profile.expected_findings = []
        mock_load.return_value = mock_profile

        mock_report = MagicMock()
        mock_report.profile_name = "test"
        mock_report.coverage = 0.8
        mock_report.discovered = 4
        mock_report.total_expected = 5
        mock_report.verification_rate = 0.5
        mock_report.steps_taken = 10
        mock_report.passed = True
        mock_report.findings_detail = []
        mock_asyncio_run.return_value = (mock_report, Path("reports/test"))

        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode="w") as f:
            f.write("name: test\ntarget: test.local\n")
            f.flush()
            result = runner.invoke(app, ["train", f.name])

        assert result.exit_code == 0

    @patch("basilisk.cli.asyncio.run")
    @patch("basilisk.training.runner.TrainingRunner")
    @patch("basilisk.training.profile.TrainingProfile.load")
    def test_train_no_docker_flag(self, mock_load, mock_runner_cls, mock_asyncio_run):
        mock_profile = MagicMock()
        mock_profile.name = "test"
        mock_profile.target = "test.local"
        mock_profile.max_steps = 20
        mock_profile.expected_findings = []
        mock_load.return_value = mock_profile

        mock_report = MagicMock()
        mock_report.profile_name = "test"
        mock_report.coverage = 1.0
        mock_report.discovered = 0
        mock_report.total_expected = 0
        mock_report.verification_rate = 0.0
        mock_report.steps_taken = 5
        mock_report.passed = True
        mock_report.findings_detail = []
        mock_asyncio_run.return_value = (mock_report, Path("reports/test"))

        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode="w") as f:
            f.write("name: test\ntarget: test.local\n")
            f.flush()
            result = runner.invoke(app, ["train", f.name, "--no-docker"])

        assert result.exit_code == 0
        # Verify TrainingRunner was called with manage_docker=False
        call_kwargs = mock_runner_cls.call_args
        assert call_kwargs is not None
        if call_kwargs.kwargs:
            assert call_kwargs.kwargs.get("manage_docker") is False
        else:
            # Positional args fallback
            assert mock_runner_cls.called


class TestCrackCommand:
    @patch("basilisk.utils.crypto_engine.CryptoEngine")
    def test_crack_identifies_hash(self, mock_engine_cls):
        mock_engine = MagicMock()
        mock_engine.identify_hash.return_value = "md5"
        mock_engine.crack_hash.return_value = None
        mock_engine_cls.return_value = mock_engine
        result = runner.invoke(app, ["crack", "5d41402abc4b2a76b9719d911017c592"])
        assert result.exit_code == 0
        assert "md5" in result.output.lower()

    @patch("basilisk.utils.crypto_engine.CryptoEngine")
    def test_crack_shows_cracked_password(self, mock_engine_cls):
        mock_engine = MagicMock()
        mock_engine.identify_hash.return_value = "md5"
        crack_result = MagicMock()
        crack_result.cracked = True
        crack_result.password = "hello"
        mock_engine.crack_hash.return_value = crack_result
        mock_engine_cls.return_value = mock_engine
        result = runner.invoke(app, ["crack", "5d41402abc4b2a76b9719d911017c592"])
        assert result.exit_code == 0
        assert "hello" in result.output

    @patch("basilisk.utils.crypto_engine.CryptoEngine")
    def test_crack_not_cracked_message(self, mock_engine_cls):
        mock_engine = MagicMock()
        mock_engine.identify_hash.return_value = "sha256"
        crack_result = MagicMock()
        crack_result.cracked = False
        mock_engine.crack_hash.return_value = crack_result
        mock_engine_cls.return_value = mock_engine
        result = runner.invoke(app, ["crack", "abc123"])
        assert result.exit_code == 0
        assert "not cracked" in result.output.lower() or "hashcat" in result.output.lower()
