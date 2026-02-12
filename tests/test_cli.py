"""Tests for CLI commands via typer.testing.CliRunner."""

from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from basilisk import __version__
from basilisk.cli import app

runner = CliRunner()


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


class TestAuditCommand:
    @patch("basilisk.cli.asyncio.run")
    def test_audit_invokes_run(self, mock_asyncio_run):
        mock_state = MagicMock()
        mock_state.total_findings = 0
        mock_state.phases = {}
        mock_state.status = "done"
        mock_asyncio_run.return_value = mock_state

        with (
            patch("basilisk.reporting.live_html.LiveHtmlRenderer") as mock_live,
            patch("basilisk.reporting.engine.ReportEngine") as mock_engine_cls,
        ):
            mock_live_inst = MagicMock()
            mock_live.return_value = mock_live_inst

            mock_engine_inst = MagicMock()
            mock_engine_inst.generate.return_value = []
            mock_engine_cls.return_value = mock_engine_inst

            runner.invoke(app, ["audit", "example.com", "--output", "test_reports"])
            # audit calls asyncio.run internally
            assert mock_asyncio_run.called


class TestRunPluginCommand:
    @patch("basilisk.cli.asyncio.run")
    def test_run_plugin(self, mock_asyncio_run):
        mock_result = MagicMock()
        mock_result.ok = True
        mock_result.findings = []
        mock_asyncio_run.return_value = [mock_result]

        result = runner.invoke(app, ["run", "ssl_check", "example.com"])
        assert result.exit_code == 0
        assert "ssl_check" in result.output

    @patch("basilisk.cli.asyncio.run")
    def test_run_plugin_error(self, mock_asyncio_run):
        mock_result = MagicMock()
        mock_result.ok = False
        mock_result.error = "Plugin failed"
        mock_asyncio_run.return_value = [mock_result]

        result = runner.invoke(app, ["run", "ssl_check", "example.com"])
        assert result.exit_code == 0


class TestProjectCommand:
    @patch("basilisk.config.Settings.load")
    @patch("basilisk.core.project_manager.ProjectManager")
    def test_project_create(self, mock_pm_cls, mock_settings_load):
        mock_settings_load.return_value = MagicMock()
        mock_pm = MagicMock()
        mock_project = MagicMock()
        mock_project.name = "test_proj"
        mock_project.path = "/tmp/test_proj"
        mock_pm.create.return_value = mock_project
        mock_pm_cls.return_value = mock_pm

        result = runner.invoke(
            app, ["project", "create", "test_proj", "--targets", "example.com"]
        )
        assert result.exit_code == 0

    @patch("basilisk.config.Settings.load")
    @patch("basilisk.core.project_manager.ProjectManager")
    def test_project_list_empty(self, mock_pm_cls, mock_settings_load):
        mock_settings_load.return_value = MagicMock()
        mock_pm = MagicMock()
        mock_pm.list_all.return_value = []
        mock_pm_cls.return_value = mock_pm

        result = runner.invoke(app, ["project", "list"])
        assert result.exit_code == 0
        assert "No projects found" in result.output
