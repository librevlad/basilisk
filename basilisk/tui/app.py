"""BasiliskApp — main Textual TUI application."""

from __future__ import annotations

from textual.app import App, ComposeResult
from textual.widgets import Footer, Header

from basilisk.tui.screens.dashboard import DashboardScreen
from basilisk.tui.screens.projects import ProjectsScreen


class BasiliskApp(App):
    """Basilisk interactive TUI dashboard."""

    TITLE = "Basilisk"
    SUB_TITLE = "Security Audit Framework"
    CSS_PATH = "styles/app.tcss"

    BINDINGS = [
        ("p", "push_screen('projects')", "Projects"),
        ("d", "push_screen('dashboard')", "Dashboard"),
        ("t", "push_screen('targets')", "Targets"),
        ("c", "push_screen('config')", "Config"),
        ("r", "push_screen('report')", "Report"),
        ("q", "quit", "Quit"),
    ]

    SCREENS = {
        "projects": ProjectsScreen,
        "dashboard": DashboardScreen,
    }

    def __init__(
        self,
        audit_target: str | None = None,
        audit_plugins: list[str] | None = None,
        audit_config: str | None = None,
        audit_wordlists: list[str] | None = None,
        audit_project: str | None = None,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self._audit_target = audit_target
        self._audit_plugins = audit_plugins
        self._audit_config = audit_config
        self._audit_wordlists = audit_wordlists
        self._audit_project = audit_project
        self._auto_audit = audit_target is not None

    def compose(self) -> ComposeResult:
        yield Header()
        yield Footer()

    def on_mount(self) -> None:
        self._register_lazy_screens()
        if self._auto_audit:
            self.push_screen("dashboard")
            self.call_later(self._start_auto_audit)
        else:
            self.push_screen("projects")

    def _register_lazy_screens(self) -> None:
        from basilisk.tui.screens.config import ConfigScreen
        from basilisk.tui.screens.report import ReportScreen
        from basilisk.tui.screens.targets import TargetsScreen

        self.install_screen(TargetsScreen, name="targets")
        self.install_screen(ConfigScreen, name="config")
        self.install_screen(ReportScreen, name="report")

    async def _start_auto_audit(self) -> None:
        """Start the audit on the dashboard screen after it's mounted."""
        dashboard = self.screen
        if isinstance(dashboard, DashboardScreen) and self._audit_target:
            await dashboard.start_audit(
                targets=[self._audit_target],
                plugins=self._audit_plugins,
                config_path=self._audit_config,
                wordlists=self._audit_wordlists,
                project_name=self._audit_project,
            )
