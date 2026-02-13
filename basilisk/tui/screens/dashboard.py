"""Dashboard screen — real-time progress, findings feed, stats."""

from __future__ import annotations

import logging

from textual.app import ComposeResult
from textual.containers import Container
from textual.screen import Screen
from textual.widgets import Footer, Header, Label
from textual.worker import Worker, WorkerState

from basilisk.tui.messages import AuditComplete, AuditFinding, AuditProgress
from basilisk.tui.widgets.finding_feed import FindingFeedWidget
from basilisk.tui.widgets.phase_progress import PhaseProgressWidget
from basilisk.tui.widgets.stats_panel import StatsPanelWidget

logger = logging.getLogger(__name__)


class DashboardScreen(Screen):
    """Main dashboard showing audit progress in real-time."""

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("p", "pause", "Pause/Cancel"),
        ("e", "export", "Export"),
        ("escape", "app.pop_screen", "Back"),
    ]

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._severity_counts: dict[str, int] = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
        }
        self._audit_worker: Worker | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        with Container():
            yield Label(
                "[bold]Dashboard[/bold] — Real-time audit progress",
                id="dashboard-title",
            )
            yield PhaseProgressWidget(id="phase-progress")
            yield StatsPanelWidget(id="stats-panel")
            yield FindingFeedWidget(id="finding-feed")
        yield Footer()

    async def start_audit(
        self,
        targets: list[str],
        plugins: list[str] | None = None,
        config_path: str | None = None,
        wordlists: list[str] | None = None,
        project_name: str | None = None,
    ) -> None:
        """Launch an audit as a Textual async worker."""
        self._severity_counts = {k: 0 for k in self._severity_counts}
        self._project_name = project_name
        self.query_one("#finding-feed", FindingFeedWidget).clear()
        self.query_one("#stats-panel", StatsPanelWidget).update_counts(self._severity_counts)

        label = f"[bold]Auditing[/bold] {', '.join(targets)}"
        if project_name:
            label += f" [dim]project={project_name}[/dim]"
        self.query_one("#dashboard-title", Label).update(label)

        self._audit_worker = self.run_worker(
            self._run_pipeline(targets, plugins, config_path, wordlists, project_name),
            name="audit-pipeline",
            exclusive=True,
        )

    async def _run_pipeline(
        self,
        targets: list[str],
        plugins: list[str] | None,
        config_path: str | None,
        wordlists: list[str] | None,
        project_name: str | None,
    ) -> None:
        """The coroutine that runs inside the Textual worker."""
        from basilisk.core.facade import Audit

        screen = self

        from pathlib import Path

        from basilisk.reporting.live_html import LiveHtmlRenderer
        live_renderer = LiveHtmlRenderer(Path("reports/live_report.html"))

        def on_progress(state):
            screen.post_message(AuditProgress(state))
            live_renderer.update(state)

        def on_finding(finding, target=""):
            screen.post_message(AuditFinding(finding, target=target))

        audit_builder = Audit(*targets)
        if config_path:
            audit_builder = audit_builder.with_config(config_path)
        if plugins:
            audit_builder = audit_builder.plugins(*plugins)
        if wordlists:
            audit_builder = audit_builder.wordlists(*wordlists)
        if project_name:
            from basilisk.config import Settings
            from basilisk.core.project_manager import ProjectManager

            pm = ProjectManager(Settings.load())
            try:
                proj = pm.load(project_name)
            except FileNotFoundError:
                proj = pm.create(project_name, targets=targets)
            audit_builder = audit_builder.for_project(proj)

        audit_builder = (
            audit_builder
            .discover().scan().analyze().pentest()
            .on_progress(on_progress)
            .on_finding(on_finding)
        )

        try:
            state = await audit_builder.run()
            self.post_message(AuditComplete(state))
        except Exception as e:
            logger.exception("Audit pipeline failed")
            from basilisk.core.pipeline import PipelineState
            self.post_message(
                AuditComplete(PipelineState(status="failed"), error=str(e))
            )

    # --- Message handlers ---

    def on_audit_progress(self, message: AuditProgress) -> None:
        """Update phase progress bars from pipeline state."""
        state = message.state
        phase_widget = self.query_one("#phase-progress", PhaseProgressWidget)

        for phase_name, phase in state.phases.items():
            phase_widget.update_phase(
                phase_name,
                completed=phase.completed,
                total=phase.total,
                status=phase.status,
            )

    def on_audit_finding(self, message: AuditFinding) -> None:
        """Add finding to live feed and update severity counts."""
        finding = message.finding
        feed = self.query_one("#finding-feed", FindingFeedWidget)
        feed.add_finding(finding, target=message.target)

        sev_name = finding.severity.label
        if sev_name in self._severity_counts:
            self._severity_counts[sev_name] += 1
        stats = self.query_one("#stats-panel", StatsPanelWidget)
        stats.update_counts(self._severity_counts)

    def on_audit_complete(self, message: AuditComplete) -> None:
        """Handle audit completion."""
        title = self.query_one("#dashboard-title", Label)
        if message.error:
            title.update(f"[bold red]Audit failed:[/] {message.error}")
            self.notify(f"Audit failed: {message.error}", severity="error")
        else:
            total = message.state.total_findings
            suffix = ""
            if hasattr(self, "_project_name") and self._project_name:
                suffix = f" [dim]saved to {self._project_name}[/dim]"
            title.update(f"[bold green]Audit complete![/] {total} findings{suffix}")
            self.notify(f"Audit complete! {total} findings", severity="information")

    def action_pause(self) -> None:
        if self._audit_worker and self._audit_worker.state == WorkerState.RUNNING:
            self._audit_worker.cancel()
            self.notify("Audit cancelled")
        else:
            self.notify("No audit running")

    def action_export(self) -> None:
        self.notify("Export not yet implemented")

    def action_quit(self) -> None:
        self.app.exit()
