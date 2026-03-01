"""TrainingDisplay — extends LiveDisplay with training-specific panel."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.console import Console, Group
from rich.panel import Panel
from rich.progress_bar import ProgressBar
from rich.table import Table

from basilisk.display.live import LiveDisplay
from basilisk.display.panels import activity_panel, header_panel

if TYPE_CHECKING:
    from basilisk.events.bus import EventBus
    from basilisk.training.validator import FindingTracker


class TrainingDisplay(LiveDisplay):
    """LiveDisplay extended with training validation panel.

    Shows real-time expected-vs-found checklist and coverage progress.
    """

    def __init__(
        self,
        bus: EventBus,
        tracker: FindingTracker,
        max_steps: int = 100,
        verbose: bool = False,
        console: Console | None = None,
        refresh_rate: float = 4.0,
    ) -> None:
        super().__init__(
            bus, max_steps=max_steps, verbose=verbose,
            console=console, refresh_rate=refresh_rate,
        )
        self._tracker = tracker

    def _render(self) -> Group:
        """Build training layout with validation panel."""
        panels = [header_panel(self.state), self._training_panel(), activity_panel(self.state)]
        return Group(*panels)

    def _training_panel(self) -> Panel:
        """Training validation checklist + coverage bar."""
        table = Table.grid(padding=(0, 2))
        table.add_column("title", min_width=22)
        table.add_column("severity", min_width=8)
        table.add_column("discovered", min_width=5)
        table.add_column("verified", min_width=5)
        table.add_column("step", min_width=4)

        discovered_count = 0
        total = len(self._tracker.tracked)

        for tf in self._tracker.tracked:
            disc = "[green]YES[/]" if tf.discovered else "[red]NO[/]"
            verif = "[green]YES[/]" if tf.verified else ("[yellow]NO[/]" if tf.discovered else "-")
            step_str = str(tf.discovery_step) if tf.discovery_step is not None else "-"
            sev_colors = {
                "critical": "bold red", "high": "red", "medium": "yellow", "low": "green",
            }
            sev = tf.expected.severity
            sev_style = sev_colors.get(sev, "")
            table.add_row(
                tf.expected.title[:24],
                f"[{sev_style}]{sev}[/{sev_style}]",
                disc,
                verif,
                step_str,
            )
            if tf.discovered:
                discovered_count += 1

        # Coverage progress bar
        bar = ProgressBar(total=max(total, 1), completed=discovered_count, width=30)
        pct = (discovered_count / total * 100) if total > 0 else 0.0
        coverage_text = Table.grid(padding=(0, 1))
        coverage_text.add_row(bar, f"{pct:.0f}%  ({discovered_count}/{total} discovered)")
        table.add_row("", "", "", "", "")
        table.add_row(coverage_text, "", "", "", "")

        return Panel(table, title="Training Validation", border_style="dim")
