"""Phase progress widget — shows recon→scan→analyze→pentest pipeline."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import Label, ProgressBar, Static


class PhaseProgressWidget(Static):
    """Displays progress for all pipeline phases."""

    DEFAULT_CSS = """
    PhaseProgressWidget {
        height: auto;
        padding: 1 2;
        border: solid $primary;
        margin: 0 0 1 0;
    }
    .phase-row {
        height: 1;
        layout: horizontal;
    }
    .phase-name {
        width: 14;
        text-style: bold;
    }
    .phase-status {
        width: 14;
        text-align: right;
    }
    """

    def compose(self) -> ComposeResult:
        yield Label("[b]Pipeline Progress[/b]")
        for phase in ("recon", "scanning", "analysis", "pentesting"):
            with Vertical(classes="phase-row"):
                yield Label(f"  {phase.capitalize():<12}", id=f"phase-name-{phase}")
                yield ProgressBar(total=100, id=f"phase-bar-{phase}", show_eta=False)
                yield Label("Waiting", id=f"phase-status-{phase}")

    def update_phase(
        self, phase: str, completed: int, total: int, status: str
    ) -> None:
        bar = self.query_one(f"#phase-bar-{phase}", ProgressBar)
        status_label = self.query_one(f"#phase-status-{phase}", Label)

        if total > 0:
            bar.update(total=total, progress=completed)
        pct = (completed / total * 100) if total > 0 else 0

        if status == "done":
            status_label.update(f"[green]Done ({completed}/{total})[/green]")
        elif status == "running":
            status_label.update(f"[yellow]{completed}/{total} ({pct:.0f}%)[/yellow]")
        else:
            status_label.update("[dim]Waiting[/dim]")
