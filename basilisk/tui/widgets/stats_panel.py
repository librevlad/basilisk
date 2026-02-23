"""Stats panel widget — severity distribution counters."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.widgets import Label, Static


class StatsPanelWidget(Static):
    """Shows severity counts: CRIT | HIGH | MED | LOW | INFO."""

    DEFAULT_CSS = """
    StatsPanelWidget {
        height: 3;
        layout: horizontal;
        padding: 0 2;
        margin: 0 0 1 0;
        border: solid $primary;
    }
    .stat-item {
        width: 1fr;
        content-align: center middle;
        text-style: bold;
    }
    """

    def compose(self) -> ComposeResult:
        yield Label("[bold red]0[/] CRIT", id="stat-critical", classes="stat-item")
        yield Label("[red]0[/] HIGH", id="stat-high", classes="stat-item")
        yield Label("[yellow]0[/] MED", id="stat-medium", classes="stat-item")
        yield Label("[green]0[/] LOW", id="stat-low", classes="stat-item")
        yield Label("[blue]0[/] INFO", id="stat-info", classes="stat-item")

    def update_counts(self, counts: dict[str, int]) -> None:
        mapping = {
            "CRITICAL": ("stat-critical", "bold red", "CRIT"),
            "HIGH": ("stat-high", "red", "HIGH"),
            "MEDIUM": ("stat-medium", "yellow", "MED"),
            "LOW": ("stat-low", "green", "LOW"),
            "INFO": ("stat-info", "blue", "INFO"),
        }
        for sev, (widget_id, color, label) in mapping.items():
            count = counts.get(sev, 0)
            self.query_one(f"#{widget_id}", Label).update(
                f"[{color}]{count}[/{color}] {label}"
            )
