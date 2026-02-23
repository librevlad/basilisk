"""Finding feed widget — live stream of vulnerability discoveries."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.widgets import RichLog, Static

from basilisk.models.result import Finding


class FindingFeedWidget(Static):
    """Live feed of findings as they are discovered."""

    DEFAULT_CSS = """
    FindingFeedWidget {
        height: 1fr;
        border: solid $secondary;
        margin: 0 0 1 0;
    }
    """

    def compose(self) -> ComposeResult:
        yield RichLog(id="finding-log", highlight=True, markup=True, wrap=True)

    def add_finding(self, finding: Finding, target: str = "") -> None:
        log = self.query_one("#finding-log", RichLog)
        color = finding.severity.color
        prefix = f"[{color}][{finding.severity.label:>8}][/{color}]"
        target_str = f" [dim]{target}[/dim]" if target else ""
        log.write(f"{prefix} {finding.title}{target_str}")

    def clear(self) -> None:
        log = self.query_one("#finding-log", RichLog)
        log.clear()
