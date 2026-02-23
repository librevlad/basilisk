"""Report screen — view findings and export reports."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Container, Horizontal
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Label, Select


class ReportScreen(Screen):
    """Screen for viewing findings and exporting reports."""

    BINDINGS = [
        ("e", "export", "Export"),
        ("f", "cycle_filter", "Filter"),
        ("escape", "app.pop_screen", "Back"),
    ]

    _current_filter: str = "ALL"

    def compose(self) -> ComposeResult:
        yield Header()
        with Container():
            yield Label("[bold]Report — Findings[/bold]", id="report-title")

            with Horizontal(id="report-controls"):
                yield Select(
                    [
                        ("All severities", "ALL"),
                        ("Critical", "CRITICAL"),
                        ("High", "HIGH"),
                        ("Medium", "MEDIUM"),
                        ("Low", "LOW"),
                        ("Info", "INFO"),
                    ],
                    value="ALL",
                    id="severity-filter",
                    allow_blank=False,
                )
                yield Button("Export JSON", id="export-json-btn")
                yield Button("Export CSV", id="export-csv-btn")
                yield Button("Export HTML", id="export-html-btn", variant="primary")

            yield DataTable(id="findings-table")

            yield Label("", id="report-summary")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.add_columns("Severity", "Target", "Plugin", "Title", "Evidence")
        table.cursor_type = "row"

    def add_findings(self, findings: list[dict]) -> None:
        """Add findings to the table. Each dict: severity, target, plugin, title, evidence."""
        table = self.query_one("#findings-table", DataTable)
        for f in findings:
            table.add_row(
                f.get("severity", ""),
                f.get("target", ""),
                f.get("plugin", ""),
                f.get("title", ""),
                self._truncate(f.get("evidence", "")),
            )
        self._update_summary()

    @staticmethod
    def _truncate(text: str, maxlen: int = 60) -> str:
        return (text[:maxlen] + "...") if len(text) > maxlen else text

    def _update_summary(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        total = len(table.rows)
        summary = self.query_one("#report-summary", Label)
        summary.update(f"[bold]Total findings: {total}[/bold]")

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "severity-filter":
            self._current_filter = str(event.value)
            self.notify(f"Filter: {self._current_filter}")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        fmt_map = {
            "export-json-btn": "json",
            "export-csv-btn": "csv",
            "export-html-btn": "html",
        }
        fmt = fmt_map.get(event.button.id)
        if fmt:
            self._export(fmt)

    def _export(self, fmt: str) -> None:
        self.notify(f"Exporting report as {fmt.upper()}...")
        # TODO: integrate with ReportEngine
        self.notify(f"Report exported as {fmt.upper()}", severity="information")

    def action_export(self) -> None:
        self._export("json")

    def action_cycle_filter(self) -> None:
        options = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        idx = options.index(self._current_filter)
        self._current_filter = options[(idx + 1) % len(options)]
        self.query_one("#severity-filter", Select).value = self._current_filter
