"""Target table widget — shows targets with their scan status."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.widgets import DataTable, Static


class TargetTableWidget(Static):
    """Table showing all targets and their current scan status."""

    DEFAULT_CSS = """
    TargetTableWidget {
        height: 1fr;
        border: solid $secondary;
    }
    """

    def compose(self) -> ComposeResult:
        yield DataTable(id="target-table")

    def on_mount(self) -> None:
        table = self.query_one("#target-table", DataTable)
        table.add_columns("Host", "Type", "IPs", "Status", "Findings")

    def add_target(
        self,
        host: str,
        type_: str = "domain",
        ips: str = "",
        status: str = "pending",
        findings: int = 0,
    ) -> None:
        table = self.query_one("#target-table", DataTable)
        table.add_row(host, type_, ips, status, str(findings))

    def update_status(self, host: str, status: str, findings: int = 0) -> None:
        table = self.query_one("#target-table", DataTable)
        for row_key in table.rows:
            row = table.get_row(row_key)
            if row[0] == host:
                table.update_cell(row_key, "Status", status)
                table.update_cell(row_key, "Findings", str(findings))
                break

    def clear(self) -> None:
        table = self.query_one("#target-table", DataTable)
        table.clear()
