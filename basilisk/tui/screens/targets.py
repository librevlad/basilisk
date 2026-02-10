"""Targets screen — add/remove/import audit targets."""

from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Container, Horizontal
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Input, Label, Select


class TargetsScreen(Screen):
    """Target management screen: add domains, IPs, import from file."""

    BINDINGS = [
        ("a", "focus_add", "Add Target"),
        ("i", "import_file", "Import File"),
        ("delete", "remove_target", "Remove"),
        ("escape", "app.pop_screen", "Back"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with Container():
            yield Label("[bold]Targets[/bold]", id="targets-title")
            yield DataTable(id="targets-table")
            with Container(id="add-target-form"):
                with Horizontal():
                    yield Input(
                        placeholder="Host (domain, IP, or URL)...",
                        id="target-host-input",
                    )
                    yield Select(
                        [
                            ("Domain", "domain"),
                            ("IP", "ip"),
                            ("URL", "url"),
                            ("Subdomain", "subdomain"),
                        ],
                        value="domain",
                        id="target-type-select",
                        allow_blank=False,
                    )
                    yield Button("Add", id="add-target-btn", variant="primary")
                with Horizontal():
                    yield Input(
                        placeholder="Path to targets file (one per line)...",
                        id="import-path-input",
                    )
                    yield Button("Import", id="import-btn", variant="default")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#targets-table", DataTable)
        table.add_columns("Host", "Type", "IPs", "Status")
        table.cursor_type = "row"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "add-target-btn":
            self._add_target()
        elif event.button.id == "import-btn":
            self._import_from_file()

    def _add_target(self) -> None:
        host = self.query_one("#target-host-input", Input).value.strip()
        type_val = self.query_one("#target-type-select", Select).value

        if not host:
            self.notify("Host is required", severity="error")
            return

        table = self.query_one("#targets-table", DataTable)
        table.add_row(host, str(type_val), "", "pending")
        self.query_one("#target-host-input", Input).value = ""
        self.notify(f"Added target: {host}")

    def _import_from_file(self) -> None:
        path_str = self.query_one("#import-path-input", Input).value.strip()
        if not path_str:
            self.notify("File path is required", severity="error")
            return

        path = Path(path_str)
        if not path.exists():
            self.notify(f"File not found: {path}", severity="error")
            return

        table = self.query_one("#targets-table", DataTable)
        count = 0
        for line in path.read_text(encoding="utf-8").splitlines():
            host = line.strip()
            if host and not host.startswith("#"):
                table.add_row(host, "domain", "", "pending")
                count += 1

        self.notify(f"Imported {count} targets from {path.name}")
        self.query_one("#import-path-input", Input).value = ""

    def action_focus_add(self) -> None:
        self.query_one("#target-host-input", Input).focus()

    def action_import_file(self) -> None:
        self.query_one("#import-path-input", Input).focus()

    def action_remove_target(self) -> None:
        table = self.query_one("#targets-table", DataTable)
        if table.cursor_row is not None:
            try:
                row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
                table.remove_row(row_key)
                self.notify("Target removed")
            except Exception:
                self.notify("No target selected", severity="warning")

    def get_targets(self) -> list[tuple[str, str]]:
        """Return list of (host, type) from the table."""
        table = self.query_one("#targets-table", DataTable)
        result = []
        for row_key in table.rows:
            row = table.get_row(row_key)
            result.append((row[0], row[1]))
        return result
