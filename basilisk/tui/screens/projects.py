"""Projects screen — list, create, and select projects."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Container
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Input, Label


class ProjectsScreen(Screen):
    """Project management screen."""

    BINDINGS = [
        ("n", "new_project", "New Project"),
        ("enter", "select_project", "Select"),
        ("d", "delete_project", "Delete"),
        ("escape", "app.pop_screen", "Back"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with Container():
            yield Label("[bold]Projects[/bold]", id="projects-title")
            yield DataTable(id="projects-table")
            with Container(id="new-project-form"):
                yield Input(placeholder="Project name...", id="project-name-input")
                yield Input(placeholder="Targets (comma-separated)...", id="targets-input")
                yield Button("Create Project", id="create-btn", variant="primary")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#projects-table", DataTable)
        table.add_columns("Name", "Status", "Targets", "Created")
        self._refresh_projects()

    def _refresh_projects(self) -> None:
        from basilisk.config import Settings
        from basilisk.core.project_manager import ProjectManager

        try:
            pm = ProjectManager(Settings.load())
            projects = pm.list_all()
            table = self.query_one("#projects-table", DataTable)
            table.clear()
            for p in projects:
                table.add_row(
                    p.name, p.status.value,
                    str(len(p.targets)),
                    p.created_at.strftime("%Y-%m-%d %H:%M"),
                )
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "create-btn":
            self._create_project()

    def _create_project(self) -> None:
        from basilisk.config import Settings
        from basilisk.core.project_manager import ProjectManager

        name = self.query_one("#project-name-input", Input).value.strip()
        targets_str = self.query_one("#targets-input", Input).value.strip()

        if not name:
            self.notify("Project name is required", severity="error")
            return

        targets = [t.strip() for t in targets_str.split(",") if t.strip()] if targets_str else []

        try:
            pm = ProjectManager(Settings.load())
            pm.create(name, targets=targets)
            self.notify(f"Project '{name}' created!", severity="information")
            self._refresh_projects()
            self.query_one("#project-name-input", Input).value = ""
            self.query_one("#targets-input", Input).value = ""
        except Exception as e:
            self.notify(f"Error: {e}", severity="error")

    def action_new_project(self) -> None:
        self.query_one("#project-name-input", Input).focus()

    def action_select_project(self) -> None:
        self.notify("Project selection — run audit from here")

    def action_delete_project(self) -> None:
        self.notify("Delete not yet implemented")
