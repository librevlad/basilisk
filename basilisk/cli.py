"""Typer CLI — headless commands for Basilisk."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from basilisk import __version__

app = typer.Typer(
    name="basilisk",
    help="Basilisk — Professional security audit framework",
    no_args_is_help=True,
)
console = Console()


def _setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


@app.command()
def audit(
    target: str = typer.Argument(help="Target domain to audit"),
    plugins: str | None = typer.Option(None, help="Comma-separated plugin names"),
    format: str = typer.Option("json", help="Output formats: json,csv,html"),  # noqa: A002
    config: str | None = typer.Option(None, help="Path to config YAML"),
    output: str = typer.Option("reports", help="Output directory"),
    verbose: bool = typer.Option(False, "-v", "--verbose"),
    interactive: bool = typer.Option(False, "--tui", help="Launch TUI dashboard"),
    wordlist: str | None = typer.Option(
        None, "--wordlist", "-w", help="Wordlist names, comma-separated",
    ),
    project_name: str | None = typer.Option(
        None, "--project", "-p", help="Save to project (auto-create, resume)",
    ),
):
    """Run a full audit against a target domain."""
    _setup_logging(verbose)

    if interactive:
        _run_tui_audit(target, plugins, config, wordlist, project_name)
        return

    from basilisk.core.facade import Audit
    from basilisk.reporting.csv import CsvRenderer
    from basilisk.reporting.engine import ReportEngine
    from basilisk.reporting.html import HtmlRenderer
    from basilisk.reporting.json import JsonRenderer

    console.print(f"[bold blue]Basilisk v{__version__}[/] — Auditing [bold]{target}[/]")

    audit_builder = Audit(target)
    if config:
        audit_builder = audit_builder.with_config(config)
    if plugins:
        audit_builder = audit_builder.plugins(*plugins.split(","))
    if wordlist:
        audit_builder = audit_builder.wordlists(*wordlist.split(","))
    if project_name:
        audit_builder = _attach_project(audit_builder, project_name, target)

    audit_builder = audit_builder.discover().scan().analyze().pentest()

    # Setup live HTML report
    from basilisk.reporting.live_html import LiveHtmlRenderer

    output_dir = Path(output)
    live_report_path = output_dir / "live_report.html"
    live_renderer = LiveHtmlRenderer(live_report_path)

    def on_progress(state):
        live_renderer.update(state)
        if state.status == "running":
            for name, phase in state.phases.items():
                if phase.status == "running":
                    console.print(
                        f"  [dim]{name}:[/] {phase.completed}/{phase.total}",
                        end="\r",
                    )

    audit_builder = audit_builder.on_progress(on_progress)

    state = asyncio.run(audit_builder.run())

    # Generate reports
    formats = format.split(",")
    engine = ReportEngine()
    engine.register("json", JsonRenderer())
    engine.register("csv", CsvRenderer())
    engine.register("html", HtmlRenderer())

    paths = engine.generate(state, output_dir, formats)

    console.print(f"\n[bold green]Audit complete![/] {state.total_findings} findings")
    console.print(f"  Live report: {live_report_path}")
    for p in paths:
        console.print(f"  Report: {p}")


def _attach_project(audit_builder, name: str, target: str):
    """Load or create project and attach to audit builder."""
    from basilisk.config import Settings
    from basilisk.core.project_manager import ProjectManager

    pm = ProjectManager(Settings.load())
    try:
        proj = pm.load(name)
    except FileNotFoundError:
        proj = pm.create(name, targets=[target])
        console.print(f"[green]Created project '{name}'[/]")
    return audit_builder.for_project(proj)


def _run_tui_audit(
    target: str,
    plugins: str | None,
    config: str | None,
    wordlist: str | None,
    project_name: str | None = None,
) -> None:
    """Launch TUI app and start audit immediately."""
    try:
        from basilisk.tui.app import BasiliskApp

        app_instance = BasiliskApp(
            audit_target=target,
            audit_plugins=plugins.split(",") if plugins else None,
            audit_config=config,
            audit_wordlists=wordlist.split(",") if wordlist else None,
            audit_project=project_name,
        )
        app_instance.run()
    except ImportError:
        console.print("[red]TUI not available. Install textual: pip install textual[/]")


@app.command(name="run")
def run_plugin(
    plugin_name: str = typer.Argument(help="Plugin name to run"),
    target: str = typer.Argument(help="Target domain/IP"),
    wordlist: str | None = typer.Option(None, help="Wordlist name for brute plugins"),
    verbose: bool = typer.Option(False, "-v", "--verbose"),
):
    """Run a single plugin against a target."""
    _setup_logging(verbose)

    from basilisk.core.facade import Audit

    console.print(
        f"[bold blue]Basilisk[/] — Running [bold]{plugin_name}[/] on [bold]{target}[/]"
    )

    results = asyncio.run(Audit.run_plugin(plugin_name, [target]))

    for result in results:
        if result.ok:
            for finding in result.findings:
                color = finding.severity.color
                console.print(f"  [{color}][{finding.severity.label}][/{color}] {finding.title}")
        else:
            console.print(f"  [red]Error:[/] {result.error}")


@app.command(name="plugins")
def list_plugins(
    category: str | None = typer.Option(None, help="Filter by category"),
    provides: str | None = typer.Option(None, help="Filter by provides type"),
):
    """List available plugins."""
    from basilisk.core.plugin import PluginCategory
    from basilisk.core.registry import PluginRegistry

    registry = PluginRegistry()
    registry.discover()

    if provides:
        plugins_list = registry.by_provides(provides)
    elif category:
        plugins_list = registry.by_category(PluginCategory(category))
    else:
        plugins_list = registry.all()

    table = Table(title="Basilisk Plugins")
    table.add_column("Name", style="cyan")
    table.add_column("Category", style="green")
    table.add_column("Description")
    table.add_column("Provides", style="yellow")
    table.add_column("Depends On", style="dim")

    for p in sorted(plugins_list, key=lambda x: (x.meta.category, x.meta.name)):
        table.add_row(
            p.meta.name,
            p.meta.category.value,
            p.meta.description or p.meta.display_name,
            p.meta.provides or "",
            ", ".join(p.meta.depends_on) or "",
        )

    console.print(table)


@app.command()
def project(
    action: str = typer.Argument(help="Action: create, list, run, report"),
    name: str | None = typer.Argument(None, help="Project name"),
    targets: str | None = typer.Option(None, help="Comma-separated targets"),
    format: str = typer.Option("json", help="Report formats"),  # noqa: A002
    verbose: bool = typer.Option(False, "-v", "--verbose"),
):
    """Manage audit projects."""
    _setup_logging(verbose)

    from basilisk.config import Settings
    from basilisk.core.project_manager import ProjectManager

    settings = Settings.load()
    pm = ProjectManager(settings)

    if action == "create":
        if not name:
            console.print("[red]Project name required[/]")
            raise typer.Exit(1)
        target_list = targets.split(",") if targets else []
        project = pm.create(name, targets=target_list)
        console.print(f"[green]Created project '{project.name}' at {project.path}[/]")

    elif action == "list":
        projects = pm.list_all()
        if not projects:
            console.print("No projects found")
            return
        table = Table(title="Projects")
        table.add_column("Name", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Targets")
        table.add_column("Created")
        for p in projects:
            table.add_row(
                p.name, p.status.value,
                str(len(p.targets)), p.created_at.strftime("%Y-%m-%d"),
            )
        console.print(table)

    elif action == "run":
        if not name:
            console.print("[red]Project name required[/]")
            raise typer.Exit(1)
        project = pm.load(name)
        console.print(f"[blue]Running project '{name}' with {len(project.targets)} targets[/]")
        # TODO: Run pipeline with project config

    elif action == "report":
        if not name:
            console.print("[red]Project name required[/]")
            raise typer.Exit(1)
        console.print(f"[blue]Generating report for '{name}'[/]")
        # TODO: Generate report from project DB

    else:
        console.print(f"[red]Unknown action: {action}[/]")


@app.command()
def version():
    """Show version."""
    console.print(f"Basilisk v{__version__}")


@app.command()
def tui():
    """Launch interactive TUI dashboard."""
    try:
        from basilisk.tui.app import BasiliskApp
        app_instance = BasiliskApp()
        app_instance.run()
    except ImportError:
        console.print("[red]TUI not available. Install textual: pip install textual[/]")


def main() -> None:
    app()
