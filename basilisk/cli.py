"""Typer CLI — headless commands for Basilisk."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
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


def _setup_logging(verbose: bool = False, config_level: str | None = None) -> None:
    if verbose:
        level = logging.DEBUG
    elif config_level:
        level = getattr(logging, config_level.upper(), logging.INFO)
    else:
        level = logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


@app.command()
def audit(
    target: str = typer.Argument(help="Target domain to audit"),
    plugins: str | None = typer.Option(None, help="Comma-separated plugin names (whitelist)"),
    exclude: str | None = typer.Option(
        None, "--exclude", "-x",
        help="Exclude plugins by name or prefix, e.g.: dns_enum,subdomain_,whois,asn_",
    ),
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
    phases: str | None = typer.Option(
        None, "--phases", help="Comma-separated phases to run (default: all). "
        "E.g.: scanning,analysis,pentesting",
    ),
    no_cache: bool = typer.Option(False, "--no-cache", help="Ignore cached results"),
    cache_ttl: int = typer.Option(
        0, "--cache-ttl", help="Cache TTL in hours (0=default per phase)",
    ),
    force: str | None = typer.Option(
        None, "--force", help="Force re-run phases, e.g.: recon,pentesting",
    ),
):
    """Run a full audit against a target domain."""
    # Load config early to get log_level
    config_log_level = None
    if config:
        from basilisk.config import Settings
        try:
            cfg = Settings.load(config)
            config_log_level = cfg.log_level
        except Exception:
            pass
    _setup_logging(verbose, config_level=config_log_level)

    if interactive:
        _run_tui_audit(target, plugins, config, wordlist, project_name)
        return

    from basilisk.core.facade import Audit

    console.print(f"[bold blue]Basilisk v{__version__}[/] — Auditing [bold]{target}[/]")

    audit_builder = Audit(target)
    if config:
        audit_builder = audit_builder.with_config(config)
    if plugins:
        audit_builder = audit_builder.plugins(*plugins.split(","))
    if exclude:
        audit_builder = audit_builder.exclude(*exclude.split(","))
    if wordlist:
        audit_builder = audit_builder.wordlists(*wordlist.split(","))
    if no_cache:
        audit_builder = audit_builder.no_cache()
    if cache_ttl > 0:
        audit_builder = audit_builder.cache_ttl(cache_ttl)
    if force:
        audit_builder = audit_builder.force_phases(*force.split(","))
    project_obj = None
    if project_name:
        audit_builder, project_obj = _attach_project(audit_builder, project_name, target)

    phase_methods = {
        "recon": "discover", "scanning": "scan",
        "analysis": "analyze", "pentesting": "pentest",
        "exploitation": "exploit", "post_exploit": "post_exploit",
        "privesc": "privesc", "lateral": "lateral",
        "crypto": "crypto", "forensics": "forensics",
    }
    if phases:
        for p in phases.split(","):
            p = p.strip()
            if p not in phase_methods:
                console.print(f"[red]Unknown phase: {p}[/]")
                raise typer.Exit(1)
            audit_builder = getattr(audit_builder, phase_methods[p])()
    else:
        audit_builder = audit_builder.discover().scan().analyze().pentest()

    # Build scan output directory: target_YYYYMMDD_HHMMSS
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace(":", "_").replace("/", "_")
    base_reports = project_obj.reports_dir if project_obj else Path(output)
    scan_dir = base_reports / f"{safe_target}_{timestamp}"

    # Unified live report engine — writes both HTML and JSON from the start
    from basilisk.reporting.live_html import LiveReportEngine

    report_engine = LiveReportEngine(scan_dir)
    console.print(f"  Reports: {scan_dir} (updating live)")

    _last_plugin = {"name": ""}

    def on_progress(state):
        report_engine.update(state)
        if state.status == "running" and state.current_plugin:
            plugin = state.current_plugin
            if plugin != _last_plugin["name"]:
                _last_plugin["name"] = plugin
                phase = state.current_phase
                phase_info = state.phases.get(phase)
                progress = ""
                if phase_info and phase_info.total:
                    progress = f" [{phase_info.completed}/{phase_info.total}]"
                elapsed = ""
                if phase_info and phase_info.elapsed > 0:
                    elapsed = f" ({phase_info.elapsed:.0f}s)"
                console.print(
                    f"  [dim]{phase}{progress}{elapsed}[/] >> [cyan]{plugin}[/]"
                )
        elif state.status == "running":
            for name, phase in state.phases.items():
                if phase.status == "done" and name == state.current_phase:
                    console.print(
                        f"  [green]OK {name}[/] done ({phase.elapsed:.0f}s, "
                        f"{phase.completed} tasks)"
                    )

    audit_builder = audit_builder.on_progress(on_progress)

    state = asyncio.run(audit_builder.run())

    # CSV is optional — only generate if explicitly requested
    if "csv" in format.split(","):
        from basilisk.reporting.csv import CsvRenderer
        from basilisk.reporting.engine import ReportEngine

        csv_engine = ReportEngine()
        csv_engine.register("csv", CsvRenderer())
        csv_engine.generate(state, scan_dir, ["csv"])

    console.print(f"\n[bold green]Audit complete![/] {state.total_findings} findings")
    if state.skipped_plugins:
        console.print(f"  [dim]Skipped {len(state.skipped_plugins)} irrelevant plugins[/]")
    for name, phase in state.phases.items():
        if phase.total > 0:
            console.print(f"  [dim]{name}: {phase.completed} tasks in {phase.elapsed:.0f}s[/]")
    console.print(f"  Reports: {scan_dir}")
    console.print(f"  - {report_engine.html_path.name}")
    console.print(f"  - {report_engine.json_path.name}")


def _attach_project(audit_builder, name: str, target: str) -> tuple:
    """Load or create project and attach to audit builder.

    Returns (audit_builder, project) tuple.
    """
    from basilisk.config import Settings
    from basilisk.core.project_manager import ProjectManager

    pm = ProjectManager(Settings.load())
    try:
        proj = pm.load(name)
    except FileNotFoundError:
        proj = pm.create(name, targets=[target])
        console.print(f"[green]Created project '{name}'[/]")
    return audit_builder.for_project(proj), proj


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
def htb(
    target: str = typer.Argument(help="Target IP (e.g. 10.10.10.1)"),
    mode: str = typer.Option("full", help="Attack mode: full, web, ad, recon"),
    verbose: bool = typer.Option(False, "-v", "--verbose"),
    output: str = typer.Option("reports", help="Output directory"),
):
    """Full HTB attack chain — automated offensive pipeline."""
    _setup_logging(verbose)

    from basilisk.core.facade import Audit

    console.print(f"[bold red]Basilisk v{__version__}[/] — HTB Attack Mode: [bold]{mode}[/]")
    console.print(f"  Target: [bold]{target}[/]")

    audit_builder = Audit(target)

    if mode == "full":
        audit_builder = audit_builder.full_offensive()
    elif mode == "web":
        audit_builder = audit_builder.discover().scan().analyze().pentest()
    elif mode == "ad":
        audit_builder = audit_builder.discover().scan().exploit().lateral()
    elif mode == "recon":
        audit_builder = audit_builder.discover().scan().analyze()
    else:
        console.print(f"[red]Unknown mode: {mode}[/]")
        raise typer.Exit(1)

    from basilisk.reporting.live_html import LiveReportEngine

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace(":", "_").replace("/", "_")
    scan_dir = Path(output) / f"htb_{safe_target}_{timestamp}"

    report_engine = LiveReportEngine(scan_dir)
    audit_builder = audit_builder.on_progress(report_engine.update)

    state = asyncio.run(audit_builder.run())

    console.print(f"\n[bold green]Attack complete![/] {state.total_findings} findings")
    console.print(f"  - {report_engine.html_path.name}")
    console.print(f"  - {report_engine.json_path.name}")


@app.command()
def crack(
    hash_value: str = typer.Argument(help="Hash to identify and crack"),
    wordlist: str | None = typer.Option(None, "-w", "--wordlist", help="Custom wordlist"),
):
    """Identify and crack a hash."""
    try:
        from basilisk.utils.crypto_engine import CryptoEngine
    except ImportError:
        console.print("[red]CryptoEngine requires pycryptodome[/]")
        raise typer.Exit(1) from None

    crypto = CryptoEngine()
    hash_type = crypto.identify_hash(hash_value)
    console.print(f"Hash type: [bold]{hash_type}[/]")

    result = crypto.crack_hash(hash_value)
    if result and result.cracked:
        console.print(f"[bold green]Cracked![/] {result.password}")
    else:
        console.print("[yellow]Not cracked with built-in wordlist[/]")
        console.print("Try: hashcat -m <mode> hash.txt wordlist.txt")


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
