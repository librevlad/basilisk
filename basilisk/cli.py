"""Typer CLI — clean interface for Basilisk."""

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
    help="Basilisk — autonomous security intelligence framework",
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
def auto(
    target: str = typer.Argument(help="Target domain/IP to audit"),
    max_steps: int = typer.Option(100, "--max-steps", "-n", help="Max autonomous steps"),
    config: str | None = typer.Option(None, help="Path to config YAML"),
    campaign: bool = typer.Option(
        False, "--campaign/--no-campaign", help="Enable persistent campaign memory",
    ),
    log_dir: str | None = typer.Option(None, "--log-dir", help="Override log directory"),
    verbose: bool = typer.Option(False, "-v", "--verbose"),
):
    """Autonomous audit — state-driven knowledge graph exploration."""
    _setup_logging(verbose)

    from basilisk import Basilisk
    from basilisk.config import Settings
    from basilisk.display import LiveDisplay, print_auto_report
    from basilisk.events.bus import EventBus

    settings = Settings.load(config) if config else Settings.load()
    if log_dir:
        settings.logging.log_dir = Path(log_dir)

    bus = EventBus()
    display = LiveDisplay(bus, max_steps=max_steps, verbose=verbose, console=console)

    b = Basilisk(target, max_steps=max_steps, config=settings, bus=bus)
    if campaign:
        b = b.campaign()

    from basilisk.reporting import ReportWriter

    writer = ReportWriter(bus, target=target, max_steps=max_steps, mode="auto")

    async def _run_with_display() -> tuple:
        display.start()
        report_dir = await writer.start()
        try:
            result = await b.run()
        finally:
            state = display.stop()
            state.termination_reason = ""  # will be set from result
        await writer.finalize(termination_reason=result.termination_reason)
        return result, report_dir

    result, report_dir = asyncio.run(_run_with_display())

    # Update display state with final result info
    display.state.termination_reason = result.termination_reason
    print_auto_report(display.state, console)
    console.print(f"\n[dim]Report:[/] {report_dir / 'report.html'}")



@app.command(name="run")
def run_plugin(
    plugin_name: str = typer.Argument(help="Plugin name to run"),
    target: str = typer.Argument(help="Target domain/IP"),
    verbose: bool = typer.Option(False, "-v", "--verbose"),
):
    """Run a single plugin against a target."""
    _setup_logging(verbose)

    from basilisk.core.executor import AsyncExecutor, PluginContext
    from basilisk.core.registry import PluginRegistry
    from basilisk.models.target import Target

    console.print(
        f"[bold blue]Basilisk[/] — Running [bold]{plugin_name}[/] on [bold]{target}[/]"
    )

    registry = PluginRegistry()
    registry.discover()
    plugin_cls = registry.get(plugin_name)
    if not plugin_cls:
        console.print(f"[red]Plugin not found: {plugin_name}[/]")
        raise typer.Exit(1)

    async def _run():
        from basilisk.config import Settings
        from basilisk.utils.dns import DnsClient
        from basilisk.utils.http import AsyncHttpClient
        from basilisk.utils.net import NetUtils
        from basilisk.utils.rate_limiter import RateLimiter

        settings = Settings.load()
        http = AsyncHttpClient(
            timeout=settings.http.timeout,
            max_connections=settings.http.max_connections,
            max_per_host=settings.http.max_connections_per_host,
            user_agent=settings.http.user_agent,
            verify_ssl=settings.http.verify_ssl,
        )
        dns = DnsClient(nameservers=settings.dns.nameservers, timeout=settings.dns.timeout)
        net = NetUtils(timeout=settings.scan.port_timeout)
        rate = RateLimiter(
            rate=settings.rate_limit.requests_per_second, burst=settings.rate_limit.burst,
        )

        ctx = PluginContext(
            config=settings, http=http, dns=dns, net=net, rate=rate,
        )
        t = Target.domain(target)
        executor = AsyncExecutor(max_concurrency=1)
        plugin = plugin_cls()
        try:
            await plugin.setup(ctx)
            result = await executor.run_one(plugin, t, ctx)
            await plugin.teardown()
        finally:
            await http.close()
        return result

    result = asyncio.run(_run())

    if result.ok:
        sev_colors = {
            "CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow",
            "LOW": "green", "INFO": "dim",
        }
        for finding in result.findings:
            color = sev_colors.get(finding.severity.label.upper(), "")
            console.print(f"  [{color}][{finding.severity.label}][/{color}] {finding.title}")
        if not result.findings:
            console.print("  [green]No findings[/]")
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


@app.command(name="train")
def train(
    profile: str = typer.Argument(help="Path to training profile YAML"),
    target: str | None = typer.Option(None, "--target", "-t", help="Override target"),
    max_steps: int | None = typer.Option(None, "--max-steps", "-n"),
    config: str | None = typer.Option(None, help="Config YAML path"),
    no_docker: bool = typer.Option(False, "--no-docker", help="Skip Docker container management"),
    verbose: bool = typer.Option(False, "-v", "--verbose"),
):
    """Training validation — benchmark engine against known vulnerabilities."""
    _setup_logging(verbose)

    from basilisk.display import TrainingDisplay, print_training_report
    from basilisk.events.bus import EventBus
    from basilisk.training.profile import TrainingProfile
    from basilisk.training.runner import TrainingRunner

    profile_path = Path(profile)
    if not profile_path.exists():
        console.print(f"[red]Profile not found: {profile_path}[/]")
        raise typer.Exit(1)

    tp = TrainingProfile.load(profile_path)
    if max_steps is not None:
        tp.max_steps = max_steps

    from basilisk.config import Settings

    settings = Settings.load(config) if config else Settings.load()
    bus = EventBus()
    runner = TrainingRunner(
        tp,
        target_override=target,
        manage_docker=not no_docker,
        project_root=profile_path.resolve().parent.parent
        if profile_path.resolve().parent.name == "training_profiles"
        else profile_path.resolve().parent,
    )

    from basilisk.training.validator import FindingTracker

    tracker = FindingTracker(tp)
    display = TrainingDisplay(
        bus, tracker, max_steps=tp.max_steps, verbose=verbose, console=console,
    )

    from basilisk.reporting import ReportWriter

    train_target = target or tp.target
    writer = ReportWriter(bus, target=train_target, max_steps=tp.max_steps, mode="train")

    async def _run_with_display() -> tuple:
        display.start()
        report_dir = await writer.start()
        try:
            result = await runner.run(config=settings, bus=bus, tracker=tracker)
        finally:
            display.stop()
        await writer.finalize_training(result, tracker)
        return result, report_dir

    report, report_dir = asyncio.run(_run_with_display())
    print_training_report(report, console)
    console.print(f"\n[dim]Report:[/] {report_dir / 'report.html'}")

    if not report.passed:
        raise typer.Exit(1)


@app.command(name="scenarios")
def list_scenarios(
    native_only: bool = typer.Option(False, "--native", help="Show only native v4 scenarios"),
):
    """List all scenarios (native v4 + legacy-wrapped plugins)."""
    from basilisk.bridge.legacy_scenario import LegacyPluginScenario
    from basilisk.engine.scenario_registry import ScenarioRegistry

    registry = ScenarioRegistry()
    registry.discover()

    table = Table(title="Basilisk Scenarios")
    table.add_column("Name", style="cyan")
    table.add_column("Type", width=8)
    table.add_column("Category", style="green")
    table.add_column("Description")

    for scenario in sorted(registry.all_scenarios(), key=lambda s: s.meta.name):
        is_native = not isinstance(scenario, LegacyPluginScenario)
        if native_only and not is_native:
            continue
        stype = "[bold green]native[/]" if is_native else "legacy"
        table.add_row(scenario.meta.name, stype, scenario.meta.category, scenario.meta.description)

    console.print(table)


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


def main() -> None:
    app()
