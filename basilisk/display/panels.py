"""Panel renderers — pure functions turning DisplayState into Rich Panels."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from rich.panel import Panel
from rich.progress_bar import ProgressBar
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from basilisk.display.state import DisplayState

SEV_STYLES = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
    "INFO": "dim",
}

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def header_panel(state: DisplayState) -> Panel:
    """Progress bar, step N/max, time, entities, findings, gaps."""
    elapsed = state.elapsed
    mins, secs = divmod(int(elapsed), 60)

    bar = ProgressBar(total=state.max_steps, completed=state.step, width=40)

    lines = Text()
    lines.append_text(Text.from_markup(
        f" Step [bold]{state.step}[/]/{state.max_steps}  {mins:02d}:{secs:02d}\n"
    ))

    info = Text.from_markup(
        f" Entities [bold]{state.total_entities}[/]  "
        f"Findings [bold]{state.total_findings}[/]  "
        f"Gaps [bold]{state.gap_count}[/]"
    )

    content = Table.grid(padding=0)
    content.add_row(bar)
    content.add_row(lines)
    content.add_row(info)

    return Panel(content, title="[bold blue]Basilisk v4.0.0[/]", border_style="blue")


def activity_panel(state: DisplayState) -> Panel:
    """Running plugins with elapsed time + last 3 completed."""
    table = Table.grid(padding=(0, 2))
    table.add_column("plugin", style="cyan", min_width=16)
    table.add_column("target", style="dim", min_width=14)
    table.add_column("status", min_width=20)

    now = time.monotonic()
    for p in state.active_plugins:
        elapsed = now - p.started_at
        table.add_row(p.name, p.target, f"[yellow]running[/] ({elapsed:.0f}s)")

    for p in state.recent_plugins[-3:]:
        suffix = ""
        if p.findings_count > 0:
            suffix = f" [bold]+{p.findings_count}F[/]"
        table.add_row(p.name, p.target, f"[green]done[/] ({p.duration:.1f}s{suffix})")

    if not state.active_plugins and not state.recent_plugins:
        table.add_row("[dim]waiting...[/]", "", "")

    return Panel(table, title="Activity", border_style="dim")


def findings_panel(state: DisplayState) -> Panel:
    """Last 5 findings by severity + severity summary line."""
    table = Table.grid(padding=(0, 2))
    table.add_column("severity", min_width=10)
    table.add_column("title", min_width=30)
    table.add_column("host", style="dim")

    for f in state.findings[-5:]:
        sev = f.severity.upper()
        style = SEV_STYLES.get(sev, "")
        table.add_row(f"[{style}]{sev}[/{style}]", f.title, f.host)

    if not state.findings:
        table.add_row("[dim]no findings yet[/]", "", "")

    # Summary line
    counts = state.severity_counts
    parts = []
    for sev in SEV_ORDER:
        c = counts.get(sev, 0)
        if c > 0:
            style = SEV_STYLES.get(sev, "")
            parts.append(f"[{style}]{c} {sev}[/{style}]")
    summary = "  ".join(parts) if parts else "[dim]none[/]"
    table.add_row("", summary, "")

    return Panel(table, title="Findings", border_style="dim")


def knowledge_panel(state: DisplayState) -> Panel:
    """Entity breakdown — verbose only."""
    table = Table.grid(padding=(0, 2))
    table.add_column("type", style="cyan")
    table.add_column("count", justify="right")

    ec = state.entity_counts
    for label, key in [
        ("Hosts", "host"),
        ("Services", "service"),
        ("Endpoints", "endpoint"),
        ("Technologies", "technology"),
        ("Containers", "container"),
        ("Images", "image"),
        ("Findings", "finding"),
        ("Vulnerabilities", "vulnerability"),
        ("Credentials", "credential"),
    ]:
        count = ec.get(key, 0)
        if count > 0:
            table.add_row(label, str(count))

    table.add_row("[bold]Total[/]", f"[bold]{state.total_entities}[/]")
    table.add_row("Relations", str(state.total_relations))

    return Panel(table, title="Knowledge Graph", border_style="dim")


def hypothesis_panel(state: DisplayState) -> Panel:
    """Active/confirmed/rejected counts — verbose only."""
    text = Text.from_markup(
        f" Active [bold]{state.hypotheses_active}[/]  "
        f"Confirmed [bold green]{state.hypotheses_confirmed}[/]  "
        f"Rejected [bold red]{state.hypotheses_rejected}[/]  "
        f"Beliefs +{state.beliefs_strengthened}/-{state.beliefs_weakened}"
    )
    return Panel(text, title="Reasoning", border_style="dim")
