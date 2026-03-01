"""Final static reports printed after live display stops."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from basilisk.display.state import DisplayState
    from basilisk.training.validator import ValidationReport

SEV_STYLES = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
    "INFO": "dim",
}

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def print_auto_report(
    state: DisplayState,
    console: Console | None = None,
) -> None:
    """Print final summary after an autonomous audit."""
    console = console or Console()

    elapsed = state.elapsed
    mins, secs = divmod(int(elapsed), 60)

    # Summary panel
    summary = Text()
    summary.append_text(Text.from_markup(
        f"[bold green]Audit complete![/]  "
        f"Steps: [bold]{state.step}[/]  "
        f"Duration: [bold]{mins:02d}:{secs:02d}[/]  "
        f"Entities: [bold]{state.total_entities}[/]  "
        f"Relations: [bold]{state.total_relations}[/]\n"
    ))
    if state.termination_reason:
        summary.append_text(Text.from_markup(
            f"Reason: [dim]{state.termination_reason}[/]"
        ))
    console.print(Panel(summary, border_style="green"))

    # Severity table
    counts = state.severity_counts
    if counts:
        sev_table = Table(title="Severity Summary")
        sev_table.add_column("Severity")
        sev_table.add_column("Count", justify="right")
        for sev in SEV_ORDER:
            c = counts.get(sev, 0)
            if c > 0:
                style = SEV_STYLES.get(sev, "")
                sev_table.add_row(f"[{style}]{sev}[/{style}]", str(c))
        console.print(sev_table)

    # Top findings (max 20)
    if state.findings:
        table = Table(title="Top Findings")
        table.add_column("Severity", width=10)
        table.add_column("Title")
        table.add_column("Target", style="dim")

        for f in state.findings[:20]:
            sev = f.severity.upper()
            style = SEV_STYLES.get(sev, "")
            table.add_row(f"[{style}]{sev}[/{style}]", f.title, f.host)

        console.print(table)
        if len(state.findings) > 20:
            console.print(f"  [dim]... and {len(state.findings) - 20} more[/]")
    else:
        console.print("[dim]No findings.[/]")


def print_training_report(
    report: ValidationReport,
    console: Console | None = None,
) -> None:
    """Print final training validation report."""
    console = console or Console()

    table = Table(title=f"Training Validation: {report.profile_name}")
    table.add_column("Finding", style="cyan")
    table.add_column("Severity")
    table.add_column("Category", style="dim")
    table.add_column("Discovered")
    table.add_column("Verified")
    table.add_column("Step")

    sev_colors = {
        "critical": "bold red", "high": "red", "medium": "yellow", "low": "green",
    }
    for fd in report.findings_detail:
        sev = fd["expected_severity"]
        sev_style = sev_colors.get(sev, "")
        disc = "[green]YES[/]" if fd["discovered"] else "[red]NO[/]"
        verif = "[green]YES[/]" if fd["verified"] else "[yellow]NO[/]"
        step = str(fd.get("discovery_step", "-") or "-")
        table.add_row(
            fd["expected_title"],
            f"[{sev_style}]{sev}[/{sev_style}]",
            fd.get("category", ""),
            disc,
            verif,
            step,
        )

    console.print(table)
    console.print(
        f"\n  Coverage: [bold]{report.coverage * 100:.1f}%[/] "
        f"({report.discovered}/{report.total_expected})"
    )
    console.print(f"  Verification: {report.verification_rate * 100:.1f}%")
    console.print(f"  Steps: {report.steps_taken}")

    if report.passed:
        console.print("[bold green]PASSED[/]")
    else:
        console.print("[bold red]FAILED[/] — coverage below required threshold")
