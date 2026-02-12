"""Example: run a full audit on target domains with all pipeline phases.

Usage:
    python examples/full_audit.py
"""

import asyncio
import logging
from collections import Counter
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)

from basilisk.config import Settings
from basilisk.core.facade import Audit
from basilisk.core.project_manager import ProjectManager
from basilisk.reporting.csv import CsvRenderer
from basilisk.reporting.engine import ReportEngine
from basilisk.reporting.html import HtmlRenderer
from basilisk.reporting.json import JsonRenderer


async def main():
    targets = ["example.com"]
    project_name = "example-audit"

    # Setup project
    settings = Settings.load()
    pm = ProjectManager(settings)
    try:
        proj = pm.load(project_name)
        print(f"Loaded project '{project_name}'")
    except FileNotFoundError:
        proj = pm.create(project_name, targets=targets)
        print(f"Created project '{project_name}'")

    def on_progress(state):
        if state.status == "running":
            for name, phase in state.phases.items():
                if phase.status == "running":
                    print(
                        f"  {name}: {phase.completed}/{phase.total} "
                        f"({phase.progress_pct:.0f}%)",
                        flush=True,
                    )

    finding_count = 0

    def on_finding(finding, target=""):
        nonlocal finding_count
        finding_count += 1
        sev = finding.severity.label
        print(f"  [{sev}] {target}: {finding.title}", flush=True)

    print(f"\nAuditing: {', '.join(targets)}")
    print("=" * 60)

    audit = (
        Audit(*targets)
        .for_project(proj)
        .discover()
        .scan()
        .analyze()
        .pentest()
        .live_report(Path("reports/live_report.html"))
        .on_progress(on_progress)
        .on_finding(on_finding)
    )

    state = await audit.run()

    print("\n" + "=" * 60)
    print(f"AUDIT COMPLETE: {state.total_findings} findings")
    print(f"Status: {state.status}")

    # Phase summary
    for name, phase in state.phases.items():
        print(f"  {name}: {phase.completed}/{phase.total} — {phase.status} ({phase.elapsed:.1f}s)")

    # Generate reports
    output_dir = Path("reports")
    engine = ReportEngine()
    engine.register("json", JsonRenderer())
    engine.register("csv", CsvRenderer())
    engine.register("html", HtmlRenderer())
    paths = engine.generate(state, output_dir, ["json", "csv", "html"])
    print("\nReports:")
    for p in paths:
        print(f"  {p}")

    # Severity breakdown
    sev_counts = Counter()
    for result in state.results:
        for f in result.findings:
            sev_counts[f.severity.label] += 1
    print("\nSeverity breakdown:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev_counts[sev]:
            print(f"  {sev}: {sev_counts[sev]}")

    return state


if __name__ == "__main__":
    asyncio.run(main())
