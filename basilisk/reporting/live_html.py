"""Live HTML renderer — auto-refreshing report updated during audit."""

from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from basilisk.core.pipeline import PipelineState
from basilisk.models.result import Severity

TEMPLATES_DIR = Path(__file__).parent / "templates"


class LiveHtmlRenderer:
    """Writes an auto-refreshing HTML report on each pipeline progress event."""

    def __init__(self, output_path: Path, refresh_interval: int = 3) -> None:
        self.output_path = output_path
        self.refresh_interval = refresh_interval
        self._env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=True,
        )
        self._start_time = time.monotonic()

    def update(self, state: PipelineState) -> None:
        """Called from on_progress callback — rewrite the HTML file."""
        template = self._env.get_template("live_report.html.j2")

        severity_counts = {s.label: 0 for s in Severity}
        all_findings = []
        for result in state.results:
            for finding in result.findings:
                severity_counts[finding.severity.label] += 1
                all_findings.append({
                    "severity": finding.severity.label,
                    "severity_color": finding.severity.color,
                    "target": result.target,
                    "plugin": result.plugin,
                    "title": finding.title,
                    "description": finding.description,
                    "evidence": finding.evidence,
                    "remediation": finding.remediation,
                    "tags": finding.tags,
                })

        all_findings.sort(
            key=lambda x: Severity[x["severity"]].value, reverse=True
        )

        phases = []
        for name, phase in state.phases.items():
            phases.append({
                "name": name,
                "status": phase.status,
                "total": phase.total,
                "completed": phase.completed,
                "pct": round(phase.progress_pct, 1),
                "elapsed": round(phase.elapsed, 1),
            })

        elapsed_total = time.monotonic() - self._start_time
        is_running = state.status in ("running", "idle")

        html = template.render(
            title="Basilisk Live Audit Report",
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            status=state.status,
            total_findings=state.total_findings,
            severity_counts=severity_counts,
            phases=phases,
            findings=all_findings,
            refresh_interval=self.refresh_interval if is_running else 0,
            elapsed_total=round(elapsed_total, 1),
            is_running=is_running,
        )

        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.output_path.write_text(html, encoding="utf-8")
