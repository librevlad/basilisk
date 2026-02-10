"""HTML report renderer using Jinja2."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from basilisk.core.pipeline import PipelineState
from basilisk.models.result import Severity

TEMPLATES_DIR = Path(__file__).parent / "templates"


class HtmlRenderer:
    """Renders audit results as a styled HTML report."""

    def render(self, state: PipelineState, output_dir: Path) -> Path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = output_dir / f"report_{timestamp}.html"

        env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=True,
        )
        template = env.get_template("report.html.j2")

        # Prepare data
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

        html = template.render(
            title="Basilisk Security Audit Report",
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            status=state.status,
            total_findings=state.total_findings,
            severity_counts=severity_counts,
            phases=state.phases,
            findings=all_findings,
        )

        output_path.write_text(html, encoding="utf-8")
        return output_path
