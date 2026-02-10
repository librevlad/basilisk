"""CSV report renderer."""

from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path

from basilisk.core.pipeline import PipelineState


class CsvRenderer:
    """Renders findings as CSV (UTF-8 with BOM for Excel)."""

    def render(self, state: PipelineState, output_dir: Path) -> Path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = output_dir / f"findings_{timestamp}.csv"

        with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow([
                "severity", "target", "plugin", "title",
                "description", "evidence", "remediation", "tags",
            ])

            # Sort by severity (highest first)
            all_findings = []
            for result in state.results:
                for finding in result.findings:
                    all_findings.append((result, finding))

            all_findings.sort(key=lambda x: x[1].severity, reverse=True)

            for result, finding in all_findings:
                writer.writerow([
                    finding.severity.label,
                    result.target,
                    result.plugin,
                    finding.title,
                    finding.description,
                    finding.evidence,
                    finding.remediation,
                    ";".join(finding.tags),
                ])

        return output_path
