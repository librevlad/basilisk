"""JSON report renderer."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from basilisk.core.pipeline import PipelineState


class JsonRenderer:
    """Renders audit results as JSON."""

    def render(self, state: PipelineState, output_dir: Path) -> Path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = output_dir / f"report_{timestamp}.json"

        data = {
            "status": state.status,
            "total_findings": state.total_findings,
            "phases": {
                name: {
                    "status": phase.status,
                    "total": phase.total,
                    "completed": phase.completed,
                    "elapsed": round(phase.elapsed, 2),
                }
                for name, phase in state.phases.items()
            },
            "results": [
                {
                    "plugin": r.plugin,
                    "target": r.target,
                    "status": r.status,
                    "duration": round(r.duration, 3),
                    "findings": [
                        {
                            "severity": f.severity.label,
                            "title": f.title,
                            "description": f.description,
                            "evidence": f.evidence,
                            "remediation": f.remediation,
                            "tags": f.tags,
                        }
                        for f in r.findings
                    ],
                    "error": r.error,
                }
                for r in state.results
            ],
        }

        from basilisk.storage.repo import _SafeEncoder

        output_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False, cls=_SafeEncoder),
            encoding="utf-8",
        )
        return output_path
