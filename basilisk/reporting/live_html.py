"""Unified live report engine — writes HTML + JSON on each progress event.

Replaces the separate LiveHtmlRenderer + final ReportEngine pattern.
Both files are created at audit start and rewritten on every progress callback,
so the report is always up-to-date (auto-refreshing HTML while running,
final static report when complete).
"""

from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from basilisk.core.pipeline import PipelineState
from basilisk.reporting.data import build_report_data
from basilisk.reporting.extraction import extract_attack_surface
from basilisk.reporting.filtering import is_noise
from basilisk.reporting.rendering import (
    build_plugin_matrix,
    build_site_tree,
    filesize,
)

TEMPLATES_DIR = Path(__file__).parent / "templates"

# Backward-compat aliases (imported by tests)
_is_noise = is_noise
_extract_attack_surface = extract_attack_surface
_build_site_tree = build_site_tree
_build_plugin_matrix = build_plugin_matrix


class LiveReportEngine:
    """Writes both HTML and JSON reports on each pipeline progress event.

    Usage in CLI:
        engine = LiveReportEngine(scan_dir)
        audit_builder = audit_builder.on_progress(engine.update)
        state = await audit_builder.run()
        # Reports are already written — engine.html_path / engine.json_path
    """

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.html_path = output_dir / "report.html"
        self.json_path = output_dir / "report.json"
        self._env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=True,
        )
        self._env.filters["filesize"] = filesize
        self._start_time = time.monotonic()

    def update(self, state: PipelineState) -> None:
        """Called from on_progress callback — rewrite both HTML and JSON."""
        self._write_html(state)
        self._write_json(state)

    def _write_html(self, state: PipelineState) -> None:
        """Write the HTML report file."""
        template = self._env.get_template("report.html.j2")

        data = build_report_data(state)

        # Live-specific overrides
        is_running = state.status not in ("completed", "done", "error")
        data["is_running"] = is_running
        data["refresh_interval"] = 3 if is_running else None
        data["elapsed_total"] = round(time.monotonic() - self._start_time, 1)
        data["autonomous"] = state.autonomous

        html = template.render(**data)
        self.html_path.write_text(html, encoding="utf-8")

    def _write_json(self, state: PipelineState) -> None:
        """Write the JSON report file."""
        data = {
            "status": state.status,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
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
                    "data": r.data if r.data else {},
                    "error": r.error,
                }
                for r in state.results
            ],
        }

        if state.autonomous:
            data["autonomous"] = state.autonomous

        from basilisk.storage.repo import _SafeEncoder

        self.json_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False, cls=_SafeEncoder),
            encoding="utf-8",
        )


# Keep LiveHtmlRenderer as backward-compat alias
class LiveHtmlRenderer(LiveReportEngine):
    """Backward-compatible alias. Use LiveReportEngine instead."""

    def __init__(self, output_path: Path, refresh_interval: int = 3) -> None:
        output_dir = output_path.parent
        super().__init__(output_dir)
        self.html_path = output_path

    def update(self, state: PipelineState) -> None:
        self._write_html(state)
