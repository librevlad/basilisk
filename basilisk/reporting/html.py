"""HTML report renderer using Jinja2."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from basilisk.core.pipeline import PipelineState
from basilisk.reporting.data import build_report_data

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

        data = build_report_data(state)
        html = template.render(**data)

        output_path.write_text(html, encoding="utf-8")
        return output_path
