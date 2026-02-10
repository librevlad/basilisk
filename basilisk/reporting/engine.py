"""Report engine — orchestrates report generation across formats."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from basilisk.core.pipeline import PipelineState


class ReportRenderer(Protocol):
    """Protocol for report renderers."""

    def render(self, state: PipelineState, output_path: Path) -> Path: ...


class ReportEngine:
    """Generates reports in multiple formats."""

    def __init__(self) -> None:
        self._renderers: dict[str, ReportRenderer] = {}

    def register(self, format_name: str, renderer: ReportRenderer) -> None:
        self._renderers[format_name] = renderer

    @property
    def formats(self) -> list[str]:
        return list(self._renderers.keys())

    def generate(
        self,
        state: PipelineState,
        output_dir: Path,
        formats: list[str] | None = None,
    ) -> list[Path]:
        """Generate reports in specified formats. Returns list of output paths."""
        output_dir.mkdir(parents=True, exist_ok=True)
        active_formats = formats or list(self._renderers.keys())
        paths: list[Path] = []

        for fmt in active_formats:
            renderer = self._renderers.get(fmt)
            if renderer:
                path = renderer.render(state, output_dir)
                paths.append(path)

        return paths
