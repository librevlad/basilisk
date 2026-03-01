"""ReportWriter — async periodic file writer for live HTML+JSON reports."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from basilisk.reporting.collector import ReportCollector
from basilisk.reporting.renderer import assemble_data, render_html, render_json

if TYPE_CHECKING:
    from basilisk.events.bus import EventBus
    from basilisk.training.validator import FindingTracker, ValidationReport

logger = logging.getLogger(__name__)


def _safe_dirname(target: str) -> str:
    """Sanitize target string for use as directory name."""
    return re.sub(r"[^\w.\-]", "_", target)[:80]


class ReportWriter:
    """Manages periodic HTML+JSON report generation during an audit.

    Creates a directory under ``reports/`` and writes ``report.html`` +
    ``report.json`` every *interval* seconds via a background asyncio task.
    Final write removes auto-refresh meta tag.
    """

    def __init__(
        self,
        bus: EventBus,
        *,
        target: str,
        max_steps: int = 100,
        mode: str = "auto",
        report_dir: Path | None = None,
        interval: float = 3.0,
    ) -> None:
        self._collector = ReportCollector(target=target, mode=mode, max_steps=max_steps)
        self._collector.subscribe(bus)
        self._interval = interval
        self._task: asyncio.Task[None] | None = None

        if report_dir is not None:
            self._report_dir = report_dir
        else:
            ts = datetime.now(tz=UTC).strftime("%Y%m%d_%H%M%S")
            dirname = f"{_safe_dirname(target)}_{ts}"
            self._report_dir = Path("reports") / dirname

    @property
    def collector(self) -> ReportCollector:
        """Access the underlying collector (for testing)."""
        return self._collector

    @property
    def report_dir(self) -> Path:
        """Report output directory."""
        return self._report_dir

    async def start(self) -> Path:
        """Create report directory, do initial write, and start background loop.

        Returns the report directory path.
        """
        self._report_dir.mkdir(parents=True, exist_ok=True)
        await self._write(auto_refresh=True)
        self._task = asyncio.create_task(self._loop())
        return self._report_dir

    async def finalize(self, *, termination_reason: str = "") -> Path:
        """Stop background loop and write final report without auto-refresh.

        Returns the report directory path.
        """
        await self._cancel_task()
        self._collector.finalize(termination_reason)
        await self._write(auto_refresh=False)
        return self._report_dir

    async def finalize_training(
        self, report: ValidationReport, tracker: FindingTracker,
    ) -> Path:
        """Stop background loop and write final training report.

        Returns the report directory path.
        """
        await self._cancel_task()
        self._collector.finalize_training(report, tracker)
        await self._write(auto_refresh=False)
        return self._report_dir

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _loop(self) -> None:
        """Background write loop — runs until cancelled."""
        try:
            while True:
                await asyncio.sleep(self._interval)
                await self._write(auto_refresh=True)
        except asyncio.CancelledError:
            pass

    async def _cancel_task(self) -> None:
        """Cancel the background loop task if running."""
        if self._task is not None and not self._task.done():
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

    async def _write(self, *, auto_refresh: bool = True) -> None:
        """Write report.html and report.json atomically."""
        try:
            data = assemble_data(self._collector)
            html_content = render_html(data, auto_refresh=auto_refresh)
            json_content = render_json(data)

            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, self._write_file, "report.html", html_content)
            await loop.run_in_executor(None, self._write_file, "report.json", json_content)
        except Exception:
            logger.debug("Report write failed", exc_info=True)

    def _write_file(self, filename: str, content: str) -> None:
        """Atomic write: tmp file then os.replace."""
        target = self._report_dir / filename
        tmp = self._report_dir / f".{filename}.tmp"
        tmp.write_text(content, encoding="utf-8")
        os.replace(tmp, target)
