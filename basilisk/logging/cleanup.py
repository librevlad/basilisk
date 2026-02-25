"""Log rotation — remove oldest run directories when over max_runs."""

from __future__ import annotations

import shutil
from pathlib import Path


def cleanup_old_runs(log_dir: Path, max_runs: int) -> None:
    """Delete oldest run directories if count exceeds *max_runs*.

    Run directories are named ``YYYYMMDD_HHMMSS_<target>`` so alphabetical
    sort equals chronological order.
    """
    if not log_dir.is_dir():
        return

    dirs = sorted(
        (d for d in log_dir.iterdir() if d.is_dir()),
        key=lambda d: d.name,
    )

    if len(dirs) <= max_runs:
        return

    to_remove = dirs[: len(dirs) - max_runs]
    for d in to_remove:
        shutil.rmtree(d, ignore_errors=True)
