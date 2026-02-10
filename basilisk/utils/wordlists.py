"""Wordlist manager — bundle, download, merge, async streaming."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from pathlib import Path

import aiofiles

logger = logging.getLogger(__name__)

BUNDLED_DIR = Path(__file__).parent.parent.parent / "wordlists" / "bundled"
DOWNLOADED_DIR = Path(__file__).parent.parent.parent / "wordlists" / "downloaded"
CUSTOM_DIR = Path(__file__).parent.parent.parent / "wordlists" / "custom"


class WordlistInfo:
    """Info about an available wordlist."""

    def __init__(self, name: str, path: Path, source: str, line_count: int = 0):
        self.name = name
        self.path = path
        self.source = source  # "bundled", "downloaded", "custom"
        self.line_count = line_count

    def __repr__(self) -> str:
        return f"<Wordlist {self.name} ({self.source}, {self.line_count} lines)>"


class WordlistManager:
    """Manages wordlists: bundled + downloaded + custom, with async streaming.

    Like Laravel Filesystem — single API, multiple sources.
    """

    def __init__(
        self,
        bundled_dir: Path | None = None,
        downloaded_dir: Path | None = None,
        custom_dir: Path | None = None,
    ):
        self.bundled_dir = bundled_dir or BUNDLED_DIR
        self.downloaded_dir = downloaded_dir or DOWNLOADED_DIR
        self.custom_dir = custom_dir or CUSTOM_DIR

    def _find_file(self, name: str) -> Path | None:
        """Find a wordlist file by name across all sources."""
        # Try exact name first
        for directory in [self.bundled_dir, self.downloaded_dir, self.custom_dir]:
            path = directory / name
            if path.exists():
                return path
            # Try with .txt extension
            path_txt = directory / f"{name}.txt"
            if path_txt.exists():
                return path_txt
        return None

    async def get(self, name: str) -> AsyncIterator[str]:
        """Get a wordlist by name — yields lines one at a time (memory-efficient)."""
        path = self._find_file(name)
        if path is None:
            msg = f"Wordlist '{name}' not found"
            raise FileNotFoundError(msg)

        async with aiofiles.open(path, encoding="utf-8", errors="ignore") as f:
            async for line in f:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    yield stripped

    async def get_all(self, name: str) -> list[str]:
        """Load entire wordlist into memory."""
        return [line async for line in self.get(name)]

    async def merge(self, *names: str, dedupe: bool = True) -> AsyncIterator[str]:
        """Merge multiple wordlists with optional deduplication."""
        seen: set[str] = set()
        for name in names:
            try:
                async for entry in self.get(name):
                    if dedupe:
                        if entry not in seen:
                            seen.add(entry)
                            yield entry
                    else:
                        yield entry
            except FileNotFoundError:
                logger.warning("Wordlist '%s' not found, skipping", name)

    def list_available(self) -> list[WordlistInfo]:
        """List all available wordlists across all sources."""
        results: list[WordlistInfo] = []

        for source, directory in [
            ("bundled", self.bundled_dir),
            ("downloaded", self.downloaded_dir),
            ("custom", self.custom_dir),
        ]:
            if not directory.exists():
                continue
            for path in sorted(directory.glob("*.txt")):
                line_count = sum(1 for _ in open(path, errors="ignore"))  # noqa: SIM115
                results.append(WordlistInfo(
                    name=path.stem,
                    path=path,
                    source=source,
                    line_count=line_count,
                ))
        return results

    async def download_seclists(self, category: str = "Discovery/Web-Content") -> Path:
        """Download a SecLists category. Returns path to downloaded file."""
        # Placeholder — actual download implementation in Phase 10
        raise NotImplementedError("SecLists download not yet implemented")

    def add_custom(self, source_path: Path, name: str | None = None) -> Path:
        """Copy a wordlist file to the custom directory."""
        self.custom_dir.mkdir(parents=True, exist_ok=True)
        dest_name = name or source_path.stem
        dest = self.custom_dir / f"{dest_name}.txt"

        import shutil
        shutil.copy2(source_path, dest)
        return dest
