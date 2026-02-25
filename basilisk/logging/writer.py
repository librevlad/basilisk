"""File writers for structured logging — JSONL and human-readable text."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import aiofiles


class JsonlWriter:
    """Append-mode JSONL writer with per-write flush for crash safety."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._file: Any = None

    async def open(self) -> None:
        self._file = await aiofiles.open(self._path, mode="a", encoding="utf-8")

    async def write(self, event_dict: dict[str, Any]) -> None:
        if self._file is None:
            return
        line = json.dumps(event_dict, default=str, ensure_ascii=False)
        await self._file.write(line + "\n")
        await self._file.flush()

    async def close(self) -> None:
        if self._file is not None:
            await self._file.flush()
            await self._file.close()
            self._file = None


class TextWriter:
    """Append-mode human-readable text writer with per-write flush."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._file: Any = None

    async def open(self) -> None:
        self._file = await aiofiles.open(self._path, mode="a", encoding="utf-8")

    async def write(self, line: str) -> None:
        if self._file is None:
            return
        await self._file.write(line + "\n")
        await self._file.flush()

    async def close(self) -> None:
        if self._file is not None:
            await self._file.flush()
            await self._file.close()
            self._file = None
