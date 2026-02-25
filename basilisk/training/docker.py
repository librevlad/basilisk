"""Docker Compose lifecycle manager for training targets."""

from __future__ import annotations

import asyncio
import logging
import shutil
from pathlib import Path

import aiohttp

logger = logging.getLogger(__name__)


class DockerComposeManager:
    """Manage Docker Compose services for training validation."""

    def __init__(self) -> None:
        self._compose_cmd = _find_compose_cmd()
        self._active: list[str] = []

    @property
    def available(self) -> bool:
        """Whether Docker Compose is available on this system."""
        return self._compose_cmd is not None

    async def up(self, compose_file: str, project_root: Path | None = None) -> None:
        """Start services defined in a compose file."""
        if not self._compose_cmd:
            logger.warning("Docker Compose not found, skipping container start")
            return

        path = self._resolve_path(compose_file, project_root)
        if not path.exists():
            logger.warning("Compose file not found: %s", path)
            return

        cmd = [*self._compose_cmd, "-f", str(path), "up", "-d"]
        logger.info("Starting containers: %s", " ".join(cmd))
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            logger.error("docker compose up failed: %s", stderr.decode(errors="replace"))
            return
        self._active.append(str(path))
        logger.info("Containers started from %s", compose_file)

    async def down(self, compose_file: str, project_root: Path | None = None) -> None:
        """Stop and remove services defined in a compose file."""
        if not self._compose_cmd:
            return

        path = self._resolve_path(compose_file, project_root)
        cmd = [*self._compose_cmd, "-f", str(path), "down"]
        logger.info("Stopping containers: %s", " ".join(cmd))
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        path_str = str(path)
        if path_str in self._active:
            self._active.remove(path_str)

    async def wait_ready(self, url: str, timeout: float = 120.0) -> bool:
        """Poll a URL until it returns 2xx/3xx or timeout expires."""
        if not url:
            return True

        deadline = asyncio.get_event_loop().time() + timeout
        logger.info("Waiting for %s (timeout=%.0fs)", url, timeout)
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
        ) as session:
            while asyncio.get_event_loop().time() < deadline:
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        if resp.status < 400:
                            logger.info("Target ready: %s (status=%d)", url, resp.status)
                            return True
                except (aiohttp.ClientError, TimeoutError, OSError):
                    pass
                await asyncio.sleep(2.0)

        logger.warning("Target not ready after %.0fs: %s", timeout, url)
        return False

    async def cleanup(self) -> None:
        """Stop all containers started during this session."""
        for path in list(self._active):
            await self.down(path)

    @staticmethod
    def _resolve_path(compose_file: str, project_root: Path | None = None) -> Path:
        p = Path(compose_file)
        if p.is_absolute():
            return p
        if project_root:
            return project_root / compose_file
        return Path.cwd() / compose_file


def _find_compose_cmd() -> list[str] | None:
    """Detect docker compose V2 or docker-compose V1."""
    if shutil.which("docker"):
        return ["docker", "compose"]
    if shutil.which("docker-compose"):
        return ["docker-compose"]
    return None
