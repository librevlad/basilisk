"""Network utilities — TCP connect, port scanning, banner grabbing."""

from __future__ import annotations

import asyncio
import logging
import socket

from basilisk.models.types import PortInfo, PortState

logger = logging.getLogger(__name__)


class NetUtils:
    """Low-level network utilities for port scanning and service detection."""

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    async def check_port(
        self, host: str, port: int, timeout: float | None = None
    ) -> PortInfo:
        """Check if a TCP port is open."""
        t = timeout or self.timeout
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=t,
            )
            writer.close()
            await writer.wait_closed()
            return PortInfo(port=port, state=PortState.OPEN)
        except TimeoutError:
            return PortInfo(port=port, state=PortState.FILTERED)
        except (ConnectionRefusedError, OSError):
            return PortInfo(port=port, state=PortState.CLOSED)

    async def scan_ports(
        self, host: str, ports: list[int], timeout: float | None = None
    ) -> list[PortInfo]:
        """Scan multiple ports concurrently."""
        tasks = [self.check_port(host, p, timeout) for p in ports]
        return list(await asyncio.gather(*tasks))

    async def grab_banner(
        self, host: str, port: int, timeout: float | None = None
    ) -> str:
        """Attempt to grab a service banner from an open port."""
        t = timeout or self.timeout
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=t,
            )
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=t)
                return data.decode("utf-8", errors="replace").strip()
            finally:
                writer.close()
                await writer.wait_closed()
        except Exception as e:
            logger.debug("Banner grab %s:%d failed: %s", host, port, e)
            return ""

    @staticmethod
    def resolve_sync(host: str) -> list[str]:
        """Synchronous DNS resolution (fallback)."""
        try:
            results = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            return list({r[4][0] for r in results})
        except socket.gaierror:
            return []
