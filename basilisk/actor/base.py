"""Actor protocol — the v4 abstraction for all network interactions."""

from __future__ import annotations

import time
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, Field


class HttpResponse(BaseModel):
    """Normalized HTTP response."""

    status: int = 0
    headers: dict[str, str] = Field(default_factory=dict)
    body: bytes = b""
    text: str = ""
    url: str = ""
    elapsed: float = 0.0


@runtime_checkable
class ActorProtocol(Protocol):
    """Protocol for all network interactions.

    Scenarios depend on this interface, never on concrete implementations.
    """

    async def http_get(
        self, url: str, *, headers: dict[str, str] | None = None, timeout: float = 0,
    ) -> HttpResponse: ...

    async def http_post(
        self,
        url: str,
        *,
        data: dict | bytes | str | None = None,
        json: dict | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 0,
    ) -> HttpResponse: ...

    async def http_head(
        self, url: str, *, timeout: float = 0,
    ) -> HttpResponse: ...

    async def http_request(
        self, method: str, url: str, **kwargs,
    ) -> HttpResponse: ...

    async def dns_resolve(
        self, hostname: str, rdtype: str = "A",
    ) -> list[str]: ...

    async def tcp_connect(
        self, host: str, port: int, timeout: float = 3.0,
    ) -> bool: ...

    async def tcp_banner(
        self, host: str, port: int, timeout: float = 3.0,
    ) -> str: ...

    @property
    def should_stop(self) -> bool: ...

    @property
    def time_remaining(self) -> float: ...


class BaseActor:
    """Shared deadline logic for all actor implementations."""

    def __init__(self, deadline: float = 0.0):
        self._deadline = deadline

    @property
    def should_stop(self) -> bool:
        if self._deadline == 0.0:
            return False
        return time.monotonic() >= self._deadline - 2.0

    @property
    def time_remaining(self) -> float:
        if self._deadline == 0.0:
            return float("inf")
        return max(0.0, self._deadline - time.monotonic())
