"""Recording actor — records all requests/responses for testing and replay."""

from __future__ import annotations

from dataclasses import dataclass, field

from basilisk.actor.base import BaseActor, HttpResponse


@dataclass
class RecordedRequest:
    """A recorded HTTP request."""

    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    data: str = ""


class RecordingActor(BaseActor):
    """Actor that records all interactions for testing/replay.

    Can be pre-loaded with canned responses for deterministic testing.
    """

    def __init__(self, deadline: float = 0.0):
        super().__init__(deadline)
        self.requests: list[RecordedRequest] = []
        self._responses: dict[str, HttpResponse] = {}
        self._dns_responses: dict[str, list[str]] = {}
        self._tcp_responses: dict[tuple[str, int], bool] = {}
        self._banner_responses: dict[tuple[str, int], str] = {}

    def set_response(self, url: str, response: HttpResponse) -> None:
        """Pre-load a canned HTTP response."""
        self._responses[url] = response

    def set_dns(self, hostname: str, records: list[str]) -> None:
        """Pre-load DNS records."""
        self._dns_responses[hostname] = records

    def set_tcp(self, host: str, port: int, open_: bool) -> None:
        """Pre-load TCP connectivity result."""
        self._tcp_responses[(host, port)] = open_

    def set_banner(self, host: str, port: int, banner: str) -> None:
        """Pre-load TCP banner."""
        self._banner_responses[(host, port)] = banner

    def _record(self, method: str, url: str, headers: dict | None = None, data: str = "") -> None:
        self.requests.append(RecordedRequest(
            method=method, url=url, headers=headers or {}, data=data,
        ))

    def _get_response(self, url: str) -> HttpResponse:
        if url in self._responses:
            return self._responses[url]
        return HttpResponse(status=200, text="OK", url=url)

    async def http_get(
        self, url: str, *, headers: dict[str, str] | None = None, timeout: float = 0,
    ) -> HttpResponse:
        self._record("GET", url, headers)
        return self._get_response(url)

    async def http_post(
        self,
        url: str,
        *,
        data: dict | bytes | str | None = None,
        json: dict | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 0,
    ) -> HttpResponse:
        data_str = str(data or json or "")
        self._record("POST", url, headers, data_str)
        return self._get_response(url)

    async def http_head(
        self, url: str, *, timeout: float = 0,
    ) -> HttpResponse:
        self._record("HEAD", url)
        return self._get_response(url)

    async def http_request(
        self, method: str, url: str, **kwargs,
    ) -> HttpResponse:
        self._record(method, url)
        return self._get_response(url)

    async def dns_resolve(
        self, hostname: str, rdtype: str = "A",
    ) -> list[str]:
        return self._dns_responses.get(hostname, [])

    async def tcp_connect(
        self, host: str, port: int, timeout: float = 3.0,
    ) -> bool:
        return self._tcp_responses.get((host, port), False)

    async def tcp_banner(
        self, host: str, port: int, timeout: float = 3.0,
    ) -> str:
        return self._banner_responses.get((host, port), "")
