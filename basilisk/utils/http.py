"""Async HTTP client — shared connection pool, retries, rate limiting."""

from __future__ import annotations

import logging
import ssl
from typing import Any

import aiohttp

logger = logging.getLogger(__name__)


class AsyncHttpClient:
    """Shared async HTTP client with connection pooling.

    Usage:
        async with AsyncHttpClient() as http:
            resp = await http.get("https://example.com")
    """

    def __init__(
        self,
        timeout: float = 10.0,
        max_connections: int = 100,
        max_per_host: int = 30,
        user_agent: str = "Basilisk/2.0",
        verify_ssl: bool = False,
        follow_redirects: bool = True,
        max_redirects: int = 5,
    ):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.user_agent = user_agent
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        self.max_redirects = max_redirects

        ssl_ctx = None
        if not verify_ssl:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        self._connector = aiohttp.TCPConnector(
            limit=max_connections,
            limit_per_host=max_per_host,
            ssl=ssl_ctx,
        )
        self._session: aiohttp.ClientSession | None = None

    async def _ensure_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                connector=self._connector,
                timeout=self.timeout,
                headers={"User-Agent": self.user_agent},
            )
        return self._session

    async def get(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> aiohttp.ClientResponse:
        session = await self._ensure_session()
        kw: dict[str, Any] = {
            "allow_redirects": self.follow_redirects,
            "max_redirects": self.max_redirects,
            **kwargs,
        }
        if headers:
            kw["headers"] = headers
        if timeout:
            kw["timeout"] = aiohttp.ClientTimeout(total=timeout)
        return await session.get(url, **kw)

    async def head(
        self,
        url: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> aiohttp.ClientResponse:
        session = await self._ensure_session()
        kw: dict[str, Any] = {
            "allow_redirects": self.follow_redirects,
            **kwargs,
        }
        if timeout:
            kw["timeout"] = aiohttp.ClientTimeout(total=timeout)
        return await session.head(url, **kw)

    async def post(
        self,
        url: str,
        data: Any = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> aiohttp.ClientResponse:
        session = await self._ensure_session()
        kw: dict[str, Any] = {
            "allow_redirects": self.follow_redirects,
            **kwargs,
        }
        if headers:
            kw["headers"] = headers
        if timeout:
            kw["timeout"] = aiohttp.ClientTimeout(total=timeout)
        if data is not None:
            kw["data"] = data
        return await session.post(url, **kw)

    async def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> aiohttp.ClientResponse:
        session = await self._ensure_session()
        kw: dict[str, Any] = {
            "allow_redirects": self.follow_redirects,
            **kwargs,
        }
        if headers:
            kw["headers"] = headers
        if timeout:
            kw["timeout"] = aiohttp.ClientTimeout(total=timeout)
        return await session.request(method, url, **kw)

    async def fetch_text(self, url: str, **kwargs: Any) -> str | None:
        """Convenience: GET and return response body as text, or None on error."""
        try:
            resp = await self.get(url, **kwargs)
            async with resp:
                if resp.status == 200:
                    return await resp.text()
        except Exception as e:
            logger.debug("fetch_text failed for %s: %s", url, e)
        return None

    async def check_url(
        self, url: str, timeout: float = 5.0
    ) -> dict[str, Any]:
        """Quick URL check — returns status, headers, title."""
        result: dict[str, Any] = {"url": url, "status": 0, "error": None}
        try:
            resp = await self.get(url, timeout=timeout)
            async with resp:
                result["status"] = resp.status
                result["headers"] = dict(resp.headers)
                if resp.status == 200 and resp.content_type == "text/html":
                    text = await resp.text()
                    # Simple title extraction
                    start = text.lower().find("<title>")
                    if start != -1:
                        end = text.lower().find("</title>", start)
                        if end != -1:
                            result["title"] = text[start + 7 : end].strip()
        except Exception as e:
            result["error"] = str(e)
        return result

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    async def __aenter__(self) -> AsyncHttpClient:
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()


# Ports that are typically HTTP/HTTPS services
_TLS_PORTS = {443, 8443, 9443, 4443}
_HTTP_PORTS = {80, 8080, 8000, 8888, 9090, 3000, 5000, 4200, 3001}
_ALL_WEB_PORTS = _TLS_PORTS | _HTTP_PORTS


async def resolve_base_url(host: str, ctx: Any) -> str | None:
    """Get base URL for target using pipeline cache, fallback to manual probe.

    Returns 'https://host' or 'http://host', or None if unreachable.
    For multi-port enumeration (8080, 8443, etc.) use resolve_base_urls().
    """
    scheme_map = ctx.state.get("http_scheme", {})
    if host in scheme_map:
        scheme = scheme_map[host]
        return f"{scheme}://{host}" if scheme else None

    # No cache — try manually (single-plugin mode)
    if ctx.http is None:
        return None
    for scheme in ("https", "http"):
        try:
            await ctx.http.head(f"{scheme}://{host}/", timeout=5.0)
            return f"{scheme}://{host}"
        except Exception:
            continue
    return None


async def resolve_base_urls(target: Any, ctx: Any) -> list[str]:
    """Resolve all reachable HTTP(S) base URLs for a target.

    Checks standard ports 443/80, then reads port_scan results
    from the pipeline context to discover HTTP services on
    non-standard ports (8080, 8443, 9090, etc.).

    Returns a list of verified base URLs like:
      ["https://example.com", "http://example.com:8080"]
    """
    if ctx.http is None:
        return []

    candidates: list[tuple[str, int]] = [
        ("https", 443),
        ("http", 80),
    ]

    # Read port_scan results for additional ports
    port_key = f"port_scan:{target.host}"
    port_result = ctx.pipeline.get(port_key) if ctx.pipeline else None
    if port_result and port_result.ok:
        open_ports = {p["port"] for p in port_result.data.get("open_ports", [])}
        for port in sorted(open_ports):
            if port in (80, 443):
                continue
            if port in _TLS_PORTS:
                candidates.append(("https", port))
            elif port in _HTTP_PORTS:
                candidates.append(("http", port))
            else:
                # Check if service_detect identified it as HTTP
                svc_key = f"service_detect:{target.host}"
                svc_result = ctx.pipeline.get(svc_key)
                if svc_result and svc_result.ok:
                    for svc in svc_result.data.get("services", []):
                        if svc.get("port") == port:
                            sname = (svc.get("service") or "").lower()
                            if "http" in sname:
                                scheme = "https" if "https" in sname else "http"
                                candidates.append((scheme, port))

    # Verify each candidate is reachable
    base_urls: list[str] = []
    seen: set[str] = set()

    for scheme, port in candidates:
        if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
            url = f"{scheme}://{target.host}"
        else:
            url = f"{scheme}://{target.host}:{port}"

        if url in seen:
            continue
        seen.add(url)

        try:
            async with ctx.rate:
                await ctx.http.head(f"{url}/", timeout=5.0)
                base_urls.append(url)
        except Exception:
            # For non-standard ports, try the other scheme
            if port not in (80, 443):
                alt = "http" if scheme == "https" else "https"
                alt_url = f"{alt}://{target.host}:{port}"
                if alt_url not in seen:
                    seen.add(alt_url)
                    try:
                        async with ctx.rate:
                            await ctx.http.head(f"{alt_url}/", timeout=5.0)
                            base_urls.append(alt_url)
                    except Exception:
                        pass

    return base_urls
