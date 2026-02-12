"""Headless browser manager — Playwright integration for JS rendering.

Playwright is an **optional** dependency. All methods gracefully return
empty/None results when playwright is not installed. Plugins should check
``ctx.browser is not None`` before using browser features.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


@dataclass
class RenderedPage:
    """Result of rendering a page with headless browser."""

    url: str
    final_url: str = ""
    status: int = 0
    html: str = ""
    title: str = ""
    text: str = ""
    scripts: list[str] = field(default_factory=list)
    api_calls: list[str] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    console_messages: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    cookies: list[dict[str, str]] = field(default_factory=list)
    screenshot: bytes = b""


@dataclass
class XSSConfirmation:
    """Result of an XSS confirmation attempt."""

    url: str
    payload: str
    executed: bool = False
    alert_text: str = ""
    context: str = ""
    screenshot: bytes = b""


class BrowserManager:
    """Manages a headless Chromium instance via Playwright.

    All operations are async and safe to call concurrently (uses semaphore).
    Gracefully degrades if Playwright is not installed.

    Usage::

        async with BrowserManager() as browser:
            page = await browser.render("https://example.com")
            print(page.html, page.api_calls)
    """

    def __init__(
        self,
        *,
        max_pages: int = 5,
        timeout: float = 15.0,
        user_agent: str = "Basilisk/2.0",
    ) -> None:
        self.max_pages = max_pages
        self.timeout = int(timeout * 1000)  # Playwright uses ms
        self.user_agent = user_agent
        self._playwright: Any = None
        self._browser: Any = None
        self._context: Any = None
        self._semaphore = asyncio.Semaphore(max_pages)

    @property
    def available(self) -> bool:
        """True if Playwright is installed and browser is running."""
        return PLAYWRIGHT_AVAILABLE and self._browser is not None

    async def start(self) -> None:
        """Launch browser. Silently skips if Playwright is not installed."""
        if not PLAYWRIGHT_AVAILABLE:
            logger.info(
                "Playwright not installed — browser features disabled. "
                "Install with: pip install playwright && playwright install chromium"
            )
            return

        try:
            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-extensions",
                ],
            )
            self._context = await self._browser.new_context(
                user_agent=self.user_agent,
                ignore_https_errors=True,
                java_script_enabled=True,
            )
            logger.info("Headless browser started (Chromium)")
        except Exception:
            logger.warning("Failed to start headless browser")
            self._browser = None

    async def stop(self) -> None:
        """Close browser and cleanup."""
        if self._context:
            with contextlib.suppress(Exception):
                await self._context.close()
        if self._browser:
            with contextlib.suppress(Exception):
                await self._browser.close()
        if self._playwright:
            with contextlib.suppress(Exception):
                await self._playwright.stop()
        self._browser = None
        self._context = None
        self._playwright = None

    async def __aenter__(self) -> BrowserManager:
        await self.start()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.stop()

    async def render(
        self,
        url: str,
        *,
        wait_for: str = "networkidle",
        screenshot: bool = False,
        extract_api_calls: bool = True,
    ) -> RenderedPage:
        """Render a page with full JavaScript execution.

        Returns a RenderedPage with rendered HTML, extracted API calls,
        links, forms, console messages, etc.
        """
        result = RenderedPage(url=url)
        if not self.available:
            return result

        async with self._semaphore:
            page = await self._context.new_page()
            try:
                api_calls: list[str] = []
                console_msgs: list[str] = []
                errors: list[str] = []

                if extract_api_calls:
                    page.on("request", lambda req: api_calls.append(req.url))
                page.on("console", lambda msg: console_msgs.append(msg.text))
                page.on(
                    "pageerror",
                    lambda err: errors.append(str(err)),
                )

                response = await page.goto(
                    url, wait_until=wait_for, timeout=self.timeout,
                )

                result.final_url = page.url
                result.status = response.status if response else 0
                result.html = await page.content()
                result.title = await page.title()

                # Extract visible text
                with contextlib.suppress(Exception):
                    result.text = await page.evaluate(
                        "() => document.body?.innerText || ''"
                    )

                # Filter API calls to interesting ones
                result.api_calls = self._filter_api_calls(api_calls, url)
                result.console_messages = console_msgs
                result.errors = errors

                # Extract links
                with contextlib.suppress(Exception):
                    result.links = await page.evaluate("""
                        () => [...document.querySelectorAll('a[href]')]
                            .map(a => a.href)
                            .filter(h => h.startsWith('http'))
                    """)

                # Extract forms
                with contextlib.suppress(Exception):
                    result.forms = await page.evaluate("""
                        () => [...document.querySelectorAll('form')].map(f => ({
                            action: f.action,
                            method: f.method,
                            inputs: [...f.querySelectorAll('input,textarea,select')]
                                .map(i => ({
                                    name: i.name,
                                    type: i.type,
                                    value: i.value
                                }))
                        }))
                    """)

                # Extract script sources
                with contextlib.suppress(Exception):
                    result.scripts = await page.evaluate("""
                        () => [...document.querySelectorAll('script[src]')]
                            .map(s => s.src)
                    """)

                # Cookies
                try:
                    raw_cookies = await self._context.cookies(url)
                    result.cookies = [
                        {
                            "name": c["name"],
                            "value": c["value"],
                            "domain": c.get("domain", ""),
                            "path": c.get("path", ""),
                            "secure": str(c.get("secure", False)),
                            "httpOnly": str(c.get("httpOnly", False)),
                        }
                        for c in raw_cookies
                    ]
                except Exception:
                    pass

                if screenshot:
                    with contextlib.suppress(Exception):
                        result.screenshot = await page.screenshot(
                            full_page=True, type="png",
                        )

            except Exception as e:
                result.errors.append(str(e))
            finally:
                await page.close()

        return result

    async def confirm_xss(
        self,
        url: str,
        payload: str,
        *,
        param: str = "",
        screenshot: bool = False,
    ) -> XSSConfirmation:
        """Confirm XSS by navigating to a URL and checking for dialog/execution.

        Injects the payload via query parameter or as-is in the URL,
        then checks if a JavaScript alert/confirm/prompt dialog fires.
        """
        result = XSSConfirmation(url=url, payload=payload)
        if not self.available:
            return result

        async with self._semaphore:
            page = await self._context.new_page()
            try:
                dialog_text: list[str] = []

                async def on_dialog(dialog: Any) -> None:
                    dialog_text.append(dialog.message)
                    await dialog.dismiss()

                page.on("dialog", on_dialog)

                # Build test URL
                if param:
                    sep = "&" if "?" in url else "?"
                    test_url = f"{url}{sep}{param}={payload}"
                else:
                    test_url = url

                await page.goto(test_url, timeout=self.timeout)
                # Wait briefly for any delayed execution
                await page.wait_for_timeout(2000)

                if dialog_text:
                    result.executed = True
                    result.alert_text = dialog_text[0]
                    result.context = "dialog"

                if screenshot and result.executed:
                    with contextlib.suppress(Exception):
                        result.screenshot = await page.screenshot(type="png")

            except Exception:
                pass
            finally:
                await page.close()

        return result

    async def crawl_spa(
        self,
        url: str,
        *,
        max_pages: int = 50,
        max_depth: int = 3,
    ) -> list[str]:
        """Crawl a Single Page Application by rendering and following links.

        Returns a list of unique URLs discovered.
        """
        if not self.available:
            return []

        discovered: set[str] = set()
        queue: list[tuple[str, int]] = [(url, 0)]
        visited: set[str] = set()

        # Extract base domain for same-origin filtering
        from urllib.parse import urlparse
        parsed = urlparse(url)
        base_domain = parsed.netloc

        while queue and len(discovered) < max_pages:
            current_url, depth = queue.pop(0)
            if current_url in visited or depth > max_depth:
                continue
            visited.add(current_url)

            page = await self.render(
                current_url, wait_for="networkidle",
            )
            discovered.add(page.final_url or current_url)

            if depth < max_depth:
                for link in page.links:
                    link_parsed = urlparse(link)
                    if (
                        link_parsed.netloc == base_domain
                        and link not in visited
                        and not link.endswith(
                            (".png", ".jpg", ".css", ".js", ".svg", ".ico")
                        )
                    ):
                        queue.append((link, depth + 1))

            # Also add API calls as discovered paths
            for api_url in page.api_calls:
                discovered.add(api_url)

        return sorted(discovered)

    async def extract_js_routes(self, url: str) -> list[str]:
        """Extract route definitions from JavaScript on a page.

        Looks for React Router, Vue Router, Angular Router patterns
        in the page's JavaScript.
        """
        if not self.available:
            return []

        page_result = await self.render(url, extract_api_calls=True)
        routes: set[str] = set()

        # Extract routes from main page HTML/JS
        route_patterns = [
            # React Router
            r'path\s*[:=]\s*["\'](/[^"\']*)["\']',
            # Vue Router
            r'path\s*:\s*["\'](/[^"\']*)["\']',
            # Angular
            r'path\s*:\s*["\']([^"\']*)["\']',
            # Generic route patterns
            r'route\s*\(\s*["\'](/[^"\']*)["\']',
            r'navigate\s*\(\s*["\'](/[^"\']*)["\']',
        ]

        for pattern in route_patterns:
            for match in re.finditer(pattern, page_result.html):
                route = match.group(1)
                if route and len(route) < 100 and not route.startswith("//"):
                    routes.add(route)

        # Fetch and analyze external JS files
        for script_url in page_result.scripts[:15]:
            if not self.available:
                break
            try:
                async with self._semaphore:
                    js_page = await self._context.new_page()
                    try:
                        resp = await js_page.goto(
                            script_url, timeout=self.timeout,
                        )
                        if resp and resp.status == 200:
                            js_text = await js_page.content()
                            for pattern in route_patterns:
                                for match in re.finditer(pattern, js_text):
                                    route = match.group(1)
                                    if (
                                        route
                                        and len(route) < 100
                                        and not route.startswith("//")
                                    ):
                                        routes.add(route)
                    finally:
                        await js_page.close()
            except Exception:
                continue

        return sorted(routes)

    @staticmethod
    def _filter_api_calls(urls: list[str], base_url: str) -> list[str]:
        """Filter captured network requests to interesting API calls."""
        from urllib.parse import urlparse
        base_parsed = urlparse(base_url)
        base_domain = base_parsed.netloc

        interesting: list[str] = []
        seen: set[str] = set()
        skip_extensions = (
            ".js", ".css", ".png", ".jpg", ".jpeg", ".gif",
            ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot",
        )
        api_indicators = (
            "/api/", "/v1/", "/v2/", "/v3/", "/graphql",
            "/rest/", "/auth/", "/oauth/", "/json",
        )

        for url in urls:
            if url in seen:
                continue
            seen.add(url)

            parsed = urlparse(url)
            # Same origin only
            if parsed.netloc != base_domain:
                continue
            path = parsed.path.lower()
            # Skip static assets
            if any(path.endswith(ext) for ext in skip_extensions):
                continue
            # Prefer API-like paths
            if any(ind in path for ind in api_indicators) or parsed.query:
                interesting.append(url)

        return interesting
