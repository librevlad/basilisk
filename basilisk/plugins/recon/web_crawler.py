"""BFS/DFS web crawler — discovers pages, forms, JS endpoints, parameters.

Enhanced with JS endpoint extraction, hidden input discovery, robots.txt/
sitemap integration, parameter collection, directory detection, and
optional headless browser for SPA support.  Level: gospider + katana.
"""

from __future__ import annotations

import asyncio
import re
from typing import ClassVar
from urllib.parse import urljoin, urlparse

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

# Regex patterns for link/form/JS extraction
_LINK_RE = re.compile(r'<a[^>]+href=["\']([^"\'#]+)["\']', re.IGNORECASE)
_FORM_RE = re.compile(
    r'<form[^>]*action=["\']?([^"\'>\s]*)["\']?[^>]*>(.*?)</form>',
    re.IGNORECASE | re.DOTALL,
)
_INPUT_RE = re.compile(
    r'<input[^>]*name=["\']([^"\']+)["\']', re.IGNORECASE,
)
_HIDDEN_RE = re.compile(
    r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\']'
    r'[^>]*value=["\']([^"\']*)["\']',
    re.IGNORECASE,
)
_METHOD_RE = re.compile(r'method=["\']?(\w+)["\']?', re.IGNORECASE)
_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
_INLINE_SCRIPT_RE = re.compile(
    r'<script[^>]*>(.*?)</script>', re.IGNORECASE | re.DOTALL,
)
_META_REDIRECT_RE = re.compile(
    r'<meta[^>]*content=["\'][^"\']*url=([^"\';\s]+)', re.IGNORECASE,
)
_COMMENT_RE = re.compile(r'<!--(.*?)-->', re.DOTALL)
_CSS_LINK_RE = re.compile(
    r'<link[^>]+href=["\']([^"\']+\.css[^"\']*)["\']', re.IGNORECASE,
)

# JS API endpoint patterns
_JS_API_PATTERNS = [
    re.compile(
        r'(?:fetch|axios\.(?:get|post|put|delete|patch)|XMLHttpRequest|'
        r'\$\.(?:ajax|get|post)|\.open\(["\'](?:GET|POST|PUT|DELETE))'
        r'[^"\']*["\']([/][a-zA-Z0-9/_.-]+)',
    ),
    re.compile(r'["\'](/api/[a-zA-Z0-9/_.-]+)["\']'),
    re.compile(r'["\'](/v[0-9]+/[a-zA-Z0-9/_.-]+)["\']'),
    re.compile(r'["\'](\S+/graphql)\b["\']'),
    re.compile(r'(?:apiUrl|baseUrl|endpoint|apiBase)\s*[:=]\s*["\']([^"\']+)["\']'),
    re.compile(r'(?:url|href|src|action)\s*[:=]\s*["\'](/[a-zA-Z0-9/_.-]{3,})["\']'),
]

# Sensitive file extensions to flag
SENSITIVE_EXTENSIONS = {
    ".sql", ".bak", ".old", ".backup", ".dump", ".log", ".conf", ".config",
    ".env", ".key", ".pem", ".p12", ".pfx", ".jks", ".sqlite", ".db",
}

# Parameter patterns in URLs
_PARAM_PATTERN = re.compile(r'[?&]([a-zA-Z0-9_-]+)=')

MAX_PAGES = 150
MAX_DEPTH = 4
WORKERS = 8


class WebCrawlerPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="web_crawler",
        display_name="BFS Web Crawler",
        category=PluginCategory.RECON,
        description=(
            "Crawls website: pages, forms, JS endpoints, parameters, "
            "hidden inputs, directory listing, robots/sitemap integration"
        ),
        produces=["crawled_urls", "forms", "api_endpoints", "parameters"],
        provides="crawled_urls",
        timeout=90.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        base_url = ""
        for scheme in ("https", "http"):
            try:
                async with ctx.rate:
                    resp = await ctx.http.head(
                        f"{scheme}://{target.host}/", timeout=5.0,
                    )
                    if resp.status < 500:
                        base_url = f"{scheme}://{target.host}"
                        break
            except Exception:
                continue

        if not base_url:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info("Host not reachable for crawling")],
                data={
                    "crawled_urls": [], "forms": [],
                    "api_endpoints": [], "parameters": [],
                },
            )

        # Seed URLs from robots.txt and sitemap
        seed_urls = [f"{base_url}/"]
        robots_urls, robots_sitemaps = await self._parse_robots(ctx, base_url)
        seed_urls.extend(robots_urls)

        sitemap_urls = await self._parse_sitemaps(ctx, base_url, robots_sitemaps)
        seed_urls.extend(sitemap_urls[:30])

        # BFS crawl
        visited: set[str] = set()
        queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
        all_forms: list[dict] = []
        all_api_endpoints: set[str] = set()
        all_parameters: set[str] = set()
        all_hidden_inputs: list[dict] = []
        all_scripts: set[str] = set()
        all_subdomains: set[str] = set()
        dir_listings: list[str] = []
        sensitive_files: list[str] = []
        external_links: set[str] = set()
        crawled: list[str] = []
        comments: list[str] = []

        for url in seed_urls:
            await queue.put((url, 0))

        lock = asyncio.Lock()

        async def worker() -> None:
            while True:
                try:
                    url, depth = queue.get_nowait()
                except asyncio.QueueEmpty:
                    break

                if ctx.should_stop or len(visited) >= MAX_PAGES:
                    break
                if url in visited or depth > MAX_DEPTH:
                    continue

                visited.add(url)

                try:
                    async with ctx.rate:
                        resp = await ctx.http.get(url, timeout=8.0)
                        if resp.status != 200:
                            # Check for directory listing
                            if resp.status == 403:
                                continue
                            continue

                        ct = resp.headers.get("content-type", "")
                        if "text/html" not in ct and "application/xhtml" not in ct:
                            continue

                        body = await resp.text(encoding="utf-8", errors="replace")
                except Exception:
                    continue

                crawled.append(url)

                async with lock:
                    # Check for directory listing
                    if self._is_directory_listing(body):
                        dir_listings.append(url)

                    # Extract links
                    for href in _LINK_RE.findall(body):
                        abs_url = urljoin(url, href)
                        parsed = urlparse(abs_url)

                        # Collect parameters
                        for param in _PARAM_PATTERN.findall(abs_url):
                            all_parameters.add(param)

                        # Track subdomains
                        if (
                            parsed.hostname
                            and parsed.hostname.endswith(f".{target.host}")
                            and parsed.hostname != target.host
                        ):
                            all_subdomains.add(parsed.hostname)

                        # External links
                        if parsed.hostname and parsed.hostname != target.host:
                            if not parsed.hostname.endswith(f".{target.host}"):
                                external_links.add(
                                    f"{parsed.scheme}://{parsed.hostname}"
                                )
                            continue

                        # Normalize URL
                        clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        if parsed.query:
                            clean += f"?{parsed.query}"

                        # Check for sensitive files
                        path_lower = parsed.path.lower()
                        for ext in SENSITIVE_EXTENSIONS:
                            if path_lower.endswith(ext):
                                sensitive_files.append(abs_url)
                                break

                        if clean not in visited and len(visited) < MAX_PAGES:
                            await queue.put((clean, depth + 1))

                    # Meta redirect
                    for meta_url in _META_REDIRECT_RE.findall(body):
                        abs_url = urljoin(url, meta_url)
                        if (
                            urlparse(abs_url).hostname == target.host
                            and abs_url not in visited
                        ):
                            await queue.put((abs_url, depth + 1))

                    # Extract forms
                    forms = self._extract_forms(url, body)
                    all_forms.extend(forms)

                    # Extract hidden inputs
                    for match in _HIDDEN_RE.finditer(body):
                        all_hidden_inputs.append({
                            "name": match.group(1),
                            "value": match.group(2)[:100],
                            "page": url,
                        })

                    # Extract inline JS API endpoints
                    for script_body in _INLINE_SCRIPT_RE.findall(body):
                        self._extract_api_from_js(
                            script_body, all_api_endpoints,
                        )

                    # Collect external script URLs
                    for src in _SCRIPT_SRC_RE.findall(body):
                        abs_src = urljoin(url, src)
                        if urlparse(abs_src).hostname == target.host:
                            all_scripts.add(abs_src)

                    # Extract HTML comments
                    for comment in _COMMENT_RE.findall(body):
                        comment = comment.strip()
                        if len(comment) > 10 and len(comment) < 500:
                            comments.append(comment)

        # Run BFS workers in waves
        for _wave in range(MAX_PAGES // WORKERS + 1):
            if queue.empty() or ctx.should_stop:
                break
            workers = [asyncio.create_task(worker()) for _ in range(WORKERS)]
            await asyncio.gather(*workers, return_exceptions=True)
            if queue.empty():
                break

        # Phase 2: Fetch and analyze JS files for API endpoints
        if not ctx.should_stop:
            for script_url in list(all_scripts)[:20]:
                if ctx.should_stop:
                    break
                try:
                    async with ctx.rate:
                        resp = await ctx.http.get(script_url, timeout=8.0)
                        if resp.status == 200:
                            js_body = await resp.text(
                                encoding="utf-8", errors="replace",
                            )
                            self._extract_api_from_js(js_body, all_api_endpoints)
                except Exception:
                    continue

        # Phase 3: Browser-based SPA crawling (optional)
        if (
            ctx.browser is not None
            and not ctx.should_stop
            and len(crawled) < 5
        ):
            try:
                spa_result = await ctx.browser.crawl_spa(
                    base_url, max_pages=20, max_depth=2,
                )
                if spa_result:
                    for page in spa_result:
                        if hasattr(page, "url") and page.url not in visited:
                            crawled.append(page.url)
                        if hasattr(page, "api_calls"):
                            all_api_endpoints.update(page.api_calls)
            except Exception:
                pass

        # Build findings
        findings: list[Finding] = []

        if crawled:
            findings.append(Finding.info(
                f"Crawled {len(crawled)} pages, {len(all_forms)} forms, "
                f"{len(all_api_endpoints)} API endpoints, "
                f"{len(all_parameters)} parameters",
                tags=["recon", "crawler"],
            ))

        if all_api_endpoints:
            findings.append(Finding.low(
                f"Discovered {len(all_api_endpoints)} API endpoints from JS",
                evidence=", ".join(sorted(all_api_endpoints)[:20]),
                tags=["recon", "crawler", "api"],
            ))

        if dir_listings:
            findings.append(Finding.medium(
                f"Directory listing enabled on {len(dir_listings)} paths",
                description="Directory listing exposes file structure",
                evidence=", ".join(dir_listings[:10]),
                remediation="Disable directory listing in web server config",
                tags=["recon", "crawler", "directory-listing"],
            ))

        if sensitive_files:
            findings.append(Finding.medium(
                f"Found {len(sensitive_files)} sensitive file links",
                evidence=", ".join(sensitive_files[:10]),
                tags=["recon", "crawler", "sensitive-files"],
            ))

        if all_subdomains:
            findings.append(Finding.info(
                f"Crawler discovered {len(all_subdomains)} subdomains",
                evidence=", ".join(sorted(all_subdomains)[:10]),
                tags=["recon", "crawler", "subdomains"],
            ))

        if not crawled:
            findings.append(Finding.info(
                "No crawlable pages found",
                tags=["recon", "crawler"],
            ))

        # Deduplicate hidden inputs
        {
            f"{h['name']}:{h['value']}" for h in all_hidden_inputs
        }

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "crawled_urls": crawled,
                "forms": all_forms[:200],
                "api_endpoints": sorted(all_api_endpoints),
                "parameters": sorted(all_parameters),
                "hidden_inputs": all_hidden_inputs[:100],
                "scripts": sorted(all_scripts),
                "subdomains": sorted(all_subdomains),
                "directory_listings": dir_listings,
                "sensitive_files": sensitive_files,
                "external_links": sorted(external_links),
                "comments": comments[:50],
                "pages_crawled": len(crawled),
            },
        )

    async def _parse_robots(
        self, ctx, base_url: str,
    ) -> tuple[list[str], list[str]]:
        """Parse robots.txt for Disallow paths and Sitemap URLs."""
        urls: list[str] = []
        sitemaps: list[str] = []
        try:
            async with ctx.rate:
                resp = await ctx.http.get(
                    f"{base_url}/robots.txt", timeout=5.0,
                )
                if resp.status == 200:
                    body = await resp.text(encoding="utf-8", errors="replace")
                    for line in body.splitlines():
                        line = line.strip()
                        lower = line.lower()
                        if lower.startswith("disallow:"):
                            path = line.split(":", 1)[1].strip()
                            if path and not path.startswith("*") and len(path) < 200:
                                urls.append(f"{base_url}{path}")
                        elif lower.startswith("allow:"):
                            path = line.split(":", 1)[1].strip()
                            if path and not path.startswith("*"):
                                urls.append(f"{base_url}{path}")
                        elif lower.startswith("sitemap:"):
                            sm = line.split(":", 1)[1].strip()
                            if sm.startswith("http"):
                                sitemaps.append(sm)
        except Exception:
            pass
        return urls[:20], sitemaps

    async def _parse_sitemaps(
        self, ctx, base_url: str, extra_sitemaps: list[str],
    ) -> list[str]:
        """Parse sitemap.xml and any referenced sitemaps."""
        urls: list[str] = []
        sitemap_urls = [f"{base_url}/sitemap.xml"] + extra_sitemaps

        for sm_url in sitemap_urls[:5]:
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(sm_url, timeout=5.0)
                    if resp.status == 200:
                        body = await resp.text(
                            encoding="utf-8", errors="replace",
                        )
                        # Extract <loc> URLs
                        host = urlparse(base_url).hostname
                        for match in re.findall(r'<loc>([^<]+)</loc>', body):
                            if urlparse(match).hostname == host:
                                urls.append(match)

                        # Check for sitemap index
                        for match in re.findall(r'<sitemap>.*?<loc>([^<]+)', body):
                            if match not in sitemap_urls:
                                sitemap_urls.append(match)
            except Exception:
                continue

        return urls[:50]

    @staticmethod
    def _extract_forms(page_url: str, body: str) -> list[dict]:
        """Extract HTML forms with actions, methods, and inputs."""
        forms: list[dict] = []
        for action, form_body in _FORM_RE.findall(body):
            method_match = _METHOD_RE.search(form_body)
            method = method_match.group(1).upper() if method_match else "GET"
            inputs = _INPUT_RE.findall(form_body)
            abs_action = urljoin(page_url, action) if action else page_url

            # Check for file upload
            has_file = bool(re.search(
                r'type=["\']file["\']', form_body, re.IGNORECASE,
            ))

            # Check for CSRF token
            has_csrf = bool(re.search(
                r'name=["\'](?:csrf|_token|csrfmiddleware|__RequestVerification)',
                form_body, re.IGNORECASE,
            ))

            forms.append({
                "action": abs_action,
                "method": method,
                "inputs": inputs,
                "page": page_url,
                "has_file_upload": has_file,
                "has_csrf_token": has_csrf,
            })
        return forms

    @staticmethod
    def _extract_api_from_js(
        js_body: str, endpoints: set[str],
    ) -> None:
        """Extract API endpoints from JavaScript code."""
        for pattern in _JS_API_PATTERNS:
            for match in pattern.findall(js_body):
                if (
                    match
                    and len(match) > 2
                    and len(match) < 200
                    and not match.endswith((".js", ".css", ".png", ".jpg", ".gif"))
                ):
                    endpoints.add(match)

    @staticmethod
    def _is_directory_listing(body: str) -> bool:
        """Detect if response is a directory listing page."""
        indicators = [
            "Index of /",
            "Directory listing for",
            "<title>Directory listing",
            "Parent Directory</a>",
            "[To Parent Directory]",
            'class="dirlist"',
            'id="dirlist"',
        ]
        lower = body[:2000].lower()
        return sum(1 for i in indicators if i.lower() in lower) >= 2
