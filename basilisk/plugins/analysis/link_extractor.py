"""Link extractor — discovers external integrations, subdomains, APIs, sensitive files.

Checks multiple pages (/, sitemap.xml, robots.txt, crawled URLs), extracts links
from 10+ HTML attributes and JS code, classifies by type, detects third-party
services, parses robots.txt for disallowed paths.
"""

from __future__ import annotations

import re
from typing import ClassVar
from urllib.parse import parse_qs, urlparse

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target
from basilisk.utils.http_check import resolve_base_url

# ---------------------------------------------------------------------------
# URL extraction patterns
# ---------------------------------------------------------------------------
_ATTR_URL_RE = re.compile(
    r'(?:href|src|action|data-src|data-url|poster|formaction|cite|manifest)'
    r'\s*=\s*["\']?\s*((?:https?://|//)[^\s"\'<>]+)',
    re.IGNORECASE,
)
_SRCSET_RE = re.compile(
    r'srcset\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_META_REFRESH_RE = re.compile(
    r'<meta[^>]+content\s*=\s*["\'][^"\']*url\s*=\s*(https?://[^\s"\'<>]+)',
    re.IGNORECASE,
)
# JS patterns for API URLs
_JS_FETCH_RE = re.compile(
    r'''(?:fetch|axios(?:\.(?:get|post|put|delete|patch))?'''
    r'''|\.open)\s*\(\s*[`"'](https?://[^`"']+)[`"']''',
    re.IGNORECASE,
)
_JS_URL_ASSIGN_RE = re.compile(
    r'''(?:url|endpoint|apiUrl|baseUrl|BASE_URL|API_URL)\s*'''
    r'''[:=]\s*[`"'](https?://[^`"']+)[`"']''',
    re.IGNORECASE,
)
_WS_URL_RE = re.compile(
    r'''[`"'](wss?://[^`"'\s]+)[`"']''',
)

# API endpoint indicators
_API_PATH_RE = re.compile(
    r"(?:/api/|/v[1-9]/|/v[1-9]\.\d/|/graphql|/rest/|/ws/|/rpc/)",
    re.IGNORECASE,
)

# Sensitive file extensions
_SENSITIVE_EXTS = frozenset({
    ".env", ".git", ".sql", ".bak", ".zip", ".tar.gz", ".tgz",
    ".log", ".conf", ".cfg", ".ini", ".yml", ".yaml", ".xml",
    ".key", ".pem", ".p12", ".pfx", ".old", ".orig", ".swp",
    ".sqlite", ".db", ".dump", ".csv",
})

# Third-party service classification
_THIRD_PARTY: dict[str, list[str]] = {
    "analytics": [
        "google-analytics", "googletagmanager", "gtm", "analytics.google",
        "mc.yandex.ru", "metrika.yandex", "facebook.com/tr",
        "connect.facebook.net", "hotjar", "mixpanel", "amplitude",
        "segment.io", "segment.com", "plausible.io", "matomo",
    ],
    "cdn": [
        "cloudflare", "cloudfront", "fastly", "akamai",
        "jsdelivr", "unpkg", "cdnjs", "bootstrapcdn",
        "googleapis.com", "gstatic.com", "stackpath",
    ],
    "payment": [
        "stripe.com", "js.stripe.com", "paypal.com",
        "braintree", "square", "checkout.com", "adyen",
    ],
    "auth": [
        "auth0", "okta", "firebase", "cognito",
        "accounts.google", "login.microsoftonline",
    ],
    "social": [
        "facebook.com", "twitter.com", "x.com", "instagram.com",
        "linkedin.com", "youtube.com", "vk.com", "t.me",
    ],
    "ads": [
        "googlesyndication", "doubleclick", "adsense",
        "adservice.google", "pagead", "googleadservices",
    ],
}

# Default pages
_DEFAULT_PATHS = ["/"]


class LinkExtractorPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="link_extractor",
        display_name="Link & Resource Extractor",
        category=PluginCategory.ANALYSIS,
        description=(
            "Extracts links from HTML attributes and JS, classifies domains, "
            "detects APIs, sensitive files, third-party services, robots.txt"
        ),
        produces=["external_links"],
        timeout=30.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        base_url = await resolve_base_url(target.host, ctx)
        if not base_url:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info("Host not reachable via HTTP/HTTPS")],
                data=self._empty_data(),
            )

        host = target.host.lower()
        external_domains: set[str] = set()
        subdomains: set[str] = set()
        internal_links: set[str] = set()
        api_endpoints: set[str] = set()
        sensitive_files: set[str] = set()
        all_params: set[str] = set()
        third_party: dict[str, set[str]] = {
            k: set() for k in _THIRD_PARTY
        }
        disallowed_paths: list[str] = []
        ws_urls: set[str] = set()

        findings: list[Finding] = []

        # Collect pages to check
        paths = list(_DEFAULT_PATHS)
        crawled = ctx.state.get("crawled_urls", [])
        for curl in crawled:
            if isinstance(curl, str) and curl.startswith(base_url):
                path = curl[len(base_url):]
                if path and path not in paths:
                    paths.append(path)
        paths = paths[:15]

        # Process HTML pages
        for path in paths:
            if ctx.should_stop:
                break
            url = f"{base_url}{path}"
            body = await self._fetch(url, ctx)
            if body is None:
                continue
            self._extract_from_html(
                body, base_url, host,
                external_domains, subdomains, internal_links,
                api_endpoints, sensitive_files, all_params,
                third_party, ws_urls,
            )

        # Parse robots.txt
        if not ctx.should_stop:
            disallowed_paths, sitemap_urls = await self._parse_robots(
                base_url, ctx,
            )
            # Check sitemaps for more URLs
            for smap_url in sitemap_urls[:3]:
                if ctx.should_stop:
                    break
                body = await self._fetch(smap_url, ctx)
                if body:
                    self._extract_sitemap_urls(
                        body, base_url, host,
                        external_domains, subdomains, internal_links,
                        api_endpoints, sensitive_files, all_params,
                        third_party, ws_urls,
                    )

        # Parse /sitemap.xml directly if not found in robots.txt
        if not ctx.should_stop and not sitemap_urls:
            body = await self._fetch(f"{base_url}/sitemap.xml", ctx)
            if body:
                self._extract_sitemap_urls(
                    body, base_url, host,
                    external_domains, subdomains, internal_links,
                    api_endpoints, sensitive_files, all_params,
                    third_party, ws_urls,
                )

        # --- Findings ---
        if external_domains:
            findings.append(Finding.info(
                f"Found {len(external_domains)} external domains",
                evidence=", ".join(sorted(external_domains)[:30]),
                tags=["analysis", "links", "external"],
            ))

        if subdomains:
            findings.append(Finding.info(
                f"Discovered {len(subdomains)} subdomains via links",
                evidence=", ".join(sorted(subdomains)[:20]),
                tags=["analysis", "links", "subdomains"],
            ))

        if api_endpoints:
            findings.append(Finding.low(
                f"Found {len(api_endpoints)} API endpoints in page source",
                evidence="\n".join(sorted(api_endpoints)[:10]),
                remediation="Ensure API endpoints require proper authentication",
                tags=["analysis", "links", "api"],
            ))

        if sensitive_files:
            findings.append(Finding.medium(
                f"Links to sensitive files detected ({len(sensitive_files)})",
                description=(
                    "Page source references files with sensitive extensions "
                    "that may contain configuration, backups, or credentials"
                ),
                evidence="\n".join(sorted(sensitive_files)[:10]),
                remediation="Remove references to sensitive files; restrict access",
                tags=["analysis", "links", "sensitive-files"],
            ))

        if ws_urls:
            findings.append(Finding.info(
                f"WebSocket endpoints found: {len(ws_urls)}",
                evidence=", ".join(sorted(ws_urls)[:5]),
                tags=["analysis", "links", "websocket"],
            ))

        if disallowed_paths:
            findings.append(Finding.low(
                f"Robots.txt disallows {len(disallowed_paths)} paths",
                description="Disallowed paths may indicate sensitive areas",
                evidence="\n".join(disallowed_paths[:15]),
                remediation=(
                    "Disallowed paths are public info; use authentication "
                    "instead of obscurity"
                ),
                tags=["analysis", "links", "robots"],
            ))

        # Third-party service findings
        active_services: dict[str, list[str]] = {}
        for category, domains in third_party.items():
            if domains:
                active_services[category] = sorted(domains)

        if active_services:
            parts = []
            for cat, doms in sorted(active_services.items()):
                parts.append(f"{cat}: {', '.join(doms[:5])}")
            findings.append(Finding.info(
                f"Third-party services: {len(active_services)} categories",
                evidence="\n".join(parts),
                tags=["analysis", "links", "third-party"],
            ))

        if not findings:
            findings.append(Finding.info(
                "No notable links found",
                tags=["analysis", "links"],
            ))

        # Store subdomains in state for recon enrichment
        if subdomains:
            ctx.state.setdefault("link_subdomains", []).extend(
                sorted(subdomains)
            )

        # Store parameters for pentesting
        if all_params:
            ctx.state.setdefault("link_params", []).extend(
                sorted(all_params)
            )

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "external_domains": sorted(external_domains),
                "subdomains": sorted(subdomains),
                "internal_links": sorted(internal_links)[:200],
                "api_endpoints": sorted(api_endpoints),
                "sensitive_files": sorted(sensitive_files),
                "parameters": sorted(all_params),
                "third_party": {
                    k: sorted(v) for k, v in third_party.items() if v
                },
                "disallowed_paths": disallowed_paths,
            },
        )

    # ------------------------------------------------------------------
    # Extraction helpers
    # ------------------------------------------------------------------

    def _extract_from_html(
        self,
        body: str,
        base_url: str,
        host: str,
        external_domains: set[str],
        subdomains: set[str],
        internal_links: set[str],
        api_endpoints: set[str],
        sensitive_files: set[str],
        all_params: set[str],
        third_party: dict[str, set[str]],
        ws_urls: set[str],
    ) -> None:
        """Extract and classify all URLs from an HTML page body."""
        urls: list[str] = []

        # Standard attribute URLs
        urls.extend(_ATTR_URL_RE.findall(body))

        # Srcset (contains URLs with descriptors)
        for srcset_val in _SRCSET_RE.findall(body):
            for part in srcset_val.split(","):
                part = part.strip()
                if part:
                    url_part = part.split()[0]
                    if url_part.startswith(("http://", "https://", "//")):
                        urls.append(url_part)

        # Meta refresh redirect
        urls.extend(_META_REFRESH_RE.findall(body))

        # JS patterns: fetch/axios/open
        urls.extend(_JS_FETCH_RE.findall(body))
        urls.extend(_JS_URL_ASSIGN_RE.findall(body))

        # WebSocket URLs
        for ws_url in _WS_URL_RE.findall(body):
            ws_urls.add(ws_url)

        # Classify each URL
        for raw_url in urls:
            self._classify_url(
                raw_url, base_url, host,
                external_domains, subdomains, internal_links,
                api_endpoints, sensitive_files, all_params,
                third_party,
            )

    def _classify_url(
        self,
        raw_url: str,
        base_url: str,
        host: str,
        external_domains: set[str],
        subdomains: set[str],
        internal_links: set[str],
        api_endpoints: set[str],
        sensitive_files: set[str],
        all_params: set[str],
        third_party: dict[str, set[str]],
    ) -> None:
        """Classify a single URL into the appropriate bucket."""
        # Normalize protocol-relative URLs
        if raw_url.startswith("//"):
            raw_url = f"https:{raw_url}"

        try:
            parsed = urlparse(raw_url)
        except Exception:
            return

        hostname = (parsed.hostname or "").lower().rstrip(".")
        if not hostname:
            return

        path = parsed.path or ""

        # Extract query parameters
        if parsed.query:
            for param_name in parse_qs(parsed.query):
                all_params.add(param_name)

        # Check for sensitive file extensions
        path_lower = path.lower()
        for ext in _SENSITIVE_EXTS:
            if path_lower.endswith(ext):
                sensitive_files.add(raw_url[:200])
                break

        # Check for API endpoints
        if _API_PATH_RE.search(path):
            api_endpoints.add(raw_url[:200])

        # Classify by domain relationship
        if hostname == host:
            internal_links.add(raw_url[:200])
        elif hostname.endswith(f".{host}"):
            subdomains.add(hostname)
            internal_links.add(raw_url[:200])
        else:
            external_domains.add(hostname)
            # Check third-party classification
            for category, indicators in _THIRD_PARTY.items():
                for indicator in indicators:
                    if indicator in hostname or indicator in raw_url.lower():
                        third_party[category].add(hostname)
                        break

    def _extract_sitemap_urls(
        self,
        body: str,
        base_url: str,
        host: str,
        external_domains: set[str],
        subdomains: set[str],
        internal_links: set[str],
        api_endpoints: set[str],
        sensitive_files: set[str],
        all_params: set[str],
        third_party: dict[str, set[str]],
        ws_urls: set[str],
    ) -> None:
        """Extract URLs from sitemap XML content."""
        loc_re = re.compile(r"<loc>\s*(.*?)\s*</loc>", re.IGNORECASE)
        for url in loc_re.findall(body):
            self._classify_url(
                url.strip(), base_url, host,
                external_domains, subdomains, internal_links,
                api_endpoints, sensitive_files, all_params,
                third_party,
            )

    # ------------------------------------------------------------------
    # Robots.txt parsing
    # ------------------------------------------------------------------

    async def _parse_robots(
        self, base_url: str, ctx,
    ) -> tuple[list[str], list[str]]:
        """Parse robots.txt for disallowed paths and sitemap URLs."""
        disallowed: list[str] = []
        sitemaps: list[str] = []
        body = await self._fetch(f"{base_url}/robots.txt", ctx)
        if not body:
            return disallowed, sitemaps

        for line in body.splitlines():
            line = line.strip()
            lower = line.lower()
            if lower.startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    if not path.startswith("/"):
                        path = "/" + path
                    disallowed.append(path)
            elif lower.startswith("sitemap:"):
                url = line.split(":", 1)[1].strip()
                # Reconstruct: "sitemap:" consumed first colon
                if not url.startswith("http"):
                    url = line.split(" ", 1)[1].strip() if " " in line else ""
                if url.startswith("http"):
                    sitemaps.append(url)

        return disallowed[:50], sitemaps[:5]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    async def _fetch(url: str, ctx) -> str | None:
        """Fetch a URL, return body text or None on error."""
        try:
            async with ctx.rate:
                resp = await ctx.http.get(url, timeout=8.0)
                if resp.status != 200:
                    return None
                return await resp.text(encoding="utf-8", errors="replace")
        except Exception:
            return None

    @staticmethod
    def _empty_data() -> dict:
        return {
            "external_domains": [],
            "subdomains": [],
            "internal_links": [],
            "api_endpoints": [],
            "sensitive_files": [],
            "parameters": [],
            "third_party": {},
            "disallowed_paths": [],
        }
