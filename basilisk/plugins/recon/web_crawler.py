"""Web crawler plugin — link extraction, webpack detection, sourcemap parsing.

Crawls target web pages to extract URLs, forms, JS files, and
parses webpack bundles / sourcemaps for secret leakage.
"""

from __future__ import annotations

import logging
import re
from typing import ClassVar
from urllib.parse import urljoin, urlparse

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult, Severity
from basilisk.models.target import Target
from basilisk.utils.secrets import redact, scan_text

logger = logging.getLogger(__name__)

# Webpack/build manifest paths
_MANIFEST_PATHS = [
    "/asset-manifest.json",
    "/webpack-manifest.json",
    "/manifest.json",
    "/build-manifest.json",
    "/static/asset-manifest.json",
    "/_next/static/chunks/webpack.js",
]

_WEBPACK_INDICATORS = re.compile(
    r"webpackJsonp|__webpack_require__|webpack_modules", re.IGNORECASE,
)

_SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")
_JS_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)


class WebCrawlerPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="web_crawler",
        display_name="Web Crawler & Webpack Analyzer",
        category=PluginCategory.RECON,
        description=(
            "Crawls pages to extract URLs, forms, and JS bundles. "
            "Detects webpack builds, parses sourcemaps, scans for secrets."
        ),
        produces=["crawled_urls", "forms", "webpack_paths"],
        timeout=60.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available",
            )

        from basilisk.utils.http_check import resolve_base_url

        findings: list[Finding] = []
        data: dict = {
            "crawled_urls": [],
            "forms": [],
            "js_files": [],
            "webpack_detected": False,
            "sourcemaps": [],
            "secrets_found": 0,
        }

        base_url = await resolve_base_url(target.host, ctx)
        if not base_url:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info("Host not reachable")],
                data=data,
            )

        # Phase 1: Fetch main page and extract links/scripts
        page_html = await self._fetch_page(ctx, base_url)
        if not page_html:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info("Could not fetch main page")],
                data=data,
            )

        js_files = self._extract_js_sources(page_html, base_url)
        links = self._extract_links(page_html, base_url, target.host)
        forms = self._extract_forms(page_html, base_url)

        # Merge config scan_paths as seed URLs to crawl
        scan_paths = ctx.config.scan.scan_paths if ctx.config else []
        for sp in scan_paths:
            if not sp.startswith("/"):
                sp = f"/{sp}"
            full = f"{base_url}{sp}"
            if full not in links:
                links.append(full)

        # Phase 1b: Follow links (depth 2) to discover parameterized URLs
        depth2_links: list[str] = []
        depth2_forms: list[dict] = []
        visited = {base_url, f"{base_url}/"}
        follow_targets = [
            u for u in links
            if u not in visited
            and (
                urlparse(u).path.endswith(
                    (".php", ".asp", ".aspx", ".jsp", ".cgi", ".html", ".htm", "/")
                )
                or "?" in u
                or "/" in urlparse(u).path.rstrip("/")
            )
        ][: max(40, len(scan_paths) + 20)]

        for follow_url in follow_targets:
            if ctx.should_stop:
                break
            visited.add(follow_url)
            sub_html = await self._fetch_page(ctx, follow_url)
            if not sub_html:
                continue
            sub_links = self._extract_links(sub_html, follow_url, target.host)
            sub_forms = self._extract_forms(sub_html, follow_url)
            for sl in sub_links:
                if sl not in links and sl not in depth2_links:
                    depth2_links.append(sl)
            for sf in sub_forms:
                if sf not in forms and sf not in depth2_forms:
                    depth2_forms.append(sf)

        links.extend(depth2_links)
        forms.extend(depth2_forms)

        data["crawled_urls"] = links[:200]
        data["forms"] = forms[:50]
        data["js_files"] = js_files[:50]

        # Phase 2: Check for webpack indicators in page
        webpack_detected = bool(_WEBPACK_INDICATORS.search(page_html))

        # Phase 3: Check manifest files
        manifest_paths: list[str] = []
        for mpath in _MANIFEST_PATHS:
            if ctx.should_stop:
                break
            try:
                async with ctx.rate:
                    url = f"{base_url}{mpath}"
                    resp = await ctx.http.get(url, timeout=5.0)
                    if resp.status == 200:
                        body = await resp.text(encoding="utf-8", errors="replace")
                        if "{" in body[:10]:  # Looks like JSON
                            webpack_detected = True
                            manifest_paths.append(mpath)
            except Exception as e:
                logger.debug("Manifest check %s failed: %s", url, e)
                continue

        data["webpack_detected"] = webpack_detected

        if webpack_detected:
            findings.append(Finding.info(
                "Webpack build detected",
                evidence=f"Manifests: {', '.join(manifest_paths) or 'inline indicators'}",
                tags=["recon", "webpack"],
            ))

        # Phase 4: Check JS files for sourcemaps
        sourcemap_urls: list[str] = []
        for js_url in js_files[:20]:
            if ctx.should_stop:
                break
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(js_url, timeout=8.0)
                    if resp.status != 200:
                        continue
                    body = await resp.text(encoding="utf-8", errors="replace")

                    # Check for webpack in inline JS
                    if _WEBPACK_INDICATORS.search(body):
                        webpack_detected = True

                    # Look for sourcemap URL
                    sm_match = _SOURCEMAP_RE.search(body)
                    if sm_match:
                        sm_url = sm_match.group(1)
                        if not sm_url.startswith("http"):
                            sm_url = urljoin(js_url, sm_url)
                        sourcemap_urls.append(sm_url)
            except Exception as e:
                logger.debug("JS fetch %s failed: %s", js_url, e)
                continue

        # Phase 5: Fetch and analyze sourcemaps
        all_secrets: list[dict] = []
        for sm_url in sourcemap_urls[:10]:
            if ctx.should_stop:
                break
            secrets = await self._analyze_sourcemap(ctx, sm_url, findings)
            all_secrets.extend(secrets)

        data["sourcemaps"] = sourcemap_urls[:20]
        data["secrets_found"] = len(all_secrets)

        if sourcemap_urls:
            findings.append(Finding.medium(
                f"Source maps accessible ({len(sourcemap_urls)} files)",
                description=(
                    "JavaScript source maps are publicly accessible. "
                    "They reveal original source code, file paths, "
                    "and potentially sensitive information."
                ),
                evidence="\n".join(sourcemap_urls[:5]),
                remediation="Remove source maps from production builds",
                tags=["recon", "sourcemap", "info-disclosure"],
            ))

        # Store for downstream plugins
        ctx.state.setdefault("webpack_paths", {})[target.host] = manifest_paths
        ctx.state.setdefault("crawled_params", {})[target.host] = (
            self._extract_params(links)
        )

        if not findings:
            findings.append(Finding.info(
                f"Crawled: {len(links)} URLs, {len(js_files)} JS files",
                tags=["recon", "crawler"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data=data,
        )

    async def _fetch_page(self, ctx, url: str) -> str:
        """Fetch a page and return its HTML content."""
        try:
            async with ctx.rate:
                resp = await ctx.http.get(url, timeout=10.0)
                if resp.status == 200:
                    return await resp.text(encoding="utf-8", errors="replace")
        except Exception:
            pass
        return ""

    @staticmethod
    def _extract_js_sources(html: str, base_url: str) -> list[str]:
        """Extract JS file URLs from HTML."""
        urls: list[str] = []
        for match in _JS_SRC_RE.finditer(html):
            src = match.group(1)
            if src.startswith("//"):
                src = "https:" + src
            elif not src.startswith("http"):
                src = urljoin(base_url, src)
            urls.append(src)
        return list(dict.fromkeys(urls))

    # URLs that destroy session state — never follow these
    _SKIP_PATHS = {"logout", "signout", "sign-out", "log-out", "logoff"}

    @staticmethod
    def _extract_links(html: str, base_url: str, host: str) -> list[str]:
        """Extract same-origin links from HTML."""
        link_re = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
        # Strip port from host for comparison (urlparse.hostname excludes port)
        host_bare = host.split(":")[0] if ":" in host else host
        urls: list[str] = []
        for match in link_re.finditer(html):
            href = match.group(1)
            if href.startswith("#") or href.startswith("javascript:"):
                continue
            if not href.startswith("http"):
                href = urljoin(base_url, href)
            parsed = urlparse(href)
            if not parsed.hostname or host_bare not in parsed.hostname:
                continue
            # Skip logout/signout URLs to preserve session
            path_lower = (parsed.path or "").lower()
            path_parts = path_lower.rstrip("/").rsplit("/", 1)[-1].split(".")
            if path_parts[0] in WebCrawlerPlugin._SKIP_PATHS:
                continue
            urls.append(href)
        return list(dict.fromkeys(urls))[:200]

    @staticmethod
    def _extract_forms(html: str, base_url: str) -> list[dict]:
        """Extract form actions and inputs (name→value) from HTML."""
        forms: list[dict] = []
        form_re = re.compile(
            r"<form[^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL,
        )
        action_re = re.compile(r'action=["\']([^"\']*)["\']', re.IGNORECASE)
        method_re = re.compile(r'method=["\']([^"\']*)["\']', re.IGNORECASE)
        # Extract name + optional value from inputs
        input_re = re.compile(
            r'<input[^>]*?name=["\']([^"\']+)["\']'
            r'(?:[^>]*?value=["\']([^"\']*)["\'])?',
            re.IGNORECASE,
        )
        # Alternative order: value before name
        input_re2 = re.compile(
            r'<input[^>]*?value=["\']([^"\']*)["\']'
            r'[^>]*?name=["\']([^"\']+)["\']',
            re.IGNORECASE,
        )
        textarea_re = re.compile(
            r'<textarea[^>]*name=["\']([^"\']+)["\']', re.IGNORECASE,
        )
        select_re = re.compile(
            r'<select[^>]*name=["\']([^"\']+)["\']', re.IGNORECASE,
        )

        for fm in form_re.finditer(html):
            form_html = fm.group(0)
            action = ""
            am = action_re.search(form_html)
            if am:
                action = urljoin(base_url, am.group(1))
            mm = method_re.search(form_html)
            method = mm.group(1).upper() if mm else "GET"
            # Build name→value dict (preserve submit button values)
            inputs: dict[str, str] = {}
            for m in input_re.finditer(form_html):
                name, value = m.group(1), m.group(2) or ""
                inputs[name] = value
            for m in input_re2.finditer(form_html):
                value, name = m.group(1), m.group(2)
                if name not in inputs:
                    inputs[name] = value
            for name in textarea_re.findall(form_html):
                if name not in inputs:
                    inputs[name] = ""
            for name in select_re.findall(form_html):
                if name not in inputs:
                    inputs[name] = ""
            forms.append({
                "action": action,
                "method": method,
                "inputs": inputs,
            })
        return forms

    @staticmethod
    def _extract_params(urls: list[str]) -> list[str]:
        """Extract unique query parameter names from URLs."""
        params: set[str] = set()
        for url in urls:
            parsed = urlparse(url)
            if parsed.query:
                for part in parsed.query.split("&"):
                    if "=" in part:
                        params.add(part.split("=")[0])
        return sorted(params)

    async def _analyze_sourcemap(
        self, ctx, sm_url: str, findings: list[Finding],
    ) -> list[dict]:
        """Fetch sourcemap and scan for secrets."""
        secrets: list[dict] = []
        try:
            async with ctx.rate:
                resp = await ctx.http.get(sm_url, timeout=10.0)
                if resp.status != 200:
                    return secrets
                body = await resp.text(encoding="utf-8", errors="replace")

                # Scan for secrets in sourcesContent (MEDIUM+ only —
                # LOW-severity matches like internal IPs are too noisy
                # in bundled JS source maps)
                for sm in scan_text(body, min_severity=Severity.MEDIUM):
                    secrets.append({
                        "type": sm.pattern_name,
                        "redacted": redact(sm.match),
                        "source": sm_url,
                    })

                if secrets:
                    findings.append(Finding.critical(
                        f"Secrets found in source map ({len(secrets)} matches)",
                        description=(
                            "Source maps contain embedded secrets such as "
                            "API keys, tokens, or private keys."
                        ),
                        evidence="\n".join(
                            f"  {s['type']}: {s['redacted']}" for s in secrets[:5]
                        ),
                        remediation=(
                            "Remove source maps from production. "
                            "Rotate all exposed credentials immediately."
                        ),
                        confidence=0.9,
                        verified=True,
                        tags=["recon", "sourcemap", "secret-leak"],
                    ))
        except Exception:
            pass  # keep any partial results found before the error
        return secrets
