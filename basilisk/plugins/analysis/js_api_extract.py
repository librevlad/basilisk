"""JavaScript secrets and API endpoint extraction plugin.

Scans inline scripts, external JS bundles, and source maps for:
- Hardcoded secrets (AWS keys, API keys, tokens, passwords, connection strings)
- API endpoints (fetch, axios, XHR, GraphQL, WebSocket)
- Framework configuration leaks (Angular, React, Vue)
- Source map files (.js.map) indicating debug builds in production
"""

from __future__ import annotations

import re
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target
from basilisk.utils.secrets import SECRET_REGISTRY

# ---------------------------------------------------------------------------
# API endpoint extraction patterns
# ---------------------------------------------------------------------------
_FETCH_RE = re.compile(
    r"""(?:fetch|axios\.\w+|get|post|put|delete|patch)"""
    r"""\s*\(\s*['"`]([/][a-zA-Z0-9_./-]+)""", re.I,
)
_API_PATH_RE = re.compile(r"""['"`](/api[a-zA-Z0-9_./-]*)['"`]""")
_VERSION_RE = re.compile(r"""['"`](/v[1-9][a-zA-Z0-9_./-]*)['"`]""")
_AJAX_RE = re.compile(
    r"""url\s*:\s*['"`]([/][a-zA-Z0-9_./-]+)['"`]""", re.I,
)
_XHR_RE = re.compile(
    r"""\.open\s*\(\s*['"](?:GET|POST|PUT|DELETE|PATCH|OPTIONS)['"],"""
    r"""\s*['"`]([/][a-zA-Z0-9_./-]+)""", re.I,
)
_ROUTER_RE = re.compile(r"""path\s*:\s*['"`](/[a-zA-Z0-9_./:*-]+)['"`]""")
_ENDPOINT_RE = re.compile(
    r"""(?:endpoint|baseURL|apiUrl|api_url|apiPath|base_url|"""
    r"""apiBase|apiEndpoint|serviceUrl)"""
    r"""\s*[:=]\s*['"`]([/][a-zA-Z0-9_./-]+)""", re.I,
)
_FULL_URL_RE = re.compile(
    r"""['"`]https?://[^'"`]+?(/(?:api|v[1-9]|rest|graphql)[a-zA-Z0-9_./-]*)['"`]""",
)
_GRAPHQL_RE = re.compile(
    r"""['"`]((?:https?://)?[^'"`]*?/graphql[a-zA-Z0-9_/-]*)['"`]""", re.I,
)
_WEBSOCKET_RE = re.compile(
    r"""['"`](wss?://[^'"`\s]{5,})['"`]""", re.I,
)

_PATH_PATTERNS = [
    _FETCH_RE, _API_PATH_RE, _VERSION_RE, _AJAX_RE,
    _XHR_RE, _ROUTER_RE, _ENDPOINT_RE, _FULL_URL_RE,
]

# Internal/admin paths of interest
_INTERESTING_PREFIXES = (
    "/api/", "/v1/", "/v2/", "/v3/", "/admin/", "/internal/",
    "/graphql", "/rest/", "/auth/", "/oauth/", "/login",
    "/user", "/account", "/profile", "/upload", "/download",
    "/webhook", "/callback", "/ws", "/socket",
    "/debug", "/metrics", "/health", "/config",
    "/token", "/session", "/payment", "/billing",
)

# Skip noise
_SKIP_PATTERNS = {
    "/api/v", "//", "/undefined", "/null", "/.js", "/.css",
    "/favicon", "/static/", "/assets/", "/img/", "/images/",
    "/fonts/", "/vendor/", "/node_modules/",
}

# Framework config patterns
_ANGULAR_ENV_RE = re.compile(
    r"""environment\s*[:=]\s*\{([^}]{20,})\}""", re.I | re.DOTALL,
)
_REACT_ENV_RE = re.compile(
    r"""(?:REACT_APP_|NEXT_PUBLIC_|VITE_)[A-Z_]+\s*[:=]\s*['"`]([^'"`]+)""",
)
_VUE_CONFIG_RE = re.compile(
    r"""(?:VUE_APP_)[A-Z_]+\s*[:=]\s*['"`]([^'"`]+)""",
)
_WEBPACK_PUBLIC_PATH_RE = re.compile(
    r"""__webpack_public_path__\s*=\s*['"`]([^'"`]+)""",
)


class JsApiExtractPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="js_api_extract",
        display_name="JS Secrets & API Extractor",
        category=PluginCategory.ANALYSIS,
        description=(
            "Extracts API endpoints, hardcoded secrets, and framework "
            "configs from JavaScript source code"
        ),
        produces=["js_api_paths", "js_secrets"],
        timeout=45.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        from basilisk.utils.http_check import resolve_base_url

        base_url = await resolve_base_url(target.host, ctx)
        if not base_url:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info("Host not reachable via HTTP(S)")],
                data={},
            )

        findings: list[Finding] = []
        all_paths: set[str] = set()
        all_secrets: list[dict] = []
        graphql_endpoints: set[str] = set()
        websocket_urls: set[str] = set()
        source_maps: list[str] = []
        framework_configs: list[dict] = []
        js_urls: list[str] = []
        js_files_scanned = 0

        # Fetch main page, extract inline scripts and JS URLs
        main_body = ""
        try:
            async with ctx.rate:
                resp = await ctx.http.get(f"{base_url}/", timeout=10.0)
                if resp.status == 200:
                    main_body = await resp.text(
                        encoding="utf-8", errors="replace",
                    )

                    # Extract paths and secrets from inline scripts
                    for m in re.finditer(
                        r'<script[^>]*>(.*?)</script>',
                        main_body, re.DOTALL | re.IGNORECASE,
                    ):
                        script_content = m.group(1)
                        if len(script_content.strip()) < 10:
                            continue
                        self._extract_paths(script_content, all_paths)
                        self._extract_secrets(
                            script_content, all_secrets, "inline",
                        )
                        self._extract_graphql(
                            script_content, graphql_endpoints,
                        )
                        self._extract_websockets(
                            script_content, websocket_urls,
                        )
                        self._extract_framework_config(
                            script_content, framework_configs,
                        )

                    # Collect external JS URLs
                    for m in re.finditer(
                        r'<script[^>]+src=["\']([^"\']+)["\']',
                        main_body, re.IGNORECASE,
                    ):
                        src = m.group(1)
                        if src.startswith("//"):
                            js_urls.append(f"https:{src}")
                        elif src.startswith("/"):
                            js_urls.append(f"{base_url}{src}")
                        elif src.startswith("http"):
                            js_urls.append(src)
        except Exception:
            pass

        # Scan external JS files (limit 25, skip third-party CDNs)
        domain = target.host
        for js_url in js_urls[:25]:
            if ctx.should_stop:
                break
            # Only fetch same-origin or subdomain JS
            if domain not in js_url and not js_url.startswith(base_url):
                continue
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(js_url, timeout=10.0)
                    if resp.status != 200:
                        continue
                    ct = resp.headers.get("content-type", "")
                    if not (
                        "javascript" in ct
                        or "text/" in ct
                        or js_url.endswith(".js")
                    ):
                        continue

                    content = await resp.text(
                        encoding="utf-8", errors="replace",
                    )
                    js_files_scanned += 1

                    self._extract_paths(content, all_paths)
                    self._extract_secrets(all_secrets=all_secrets, content=content, source=js_url)
                    self._extract_graphql(content, graphql_endpoints)
                    self._extract_websockets(content, websocket_urls)
                    self._extract_framework_config(
                        content, framework_configs,
                    )

                    # Check for source map reference
                    sm = self._check_source_map(content, js_url)
                    if sm:
                        source_maps.append(sm)
            except Exception:
                continue

        # Also scan common JS bundle paths
        bundle_paths = [
            "/static/js/main.js", "/assets/js/app.js", "/bundle.js",
            "/static/js/app.js", "/dist/app.js", "/js/main.js",
            "/build/static/js/main.js", "/js/app.js",
            "/static/js/vendor.js", "/static/js/chunk.js",
            "/_next/static/chunks/main.js",
            "/_next/static/chunks/pages/_app.js",
        ]
        for bp in bundle_paths:
            if ctx.should_stop:
                break
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(
                        f"{base_url}{bp}", timeout=6.0,
                    )
                    if resp.status != 200:
                        continue
                    ct = resp.headers.get("content-type", "")
                    if not ("javascript" in ct or "text/" in ct):
                        continue

                    content = await resp.text(
                        encoding="utf-8", errors="replace",
                    )
                    js_files_scanned += 1

                    self._extract_paths(content, all_paths)
                    self._extract_secrets(
                        content, all_secrets, f"{base_url}{bp}",
                    )
                    self._extract_graphql(content, graphql_endpoints)
                    self._extract_websockets(content, websocket_urls)
                    self._extract_framework_config(
                        content, framework_configs,
                    )

                    sm = self._check_source_map(
                        content, f"{base_url}{bp}",
                    )
                    if sm:
                        source_maps.append(sm)
            except Exception:
                continue

        # Verify source maps are accessible
        verified_maps: list[str] = []
        for map_url in source_maps[:10]:
            if ctx.should_stop:
                break
            try:
                async with ctx.rate:
                    resp = await ctx.http.head(map_url, timeout=5.0)
                    if resp.status == 200:
                        verified_maps.append(map_url)
            except Exception:
                continue

        # ----- Generate findings -----

        # Secrets findings
        if all_secrets:
            # Deduplicate by (name, match)
            seen: set[tuple[str, str]] = set()
            unique_secrets: list[dict] = []
            for s in all_secrets:
                key = (s["name"], s["match"][:40])
                if key not in seen:
                    seen.add(key)
                    unique_secrets.append(s)

            for secret in unique_secrets[:20]:
                factory = getattr(Finding, secret["severity"])
                # Mask the actual secret value for safe display
                match_display = secret["match"]
                if len(match_display) > 12:
                    match_display = (
                        match_display[:6] + "..." + match_display[-4:]
                    )
                findings.append(factory(
                    f"{secret['name']} found in JS ({secret['source']})",
                    description=secret["description"],
                    evidence=f"Pattern match: {match_display}",
                    remediation=(
                        "Remove hardcoded secrets from client-side code. "
                        "Rotate compromised credentials immediately."
                    ),
                    tags=["analysis", "secrets", "javascript"],
                ))

        # API endpoint findings
        api_paths = sorted(all_paths)
        interesting = [
            p for p in api_paths
            if any(p.startswith(px) for px in _INTERESTING_PREFIXES)
        ]

        if interesting:
            findings.append(Finding.medium(
                f"JS API extraction: {len(interesting)} interesting "
                f"endpoints found",
                description=(
                    "Sensitive API paths extracted from JavaScript source code"
                ),
                evidence=", ".join(interesting[:15]),
                remediation=(
                    "Review exposed API endpoints for authorization "
                    "requirements and rate limiting"
                ),
                tags=["analysis", "api", "javascript"],
            ))
        elif api_paths:
            findings.append(Finding.info(
                f"JS API extraction: {len(api_paths)} paths found "
                "(no sensitive ones)",
                evidence=", ".join(api_paths[:10]),
                tags=["analysis", "api", "javascript"],
            ))
        else:
            findings.append(Finding.info(
                f"No API paths found in {js_files_scanned} JS sources",
                tags=["analysis", "api", "javascript"],
            ))

        # GraphQL findings
        if graphql_endpoints:
            findings.append(Finding.medium(
                f"GraphQL endpoint(s) discovered: "
                f"{len(graphql_endpoints)} found",
                description=(
                    "GraphQL endpoints may allow introspection queries "
                    "and data exfiltration"
                ),
                evidence=", ".join(sorted(graphql_endpoints)[:10]),
                remediation=(
                    "Disable GraphQL introspection in production. "
                    "Implement query depth/complexity limits."
                ),
                tags=["analysis", "api", "graphql", "javascript"],
            ))

        # WebSocket findings
        if websocket_urls:
            findings.append(Finding.low(
                f"WebSocket URL(s) discovered: "
                f"{len(websocket_urls)} found",
                description="WebSocket endpoints found in JavaScript source",
                evidence=", ".join(sorted(websocket_urls)[:10]),
                remediation=(
                    "Ensure WebSocket endpoints require authentication "
                    "and validate origin headers"
                ),
                tags=["analysis", "websocket", "javascript"],
            ))

        # Source map findings
        if verified_maps:
            findings.append(Finding.medium(
                f"Source maps accessible: {len(verified_maps)} .map files",
                description=(
                    "JavaScript source maps expose original source code, "
                    "making reverse engineering trivial"
                ),
                evidence=", ".join(verified_maps[:5]),
                remediation=(
                    "Remove source map files from production or restrict "
                    "access. Remove sourceMappingURL comments from JS."
                ),
                tags=["analysis", "sourcemap", "javascript"],
            ))

        # Framework config findings
        if framework_configs:
            findings.append(Finding.low(
                f"Framework configuration exposed: "
                f"{len(framework_configs)} configs found",
                description=(
                    "Frontend framework environment variables and "
                    "configuration found in JavaScript bundles"
                ),
                evidence=", ".join(
                    f"{c['framework']}: {c['snippet'][:60]}"
                    for c in framework_configs[:5]
                ),
                remediation=(
                    "Review exposed configuration for sensitive values. "
                    "Use server-side environment variables for secrets."
                ),
                tags=["analysis", "config", "javascript"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "api_paths": api_paths,
                "interesting_paths": interesting,
                "secrets_count": len(all_secrets),
                "graphql_endpoints": sorted(graphql_endpoints),
                "websocket_urls": sorted(websocket_urls),
                "source_maps": verified_maps,
                "framework_configs": framework_configs,
                "js_files_scanned": js_files_scanned,
            },
        )

    # ------------------------------------------------------------------
    # Extraction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_paths(content: str, paths: set[str]) -> None:
        """Extract API paths from JS content."""
        for pattern in _PATH_PATTERNS:
            for m in pattern.finditer(content):
                path = m.group(1).strip()
                if len(path) < 3 or len(path) > 200:
                    continue
                if any(skip in path for skip in _SKIP_PATTERNS):
                    continue
                # Normalize: remove trailing slash, query params
                path = path.split("?")[0].split("#")[0].rstrip("/")
                if path and path.startswith("/"):
                    paths.add(path)

    @staticmethod
    def _extract_secrets(
        content: str,
        all_secrets: list[dict],
        source: str,
    ) -> None:
        """Scan content for hardcoded secrets using regex patterns."""
        for sp in SECRET_REGISTRY:
            for m in sp.pattern.finditer(content):
                match_text = m.group(0).strip()
                # Skip very short matches (likely false positives)
                if len(match_text) < 8:
                    continue
                all_secrets.append({
                    "name": sp.name,
                    "severity": sp.severity.name.lower(),
                    "description": sp.description,
                    "match": match_text,
                    "source": (
                        source if len(source) <= 60
                        else "..." + source[-57:]
                    ),
                })

    @staticmethod
    def _extract_graphql(
        content: str, endpoints: set[str],
    ) -> None:
        """Extract GraphQL endpoint URLs."""
        for m in _GRAPHQL_RE.finditer(content):
            ep = m.group(1).strip()
            if len(ep) > 5 and "graphql" in ep.lower():
                endpoints.add(ep)

    @staticmethod
    def _extract_websockets(
        content: str, urls: set[str],
    ) -> None:
        """Extract WebSocket URLs."""
        for m in _WEBSOCKET_RE.finditer(content):
            ws_url = m.group(1).strip()
            if len(ws_url) > 6:
                urls.add(ws_url)

    @staticmethod
    def _extract_framework_config(
        content: str, configs: list[dict],
    ) -> None:
        """Extract frontend framework configuration."""
        # Angular environment object
        for m in _ANGULAR_ENV_RE.finditer(content):
            snippet = m.group(1).strip()
            if "production" in snippet or "apiUrl" in snippet.lower():
                configs.append({
                    "framework": "Angular",
                    "snippet": snippet[:200],
                })

        # React/Next.js/Vite environment variables
        for m in _REACT_ENV_RE.finditer(content):
            value = m.group(1).strip()
            if value and len(value) > 3:
                configs.append({
                    "framework": "React/Next/Vite",
                    "snippet": m.group(0)[:200],
                })

        # Vue.js environment variables
        for m in _VUE_CONFIG_RE.finditer(content):
            value = m.group(1).strip()
            if value and len(value) > 3:
                configs.append({
                    "framework": "Vue",
                    "snippet": m.group(0)[:200],
                })

        # Webpack public path (can reveal internal structure)
        for m in _WEBPACK_PUBLIC_PATH_RE.finditer(content):
            path = m.group(1).strip()
            if path and path != "/":
                configs.append({
                    "framework": "Webpack",
                    "snippet": f"__webpack_public_path__ = {path}",
                })

    @staticmethod
    def _check_source_map(content: str, js_url: str) -> str | None:
        """Check for sourceMappingURL in JS content.

        Returns the full source map URL if found, or None.
        """
        # Standard comment format
        m = re.search(
            r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)", content[-500:],
        )
        if not m:
            # Also check header-style (less common in content)
            m = re.search(
                r"/\*[#@]\s*sourceMappingURL\s*=\s*(\S+)\s*\*/",
                content[-500:],
            )
        if not m:
            return None

        map_ref = m.group(1).strip()

        # Skip data URIs (inline maps)
        if map_ref.startswith("data:"):
            return None

        # Resolve relative URLs
        if map_ref.startswith("http"):
            return map_ref
        if map_ref.startswith("//"):
            return f"https:{map_ref}"
        if map_ref.startswith("/"):
            # Need base from js_url
            from urllib.parse import urlparse
            parsed = urlparse(js_url)
            return f"{parsed.scheme}://{parsed.netloc}{map_ref}"

        # Relative to JS file location
        base = js_url.rsplit("/", 1)[0]
        return f"{base}/{map_ref}"
