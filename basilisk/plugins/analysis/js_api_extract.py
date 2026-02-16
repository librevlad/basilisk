"""JavaScript secrets and API endpoint extraction plugin.

Deep analysis of HTML pages and JavaScript bundles:
- Parses HTML: links, forms, data-attributes, iframes, preload/prefetch, internal IPs
- Parses JS: inline scripts, external bundles, webpack manifests, source maps
- Extracts: API endpoints, hardcoded secrets, framework configs, GraphQL, WebSocket
- All discovered paths feed into the attack surface map
"""

from __future__ import annotations

import logging
import re
from typing import ClassVar
from urllib.parse import urlparse

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target
from basilisk.utils.secrets import SECRET_REGISTRY, _is_false_positive

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# API endpoint extraction patterns (JS)
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

# Template literals: `/api/${resource}`
_TEMPLATE_RE = re.compile(r'`(/(?:api|v[1-9])[^`]{2,60})`')

# String concatenation: "/api" + "/users"
_CONCAT_RE = re.compile(
    r"""['"](/[a-zA-Z0-9_/-]+)['"]\s*\+\s*['"](/[a-zA-Z0-9_/-]+)['"]"""
)

# .json/.xml/.csv suffix paths
_JSON_SUFFIX_RE = re.compile(
    r"""['"`](/[a-zA-Z0-9_/-]+\.(?:json|xml|csv))['"`]"""
)

# ActionCable/Turbo channels
_CABLE_RE = re.compile(r"""['"]/(cable|turbo[_-]stream|ws|socket\.io)[/'"]""")

# Route definitions
_ROUTE_DEF_RE = re.compile(
    r"""(?:resources?\s+[:'"]+(\w+)|route\s*\(\s*['"]([^'"]+))""", re.I,
)

_PATH_PATTERNS = [
    _FETCH_RE, _API_PATH_RE, _VERSION_RE, _AJAX_RE,
    _XHR_RE, _ROUTER_RE, _ENDPOINT_RE, _FULL_URL_RE,
    _TEMPLATE_RE, _JSON_SUFFIX_RE,
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

# ---------------------------------------------------------------------------
# HTML deep-parsing patterns
# ---------------------------------------------------------------------------
_HREF_RE = re.compile(r'<a\s[^>]*href=["\']([^"\'#][^"\']*)["\']', re.I)
_FORM_RE = re.compile(r'<form\s([^>]*)>(.*?)</form>', re.I | re.DOTALL)
_FORM_ACTION_RE = re.compile(r'action=["\']([^"\']*)["\']', re.I)
_FORM_METHOD_RE = re.compile(r'method=["\']([^"\']*)["\']', re.I)
_INPUT_RE = re.compile(
    r'<input\s([^>]*)/?>', re.I,
)
_INPUT_NAME_RE = re.compile(r'name=["\']([^"\']*)["\']', re.I)
_INPUT_TYPE_RE = re.compile(r'type=["\']([^"\']*)["\']', re.I)
_INPUT_VALUE_RE = re.compile(r'value=["\']([^"\']*)["\']', re.I)
_DATA_URL_RE = re.compile(
    r'data-(?:url|api|endpoint|action|href|src|path|route)'
    r'=["\']([^"\']+)["\']', re.I,
)
_LINK_PREFETCH_RE = re.compile(
    r'<link\s[^>]*rel=["\'](?:prefetch|preload|preconnect|dns-prefetch)'
    r'["\'][^>]*href=["\']([^"\']+)["\']', re.I,
)
_IFRAME_RE = re.compile(r'<iframe\s[^>]*src=["\']([^"\']+)["\']', re.I)

# Internal IP detection (RFC 1918 + loopback + link-local)
_INTERNAL_IP_RE = re.compile(
    r'\b('
    r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
    r'|192\.168\.\d{1,3}\.\d{1,3}'
    r'|127\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r')\b'
)
# Also catch http://internal-host patterns
_INTERNAL_URL_RE = re.compile(
    r"""['"`](https?://(?:"""
    r"""10\.\d{1,3}\.\d{1,3}\.\d{1,3}"""
    r"""|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"""
    r"""|192\.168\.\d{1,3}\.\d{1,3}"""
    r"""|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"""
    r"""|localhost"""
    r""")[^'"`]*)['"`]""", re.I,
)

# CSRF token field names
_CSRF_NAMES = {
    "csrf", "csrf_token", "csrftoken", "csrfmiddlewaretoken",
    "_token", "authenticity_token", "__requestverificationtoken",
    "antiforgery", "__antiforgerytoken", "xsrf", "xsrf_token",
}

# Manifest paths for chunk autodiscovery
_MANIFEST_PATHS = [
    "/asset-manifest.json",
    "/build-manifest.json",
    "/_next/static/chunks/webpack.js",
    "/webpack-manifest.json",
    "/manifest.json",
    "/stats.json",
    "/static/js/manifest.json",
    "/vite-manifest.json",
    "/.vite/manifest.json",
]

# Extra pages to scan
_EXTRA_PAGES = [
    "/login", "/signin", "/register", "/signup",
    "/dashboard", "/admin", "/app",
    "/api", "/docs",
]


def _extract_js_from_manifest(data: dict | list, base_url: str) -> list[str]:
    """Extract .js URLs from a structured webpack/Vite manifest."""
    urls: list[str] = []

    def _collect(obj: object) -> None:
        if isinstance(obj, str):
            if obj.endswith(".js") and len(obj) > 3:
                if obj.startswith("http"):
                    urls.append(obj)
                elif obj.startswith("/"):
                    urls.append(f"{base_url}{obj}")
                else:
                    urls.append(f"{base_url}/{obj}")
        elif isinstance(obj, dict):
            for v in obj.values():
                _collect(v)
        elif isinstance(obj, list):
            for v in obj:
                _collect(v)

    _collect(data)
    return urls


def _normalize_path(raw: str) -> str | None:
    """Normalize a raw URL/path to a clean /-prefixed path, or None."""
    if not raw or len(raw) < 2 or len(raw) > 300:
        return None
    p = raw.split("?")[0].split("#")[0].rstrip("/")
    if not p:
        return None
    if p.startswith("/"):
        if any(skip in p for skip in _SKIP_PATTERNS):
            return None
        return p
    return None


class JsApiExtractPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="js_api_extract",
        display_name="JS & HTML Deep Extractor",
        category=PluginCategory.ANALYSIS,
        description=(
            "Deep analysis of HTML pages and JavaScript bundles: "
            "extracts API endpoints, forms, links, data-attributes, "
            "secrets, framework configs, source maps, internal IPs"
        ),
        produces=["js_api_paths", "js_secrets"],
        timeout=60.0,
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
        webpack_detected = False
        seen_js_urls: set[str] = set()
        all_forms: list[dict] = []
        all_internal_ips: set[str] = set()
        all_internal_urls: set[str] = set()
        pages_scanned = 0

        # ── Fetch + deep-parse main page ──
        main_body = ""
        try:
            async with ctx.rate:
                resp = await ctx.http.get(f"{base_url}/", timeout=10.0)
                if resp.status == 200:
                    main_body = await resp.text(
                        encoding="utf-8", errors="replace",
                    )
                    pages_scanned += 1
                    self._process_html_deep(
                        main_body, base_url, "/", target.host,
                        js_urls, all_paths, all_secrets,
                        graphql_endpoints, websocket_urls,
                        framework_configs, all_forms,
                        all_internal_ips, all_internal_urls,
                    )
                    if "webpack" in main_body.lower() or "__webpack" in main_body:
                        webpack_detected = True
        except Exception as e:
            logger.debug("js_api_extract: main page fetch failed: %s", e)

        # ── Multi-page scan: fetch extra pages + deep-parse HTML ──
        for page_path in _EXTRA_PAGES:
            if ctx.should_stop:
                break
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(
                        f"{base_url}{page_path}", timeout=8.0,
                    )
                    if resp.status != 200:
                        continue
                    ct = resp.headers.get("content-type", "")
                    if "text/html" not in ct:
                        continue
                    page_body = await resp.text(
                        encoding="utf-8", errors="replace",
                    )
                    pages_scanned += 1
                    self._process_html_deep(
                        page_body, base_url, page_path, target.host,
                        js_urls, all_paths, all_secrets,
                        graphql_endpoints, websocket_urls,
                        framework_configs, all_forms,
                        all_internal_ips, all_internal_urls,
                    )
            except Exception as e:
                logger.debug("js_api_extract: page %s failed: %s", page_path, e)
                continue

        # ── Manifest autodiscovery ──
        manifest_chunks = await self._discover_chunks_from_manifests(
            base_url, ctx,
        )
        for chunk_url in manifest_chunks:
            if chunk_url not in seen_js_urls:
                js_urls.append(chunk_url)

        # Deduplicate JS URLs preserving order
        deduped_js_urls: list[str] = []
        for u in js_urls:
            if u not in seen_js_urls:
                seen_js_urls.add(u)
                deduped_js_urls.append(u)

        # ── Scan external JS files (limit 50) ──
        domain = target.host
        for js_url in deduped_js_urls[:50]:
            if ctx.should_stop:
                break
            if domain not in js_url and not js_url.startswith(base_url):
                continue
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(js_url, timeout=15.0)
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
                    self._extract_concat_paths(content, all_paths)
                    self._extract_secrets(content, all_secrets, js_url)
                    self._extract_graphql(content, graphql_endpoints)
                    self._extract_websockets(content, websocket_urls)
                    self._extract_framework_config(
                        content, framework_configs,
                    )
                    self._extract_internal_ips(
                        content, all_internal_ips, all_internal_urls,
                    )

                    sm = self._check_source_map(content, js_url)
                    if sm:
                        source_maps.append(sm)

                    if "webpack" in content[:2000].lower():
                        webpack_detected = True
            except Exception as e:
                logger.debug("js_api_extract: JS file %s failed: %s", js_url, e)
                continue

        # ── Common JS bundle paths ──
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
            full_url = f"{base_url}{bp}"
            if full_url in seen_js_urls:
                continue
            seen_js_urls.add(full_url)
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(full_url, timeout=10.0)
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
                    self._extract_concat_paths(content, all_paths)
                    self._extract_secrets(content, all_secrets, full_url)
                    self._extract_graphql(content, graphql_endpoints)
                    self._extract_websockets(content, websocket_urls)
                    self._extract_framework_config(
                        content, framework_configs,
                    )
                    self._extract_internal_ips(
                        content, all_internal_ips, all_internal_urls,
                    )

                    sm = self._check_source_map(content, full_url)
                    if sm:
                        source_maps.append(sm)
            except Exception as e:
                logger.debug("js_api_extract: bundle %s failed: %s", bp, e)
                continue

        # ── Source maps — GET and extract paths ──
        verified_maps: list[str] = []
        for map_url in source_maps[:5]:
            if ctx.should_stop:
                break
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(map_url, timeout=15.0)
                    if resp.status != 200:
                        continue
                    verified_maps.append(map_url)
                    ct = resp.headers.get("content-type", "")
                    if "json" in ct or map_url.endswith(".map"):
                        try:
                            data = await resp.json()
                        except Exception as e:
                            logger.debug("js_api_extract: sourcemap JSON parse failed: %s", e)
                            continue
                        self._extract_paths_from_sourcemap(
                            data, all_paths,
                        )
            except Exception as e:
                logger.debug("js_api_extract: sourcemap %s failed: %s", map_url, e)
                continue

        # ══════════════════════════════════════════════════════════
        # Generate findings
        # ══════════════════════════════════════════════════════════

        # Secrets
        if all_secrets:
            seen_sec: set[tuple[str, str]] = set()
            unique_secrets: list[dict] = []
            for s in all_secrets:
                key = (s["name"], s["match"][:40])
                if key not in seen_sec:
                    seen_sec.add(key)
                    unique_secrets.append(s)

            for secret in unique_secrets[:20]:
                factory = getattr(Finding, secret["severity"])
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

        # Probe discovered API paths to get status codes
        api_paths = sorted(all_paths)
        probed: dict[str, int] = {}
        if api_paths and not ctx.should_stop:
            from basilisk.utils.batch_check import batch_head_check

            probe_urls = [f"{base_url}{p}" for p in api_paths[:100]]
            results = await batch_head_check(
                ctx.http, probe_urls, ctx.rate,
                concurrency=10, timeout=5.0,
                valid_statuses={200, 201, 204, 301, 302, 307, 308,
                                400, 401, 403, 404, 405, 500},
            )
            for url, status, _size in results:
                path = url.replace(base_url, "", 1)
                probed[path] = status

        interesting = [
            p for p in api_paths
            if any(p.startswith(px) for px in _INTERESTING_PREFIXES)
        ]

        # Format paths with status codes for evidence
        def _fmt(p: str) -> str:
            s = probed.get(p, 0)
            return f"{p} [{s}]" if s else p

        probed_count = sum(1 for p in api_paths if probed.get(p, 0))
        live_count = sum(
            1 for p in api_paths
            if probed.get(p, 0) in (200, 201, 204, 301, 302)
        )

        if interesting:
            findings.append(Finding.medium(
                f"Deep extraction: {len(interesting)} sensitive endpoints "
                f"from {pages_scanned} pages + {js_files_scanned} JS files"
                f" ({live_count}/{probed_count} probed live)",
                description=(
                    "Sensitive API/admin paths extracted from HTML and "
                    "JavaScript analysis across multiple pages"
                ),
                evidence=", ".join(_fmt(p) for p in interesting[:15]),
                remediation=(
                    "Review exposed API endpoints for authorization "
                    "requirements and rate limiting"
                ),
                tags=["analysis", "api", "javascript"],
            ))
        elif api_paths:
            findings.append(Finding.info(
                f"Deep extraction: {len(api_paths)} paths from "
                f"{pages_scanned} pages + {js_files_scanned} JS files"
                f" ({live_count}/{probed_count} probed live)",
                evidence=", ".join(_fmt(p) for p in api_paths[:10]),
                tags=["analysis", "api", "javascript"],
            ))
        else:
            findings.append(Finding.info(
                f"No paths found in {pages_scanned} pages + "
                f"{js_files_scanned} JS sources",
                tags=["analysis", "api", "javascript"],
            ))

        # Forms without CSRF
        no_csrf_forms = [f for f in all_forms if not f["has_csrf"] and f["method"] == "POST"]
        if no_csrf_forms:
            evidence_lines = [
                f"POST {f['action']} (page: {f['page']})"
                for f in no_csrf_forms[:5]
            ]
            findings.append(Finding.medium(
                f"{len(no_csrf_forms)} POST form(s) without CSRF token",
                description=(
                    "Forms using POST method without a CSRF protection "
                    "token are vulnerable to cross-site request forgery"
                ),
                evidence="; ".join(evidence_lines),
                remediation=(
                    "Add CSRF tokens to all state-changing forms. "
                    "Use framework CSRF middleware."
                ),
                tags=["analysis", "csrf", "forms"],
            ))

        # Forms posting to HTTP
        http_forms = [
            f for f in all_forms
            if f["action"].startswith("http://")
        ]
        if http_forms:
            findings.append(Finding.high(
                f"{len(http_forms)} form(s) submit to HTTP (not HTTPS)",
                description=(
                    "Form data is transmitted over unencrypted HTTP, "
                    "exposing credentials and user data to interception"
                ),
                evidence="; ".join(
                    f"{f['method']} {f['action']}" for f in http_forms[:5]
                ),
                remediation="Change all form actions to use HTTPS.",
                tags=["analysis", "forms", "http"],
            ))

        # Hidden fields with sensitive names
        sensitive_hidden = []
        for f in all_forms:
            for inp in f.get("inputs", []):
                if inp["type"] == "hidden" and inp.get("value"):
                    name_lower = inp["name"].lower()
                    if any(kw in name_lower for kw in (
                        "password", "secret", "key", "token",
                        "api_key", "apikey", "private",
                    )):
                        sensitive_hidden.append(
                            f"{inp['name']}={inp['value'][:20]}... "
                            f"(form: {f['action']})"
                        )
        if sensitive_hidden:
            findings.append(Finding.medium(
                f"{len(sensitive_hidden)} hidden field(s) with sensitive values",
                description=(
                    "Hidden form fields contain values that appear to be "
                    "secrets, tokens or API keys exposed in page source"
                ),
                evidence="; ".join(sensitive_hidden[:5]),
                remediation=(
                    "Do not embed secrets in hidden form fields. "
                    "Use server-side session storage instead."
                ),
                tags=["analysis", "forms", "secrets"],
            ))

        # Internal IPs exposed
        if all_internal_ips:
            findings.append(Finding.low(
                f"Internal IP addresses exposed: "
                f"{len(all_internal_ips)} found in HTML/JS",
                description=(
                    "Private/internal IP addresses (RFC 1918) found in "
                    "HTML source or JavaScript bundles reveal internal "
                    "network structure"
                ),
                evidence=", ".join(sorted(all_internal_ips)[:10]),
                remediation=(
                    "Remove internal IP addresses from client-facing code. "
                    "Use hostnames or environment variables instead."
                ),
                tags=["analysis", "disclosure", "internal-ip"],
            ))

        if all_internal_urls:
            findings.append(Finding.medium(
                f"Internal URLs exposed: {len(all_internal_urls)} found",
                description=(
                    "Full URLs pointing to internal services (localhost, "
                    "private IPs) found in client-side code. These reveal "
                    "internal architecture and may enable SSRF attacks."
                ),
                evidence=", ".join(sorted(all_internal_urls)[:5]),
                remediation=(
                    "Remove internal URLs from client-side code. "
                    "Proxy through the public API instead."
                ),
                tags=["analysis", "disclosure", "ssrf"],
            ))

        # GraphQL
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

        # WebSocket
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

        # Source maps
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

        # Framework configs
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

        # ── Build result data for attack surface ──
        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "api_paths": api_paths,
                "api_endpoints": [
                    {"path": p, "status": probed.get(p, 0), "source": "js"}
                    for p in api_paths
                ],
                "interesting_paths": interesting,
                "found_paths": [
                    {"path": p, "status": probed.get(p, 0), "source": "js"}
                    for p in api_paths
                ],
                "forms": all_forms,
                "internal_ips": sorted(all_internal_ips),
                "internal_urls": sorted(all_internal_urls),
                "secrets_count": len(all_secrets),
                "graphql_endpoints": sorted(graphql_endpoints),
                "websocket_urls": sorted(websocket_urls),
                "source_maps": verified_maps,
                "framework_configs": framework_configs,
                "js_files_scanned": js_files_scanned,
                "pages_scanned": pages_scanned,
                "webpack_detected": webpack_detected,
            },
        )

    # ==================================================================
    # Deep HTML processing — parse EVERYTHING from the page
    # ==================================================================

    def _process_html_deep(
        self,
        html: str,
        base_url: str,
        page_path: str,
        host: str,
        js_urls: list[str],
        all_paths: set[str],
        all_secrets: list[dict],
        graphql_endpoints: set[str],
        websocket_urls: set[str],
        framework_configs: list[dict],
        all_forms: list[dict],
        all_internal_ips: set[str],
        all_internal_urls: set[str],
    ) -> None:
        """Deep-parse an HTML page: scripts, links, forms, data-attrs, etc."""

        # ── 1. Inline scripts (existing) ──
        for m in re.finditer(
            r'<script[^>]*>(.*?)</script>',
            html, re.DOTALL | re.IGNORECASE,
        ):
            script_content = m.group(1)
            if len(script_content.strip()) < 10:
                continue
            self._extract_paths(script_content, all_paths)
            self._extract_concat_paths(script_content, all_paths)
            self._extract_secrets(script_content, all_secrets, "inline")
            self._extract_graphql(script_content, graphql_endpoints)
            self._extract_websockets(script_content, websocket_urls)
            self._extract_framework_config(script_content, framework_configs)
            self._extract_internal_ips(
                script_content, all_internal_ips, all_internal_urls,
            )

        # ── 2. External JS URLs ──
        for m in re.finditer(
            r'<script[^>]+src=["\']([^"\']+)["\']',
            html, re.IGNORECASE,
        ):
            src = m.group(1)
            if src.startswith("//"):
                js_urls.append(f"https:{src}")
            elif src.startswith("/"):
                js_urls.append(f"{base_url}{src}")
            elif src.startswith("http"):
                js_urls.append(src)

        # ── 3. <a href> links → paths ──
        for m in _HREF_RE.finditer(html):
            href = m.group(1).strip()
            path = self._resolve_to_path(href, base_url, host)
            if path:
                all_paths.add(path)

        # ── 4. <form> elements → forms + paths ──
        for m in _FORM_RE.finditer(html):
            form_attrs = m.group(1)
            form_body = m.group(2)
            form_info = self._parse_form(
                form_attrs, form_body, base_url, page_path,
            )
            all_forms.append(form_info)
            # Add form action as a path
            action_path = _normalize_path(form_info["action"])
            if action_path:
                all_paths.add(action_path)

        # ── 5. data-* attributes with URLs ──
        for m in _DATA_URL_RE.finditer(html):
            val = m.group(1).strip()
            path = self._resolve_to_path(val, base_url, host)
            if path:
                all_paths.add(path)

        # ── 6. <link rel=prefetch/preload> ──
        for m in _LINK_PREFETCH_RE.finditer(html):
            href = m.group(1).strip()
            path = self._resolve_to_path(href, base_url, host)
            if path:
                all_paths.add(path)

        # ── 7. <iframe src> ──
        for m in _IFRAME_RE.finditer(html):
            src = m.group(1).strip()
            path = self._resolve_to_path(src, base_url, host)
            if path:
                all_paths.add(path)

        # ── 8. Internal IPs in the whole HTML ──
        self._extract_internal_ips(
            html, all_internal_ips, all_internal_urls,
        )

    # ==================================================================
    # Form parsing
    # ==================================================================

    @staticmethod
    def _parse_form(
        attrs: str, body: str, base_url: str, page_path: str,
    ) -> dict:
        """Parse a <form> tag into structured data."""
        action_m = _FORM_ACTION_RE.search(attrs)
        raw_action = action_m.group(1).strip() if action_m else ""
        if not raw_action or raw_action == "#":
            action = page_path
        elif raw_action.startswith("/") or raw_action.startswith("http"):
            action = raw_action
        else:
            action = f"{page_path.rsplit('/', 1)[0]}/{raw_action}"

        method_m = _FORM_METHOD_RE.search(attrs)
        method = (method_m.group(1).upper() if method_m else "GET")

        inputs: list[dict] = []
        has_csrf = False
        has_password = False
        has_file_upload = False

        for inp_m in _INPUT_RE.finditer(body):
            inp_attrs = inp_m.group(1)
            name_m = _INPUT_NAME_RE.search(inp_attrs)
            type_m = _INPUT_TYPE_RE.search(inp_attrs)
            value_m = _INPUT_VALUE_RE.search(inp_attrs)

            name = name_m.group(1) if name_m else ""
            itype = (type_m.group(1).lower() if type_m else "text")
            value = value_m.group(1) if value_m else ""

            if name:
                inputs.append({
                    "name": name,
                    "type": itype,
                    "value": value if itype == "hidden" else "",
                })

            if name.lower() in _CSRF_NAMES:
                has_csrf = True
            if itype == "password":
                has_password = True
            if itype == "file":
                has_file_upload = True

        return {
            "action": action,
            "method": method,
            "page": page_path,
            "inputs": inputs,
            "has_csrf": has_csrf,
            "has_password": has_password,
            "has_file_upload": has_file_upload,
            "input_count": len(inputs),
        }

    # ==================================================================
    # Path resolution
    # ==================================================================

    @staticmethod
    def _resolve_to_path(
        raw: str, base_url: str, host: str,
    ) -> str | None:
        """Resolve a raw href/src to a local path, or None if external."""
        if not raw or raw.startswith("#") or raw.startswith("javascript:"):
            return None
        if raw.startswith("mailto:") or raw.startswith("tel:"):
            return None

        if raw.startswith("/"):
            return _normalize_path(raw)

        if raw.startswith("http"):
            try:
                parsed = urlparse(raw)
                if parsed.hostname and (
                    parsed.hostname == host
                    or parsed.hostname.endswith(f".{host}")
                ):
                    return _normalize_path(parsed.path or "/")
            except Exception as e:
                logger.debug("js_api_extract: URL parse failed for %s: %s", raw[:80], e)
            return None

        # Relative path — skip
        return None

    # ==================================================================
    # Internal IP extraction
    # ==================================================================

    @staticmethod
    def _extract_internal_ips(
        content: str,
        ips: set[str],
        urls: set[str],
    ) -> None:
        """Extract RFC 1918 IPs and internal URLs from content."""
        for m in _INTERNAL_IP_RE.finditer(content):
            ips.add(m.group(1))

        for m in _INTERNAL_URL_RE.finditer(content):
            urls.add(m.group(1))

    # ==================================================================
    # Manifest autodiscovery
    # ==================================================================

    async def _discover_chunks_from_manifests(
        self, base_url: str, ctx,
    ) -> list[str]:
        """Parse webpack/Vite manifests to discover JS chunk URLs."""
        chunk_urls: list[str] = []
        for path in _MANIFEST_PATHS:
            if ctx.should_stop:
                break
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(
                        f"{base_url}{path}", timeout=8.0,
                    )
                    if resp.status != 200:
                        continue
                    try:
                        data = await resp.json()
                        chunk_urls.extend(
                            _extract_js_from_manifest(data, base_url),
                        )
                    except Exception as e:
                        logger.debug("js_api_extract: manifest JSON parse failed: %s", e)
                        text = await resp.text(
                            encoding="utf-8", errors="replace",
                        )
                        for m in re.finditer(
                            r'["\']([^"\']*\.js)["\']', text,
                        ):
                            js_ref = m.group(1)
                            if js_ref.startswith("http"):
                                chunk_urls.append(js_ref)
                            elif js_ref.startswith("/"):
                                chunk_urls.append(f"{base_url}{js_ref}")
                            elif not js_ref.startswith("data:"):
                                chunk_urls.append(f"{base_url}/{js_ref}")
            except Exception as e:
                logger.debug("js_api_extract: manifest %s failed: %s", path, e)
                continue
        return chunk_urls

    # ==================================================================
    # Source map content extraction
    # ==================================================================

    @staticmethod
    def _extract_paths_from_sourcemap(
        data: dict, paths: set[str],
    ) -> None:
        """Extract API paths from source map content."""
        for source_content in data.get("sourcesContent", []):
            if not source_content:
                continue
            for pattern in _PATH_PATTERNS:
                for m in pattern.finditer(source_content):
                    path = m.group(1).strip()
                    if len(path) < 3 or len(path) > 200:
                        continue
                    if any(skip in path for skip in _SKIP_PATTERNS):
                        continue
                    path = path.split("?")[0].split("#")[0].rstrip("/")
                    if path and path.startswith("/"):
                        paths.add(path)

        for source_name in data.get("sources", []):
            if not source_name:
                continue
            for prefix in ("/api/", "/routes/", "/services/", "/endpoints/"):
                if prefix in source_name:
                    idx = source_name.index(prefix)
                    api_path = source_name[idx:].split("?")[0].rstrip("/")
                    if api_path and len(api_path) > 3:
                        paths.add(api_path)
                    break

    # ==================================================================
    # JS extraction helpers
    # ==================================================================

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
                path = path.split("?")[0].split("#")[0].rstrip("/")
                if path and path.startswith("/"):
                    paths.add(path)

    @staticmethod
    def _extract_concat_paths(content: str, paths: set[str]) -> None:
        """Extract paths from string concatenation and special patterns."""
        for m in _CONCAT_RE.finditer(content):
            combined = m.group(1) + m.group(2)
            if (
                len(combined) > 3
                and combined.startswith("/")
                and not any(skip in combined for skip in _SKIP_PATTERNS)
            ):
                paths.add(combined.rstrip("/"))

        for m in _CABLE_RE.finditer(content):
            paths.add(f"/{m.group(1)}")

        for m in _ROUTE_DEF_RE.finditer(content):
            resource = m.group(1) or m.group(2)
            if resource:
                path = "/" + resource.replace(".", "/")
                if len(path) > 2 and not any(
                    skip in path for skip in _SKIP_PATTERNS
                ):
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
                if len(match_text) < 8:
                    continue
                if _is_false_positive(match_text):
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
        for m in _ANGULAR_ENV_RE.finditer(content):
            snippet = m.group(1).strip()
            if "production" in snippet or "apiUrl" in snippet.lower():
                configs.append({
                    "framework": "Angular",
                    "snippet": snippet[:200],
                })

        for m in _REACT_ENV_RE.finditer(content):
            value = m.group(1).strip()
            if value and len(value) > 3:
                configs.append({
                    "framework": "React/Next/Vite",
                    "snippet": m.group(0)[:200],
                })

        for m in _VUE_CONFIG_RE.finditer(content):
            value = m.group(1).strip()
            if value and len(value) > 3:
                configs.append({
                    "framework": "Vue",
                    "snippet": m.group(0)[:200],
                })

        for m in _WEBPACK_PUBLIC_PATH_RE.finditer(content):
            path = m.group(1).strip()
            if path and path != "/":
                configs.append({
                    "framework": "Webpack",
                    "snippet": f"__webpack_public_path__ = {path}",
                })

    @staticmethod
    def _check_source_map(content: str, js_url: str) -> str | None:
        """Check for sourceMappingURL in JS content."""
        m = re.search(
            r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)", content[-500:],
        )
        if not m:
            m = re.search(
                r"/\*[#@]\s*sourceMappingURL\s*=\s*(\S+)\s*\*/",
                content[-500:],
            )
        if not m:
            return None

        map_ref = m.group(1).strip()

        if map_ref.startswith("data:"):
            return None

        if map_ref.startswith("http"):
            return map_ref
        if map_ref.startswith("//"):
            return f"https:{map_ref}"
        if map_ref.startswith("/"):
            parsed = urlparse(js_url)
            return f"{parsed.scheme}://{parsed.netloc}{map_ref}"

        base = js_url.rsplit("/", 1)[0]
        return f"{base}/{map_ref}"
