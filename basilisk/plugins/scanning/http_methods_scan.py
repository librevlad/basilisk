"""HTTP methods scanner — comprehensive method detection with risk analysis."""

from __future__ import annotations

from typing import Any, ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target
from basilisk.utils.http_check import resolve_base_url

# All HTTP methods to test
_ALL_METHODS = [
    "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE",
    "CONNECT",
    # WebDAV
    "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK",
]

_DANGEROUS_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT"}
_WEBDAV_METHODS = {"PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"}

# Method override headers to test
_OVERRIDE_HEADERS = [
    "X-HTTP-Method-Override",
    "X-Method-Override",
    "X-HTTP-Method",
]


class HttpMethodsScanPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="http_methods_scan",
        display_name="HTTP Methods Scanner",
        category=PluginCategory.SCANNING,
        description="Detects allowed HTTP methods including dangerous ones",
        produces=["http_methods"],
        timeout=30.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        findings: list[Finding] = []
        data: dict[str, Any] = {}

        base_url = await resolve_base_url(target.host, ctx)
        if not base_url:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info(
                    "Host not reachable via HTTP/HTTPS",
                    tags=["scanning", "http-methods"],
                )],
                data={"methods": []},
            )

        # ---- 1. OPTIONS Allow header ----
        options_methods: list[str] = []
        options_headers: dict[str, str] = {}
        try:
            async with ctx.rate:
                resp = await ctx.http.request("OPTIONS", f"{base_url}/", timeout=8.0)
                allow_header = resp.headers.get("Allow", "")
                options_headers = dict(resp.headers)
                if allow_header:
                    options_methods = [
                        m.strip().upper() for m in allow_header.split(",")
                    ]
        except Exception:
            pass

        data["options_allow"] = options_methods
        data["options_headers"] = options_headers

        # ---- 2. Active method probing ----
        active_methods: dict[str, dict] = {}
        for method in _ALL_METHODS:
            if ctx.should_stop:
                break
            try:
                async with ctx.rate:
                    resp = await ctx.http.request(
                        method, f"{base_url}/", timeout=5.0,
                    )
                    status = resp.status
                    # Method is "allowed" only for success statuses
                    # 403 = forbidden (server blocks it, NOT a vulnerability)
                    # 405/501 = method not supported
                    allowed = status in (200, 201, 204, 207, 301, 302, 307, 308)
                    active_methods[method] = {
                        "status": status,
                        "allowed": allowed,
                    }
            except Exception:
                active_methods[method] = {"status": 0, "allowed": False}

        data["active_probe"] = active_methods
        allowed_active = [m for m, v in active_methods.items() if v.get("allowed")]
        data["methods"] = sorted(set(options_methods) | set(allowed_active))

        # ---- 3. TRACE detection (XST) ----
        if not ctx.should_stop:
            trace_finding = await self._check_trace(base_url, ctx)
            if trace_finding:
                findings.append(trace_finding)

        # ---- 4. PUT / DELETE risk assessment ----
        if not ctx.should_stop:
            put_del_findings = await self._check_put_delete(
                base_url, active_methods, ctx
            )
            findings.extend(put_del_findings)

        # ---- 5. CONNECT proxy test ----
        if not ctx.should_stop:
            connect_finding = await self._check_connect(base_url, active_methods, ctx)
            if connect_finding:
                findings.append(connect_finding)

        # ---- 6. WebDAV method detection ----
        if not ctx.should_stop:
            webdav_findings = self._check_webdav(active_methods, options_methods)
            findings.extend(webdav_findings)

        # ---- 7. Method override headers ----
        if not ctx.should_stop:
            override_findings = await self._check_method_overrides(base_url, ctx)
            findings.extend(override_findings)
            data["override_headers"] = [
                h for h in _OVERRIDE_HEADERS
                if any(f"override: {h}" in str(f.evidence).lower() for f in override_findings)
            ]

        # ---- 8. CORS pre-flight (OPTIONS) analysis ----
        if not ctx.should_stop:
            preflight_findings = await self._check_cors_preflight(
                base_url, options_headers, ctx
            )
            findings.extend(preflight_findings)

        # ---- 9. HTTP method tampering (_method parameter) ----
        if not ctx.should_stop:
            tamper_findings = await self._check_method_tampering(base_url, ctx)
            findings.extend(tamper_findings)

        # ---- Summary ----
        all_allowed = sorted(data.get("methods", []))
        if all_allowed and not any(
            f.severity.value >= 2 for f in findings
        ):
            findings.append(Finding.info(
                f"Allowed methods: {', '.join(all_allowed)}",
                tags=["scanning", "http-methods"],
            ))
        elif not all_allowed:
            findings.append(Finding.info(
                "OPTIONS not supported or no Allow header; "
                "active probing completed",
                tags=["scanning", "http-methods"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data=data,
        )

    # ================================================================
    # Individual checks
    # ================================================================

    async def _check_trace(self, base_url: str, ctx: Any) -> Finding | None:
        """Detect TRACE method and verify XST by checking body reflection."""
        try:
            async with ctx.rate:
                resp = await ctx.http.request(
                    "TRACE", f"{base_url}/",
                    headers={"X-Custom-Trace-Test": "basilisk-xst-check"},
                    timeout=5.0,
                )
                if resp.status == 200:
                    body = await resp.text()
                    if "basilisk-xst-check" in body:
                        return Finding.high(
                            "TRACE method enabled — XST confirmed",
                            description=(
                                "TRACE reflects request headers in the response body, "
                                "allowing Cross-Site Tracing (XST) to steal "
                                "HttpOnly cookies via XSS"
                            ),
                            evidence=f"HTTP {resp.status}: body contains reflected header",
                            remediation="Disable TRACE method on the web server",
                            tags=[
                                "scanning", "http-methods", "trace", "xst",
                                "owasp:a05",
                            ],
                        )
                    else:
                        return Finding.medium(
                            "TRACE method enabled (no body reflection confirmed)",
                            description=(
                                "TRACE returns 200 but does not appear to "
                                "reflect headers; still recommended to disable"
                            ),
                            evidence=f"HTTP {resp.status}",
                            remediation="Disable TRACE method on the web server",
                            tags=["scanning", "http-methods", "trace"],
                        )
                elif resp.status not in (405, 501):
                    return Finding.low(
                        f"TRACE returns unexpected status: {resp.status}",
                        evidence=f"HTTP {resp.status}",
                        remediation="Disable TRACE method on the web server",
                        tags=["scanning", "http-methods", "trace"],
                    )
        except Exception:
            pass
        return None

    async def _check_put_delete(
        self, base_url: str, active_methods: dict, ctx: Any,
    ) -> list[Finding]:
        """Assess risk of PUT and DELETE methods."""
        findings: list[Finding] = []

        for method in ("PUT", "DELETE"):
            info = active_methods.get(method, {})
            if not info.get("allowed"):
                continue

            status = info.get("status", 0)

            # Try PUT with a harmless test to see if it actually writes
            if method == "PUT":
                try:
                    test_path = f"{base_url}/.basilisk_method_test_{method.lower()}"
                    test_body = "basilisk-put-verify-38668"
                    async with ctx.rate:
                        resp = await ctx.http.request(
                            "PUT", test_path,
                            data=test_body,
                            headers={"Content-Type": "text/plain"},
                            timeout=5.0,
                        )
                        if resp.status in (200, 201, 204):
                            # Verify: GET the file back to confirm it was stored
                            verified = False
                            try:
                                async with ctx.rate:
                                    get_resp = await ctx.http.get(
                                        test_path, timeout=5.0,
                                    )
                                    if get_resp.status == 200:
                                        content = await get_resp.text()
                                        if test_body in content:
                                            verified = True
                            except Exception:
                                pass
                            # Clean up: try DELETE
                            try:
                                async with ctx.rate:
                                    await ctx.http.request(
                                        "DELETE", test_path, timeout=3.0,
                                    )
                            except Exception:
                                pass
                            if verified:
                                findings.append(Finding.critical(
                                    f"{method} method allows file upload",
                                    description=(
                                        f"Server accepted {method}, returned "
                                        f"HTTP {resp.status}, and GET confirmed "
                                        "the file was stored — arbitrary file "
                                        "upload possible"
                                    ),
                                    evidence=(
                                        f"PUT {test_path} -> HTTP {resp.status}, "
                                        f"GET {test_path} -> content verified"
                                    ),
                                    remediation=(
                                        f"Disable {method} or restrict to "
                                        "authenticated API endpoints only"
                                    ),
                                    tags=[
                                        "scanning", "http-methods", method.lower(),
                                        "file-upload", "owasp:a01",
                                    ],
                                ))
                            else:
                                findings.append(Finding.info(
                                    f"{method} accepted but file not persisted",
                                    evidence=(
                                        f"PUT {test_path} -> HTTP {resp.status}, "
                                        "but GET did not return the content"
                                    ),
                                    tags=["scanning", "http-methods", method.lower()],
                                ))
                            continue
                except Exception:
                    pass

            sev = "high" if status in (200, 201, 204) else "medium"
            findings.append(getattr(Finding, sev)(
                f"{method} method enabled (HTTP {status})",
                description=(
                    f"{method} may allow unauthorized resource modification "
                    f"or deletion"
                ),
                evidence=f"{method} / -> HTTP {status}",
                remediation=(
                    f"Disable {method} unless required by the API; "
                    "ensure proper authentication"
                ),
                tags=["scanning", "http-methods", method.lower()],
            ))

        return findings

    async def _check_connect(
        self, base_url: str, active_methods: dict, ctx: Any,
    ) -> Finding | None:
        """Check if CONNECT is enabled (open proxy)."""
        info = active_methods.get("CONNECT", {})
        if info.get("allowed") and info.get("status") in (200, 0):
            return Finding.high(
                "CONNECT method enabled — potential open proxy",
                description=(
                    "CONNECT allows tunneling TCP connections through the "
                    "server, which could be abused as an open proxy"
                ),
                evidence=f"CONNECT / -> HTTP {info.get('status', '?')}",
                remediation="Disable CONNECT method on the web server",
                tags=["scanning", "http-methods", "connect", "proxy", "owasp:a05"],
            )
        return None

    def _check_webdav(
        self, active_methods: dict, options_methods: list[str],
    ) -> list[Finding]:
        """Detect WebDAV methods from active probing and OPTIONS."""
        findings: list[Finding] = []

        webdav_active = {
            m for m in _WEBDAV_METHODS
            if active_methods.get(m, {}).get("allowed")
            and active_methods.get(m, {}).get("status") in (200, 201, 204, 207)
        }
        webdav_options = set(options_methods) & _WEBDAV_METHODS
        webdav_all = webdav_active | webdav_options

        if webdav_all:
            # PROPFIND is particularly dangerous (directory listing)
            if "PROPFIND" in webdav_all:
                findings.append(Finding.high(
                    "WebDAV PROPFIND enabled — directory listing possible",
                    description=(
                        "PROPFIND reveals directory structure and file metadata; "
                        "attackers can enumerate the web root"
                    ),
                    evidence=f"WebDAV methods: {', '.join(sorted(webdav_all))}",
                    remediation="Disable WebDAV unless explicitly required",
                    tags=["scanning", "http-methods", "webdav", "propfind"],
                ))
            else:
                findings.append(Finding.medium(
                    f"WebDAV methods enabled: {', '.join(sorted(webdav_all))}",
                    description=(
                        "WebDAV methods expose additional attack surface "
                        "including file manipulation"
                    ),
                    evidence=f"Methods: {', '.join(sorted(webdav_all))}",
                    remediation="Disable WebDAV if not needed",
                    tags=["scanning", "http-methods", "webdav"],
                ))

            # MOVE/COPY can be used to overwrite files
            if "MOVE" in webdav_all or "COPY" in webdav_all:
                mc = sorted({"MOVE", "COPY"} & webdav_all)
                findings.append(Finding.high(
                    f"WebDAV {'/'.join(mc)} enabled — file overwrite risk",
                    description=(
                        f"{'/'.join(mc)} can move/copy files on the server, "
                        "potentially overwriting critical files"
                    ),
                    evidence=f"Methods: {', '.join(mc)}",
                    remediation="Disable MOVE and COPY methods",
                    tags=["scanning", "http-methods", "webdav", "file-overwrite"],
                ))

        return findings

    async def _check_method_overrides(
        self, base_url: str, ctx: Any,
    ) -> list[Finding]:
        """Test method override headers that bypass method restrictions."""
        findings: list[Finding] = []

        for header in _OVERRIDE_HEADERS:
            if ctx.should_stop:
                break

            # Send POST with override header requesting DELETE
            try:
                async with ctx.rate:
                    resp = await ctx.http.request(
                        "POST",
                        f"{base_url}/",
                        headers={header: "DELETE"},
                        timeout=5.0,
                    )
                    # Compare with normal POST to detect if override was honoured
                    async with ctx.rate:
                        normal_resp = await ctx.http.request(
                            "POST", f"{base_url}/", timeout=5.0,
                        )

                    # Heuristic: different status or body size suggests override worked
                    if resp.status != normal_resp.status:
                        findings.append(Finding.medium(
                            f"Method override via {header} header accepted",
                            description=(
                                f"Server processes {header}: DELETE differently "
                                f"from normal POST (status {resp.status} vs "
                                f"{normal_resp.status}), allowing method "
                                "restriction bypass"
                            ),
                            evidence=(
                                f"POST with {header}: DELETE -> HTTP {resp.status}, "
                                f"normal POST -> HTTP {normal_resp.status}"
                            ),
                            remediation=(
                                f"Disable {header} header processing or ensure "
                                "authorization checks apply to overridden methods"
                            ),
                            tags=[
                                "scanning", "http-methods", "override",
                                header.lower(),
                            ],
                        ))
            except Exception:
                continue

        # Also check _method query parameter
        if not ctx.should_stop:
            try:
                async with ctx.rate:
                    resp = await ctx.http.request(
                        "POST",
                        f"{base_url}/?_method=DELETE",
                        timeout=5.0,
                    )
                    async with ctx.rate:
                        normal_resp = await ctx.http.request(
                            "POST", f"{base_url}/", timeout=5.0,
                        )
                    if resp.status != normal_resp.status:
                        findings.append(Finding.medium(
                            "Method override via _method query parameter accepted",
                            description=(
                                "Server processes _method=DELETE parameter, "
                                "allowing method restriction bypass via URL"
                            ),
                            evidence=(
                                f"POST ?_method=DELETE -> HTTP {resp.status}, "
                                f"normal POST -> HTTP {normal_resp.status}"
                            ),
                            remediation=(
                                "Disable _method parameter processing or ensure "
                                "authorization checks apply"
                            ),
                            tags=["scanning", "http-methods", "override", "_method"],
                        ))
            except Exception:
                pass

        return findings

    async def _check_cors_preflight(
        self, base_url: str, options_headers: dict, ctx: Any,
    ) -> list[Finding]:
        """Analyse CORS pre-flight response from OPTIONS."""
        findings: list[Finding] = []

        # Send proper pre-flight request
        try:
            async with ctx.rate:
                resp = await ctx.http.request(
                    "OPTIONS",
                    f"{base_url}/",
                    headers={
                        "Origin": "https://attacker.example.com",
                        "Access-Control-Request-Method": "DELETE",
                        "Access-Control-Request-Headers": "Authorization, X-Custom",
                    },
                    timeout=5.0,
                )

                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acam = resp.headers.get("Access-Control-Allow-Methods", "")
                acah = resp.headers.get("Access-Control-Allow-Headers", "")

                if acao and acao != "":
                    if acam:
                        methods = [m.strip().upper() for m in acam.split(",")]
                        dangerous = {"PUT", "DELETE", "PATCH"} & set(methods)
                        if dangerous and acao in ("*", "https://attacker.example.com"):
                            findings.append(Finding.medium(
                                "CORS pre-flight allows dangerous methods: "
                                f"{', '.join(sorted(dangerous))}",
                                description=(
                                    "Pre-flight response permits destructive "
                                    "HTTP methods from external origins"
                                ),
                                evidence=(
                                    f"ACAO: {acao}, ACAM: {acam}"
                                ),
                                remediation="Restrict CORS allowed methods",
                                tags=["scanning", "http-methods", "cors", "preflight"],
                            ))

                    if acah and (acah == "*" or "authorization" in acah.lower()):
                        findings.append(Finding.medium(
                            "CORS pre-flight exposes sensitive headers",
                            description=(
                                "Pre-flight allows Authorization header from "
                                "cross-origin, enabling credential theft"
                            ),
                            evidence=f"ACAH: {acah}",
                            remediation="Restrict allowed headers to non-sensitive ones",
                            tags=["scanning", "http-methods", "cors", "preflight"],
                        ))

        except Exception:
            pass

        return findings

    async def _check_method_tampering(
        self, base_url: str, ctx: Any,
    ) -> list[Finding]:
        """Test HTTP method tampering via POST body _method parameter."""
        findings: list[Finding] = []

        # Test POST with _method=DELETE in the body
        try:
            async with ctx.rate:
                resp = await ctx.http.post(
                    f"{base_url}/",
                    data="_method=DELETE",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=5.0,
                )
                async with ctx.rate:
                    normal = await ctx.http.post(
                        f"{base_url}/",
                        data="dummy=1",
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        timeout=5.0,
                    )

                if resp.status != normal.status:
                    findings.append(Finding.medium(
                        "HTTP method tampering via POST body _method=DELETE",
                        description=(
                            "Server interprets _method in POST body as the "
                            "actual HTTP method, bypassing method-level ACLs"
                        ),
                        evidence=(
                            f"POST _method=DELETE -> HTTP {resp.status}, "
                            f"normal POST -> HTTP {normal.status}"
                        ),
                        remediation=(
                            "Disable _method body parameter or enforce "
                            "authorization on the overridden method"
                        ),
                        tags=["scanning", "http-methods", "tampering"],
                    ))
        except Exception:
            pass

        return findings
