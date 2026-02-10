"""HTTP methods scanner — detects dangerous allowed methods."""

from __future__ import annotations

from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

DANGEROUS_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}
RISKY_METHODS = {"PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"}


class HttpMethodsScanPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="http_methods_scan",
        display_name="HTTP Methods Scanner",
        category=PluginCategory.SCANNING,
        description="Detects allowed HTTP methods including dangerous ones",
        produces=["http_methods"],
        timeout=10.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        findings: list[Finding] = []
        allowed_methods: list[str] = []

        for scheme in ("https", "http"):
            url = f"{scheme}://{target.host}/"
            try:
                async with ctx.rate:
                    resp = await ctx.http.request("OPTIONS", url, timeout=8.0)
                    allow_header = resp.headers.get("Allow", "")
                    if allow_header:
                        allowed_methods = [
                            m.strip().upper() for m in allow_header.split(",")
                        ]
                        break
            except Exception:
                continue

        if not allowed_methods:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info("OPTIONS not supported or no Allow header")],
                data={"methods": []},
            )

        # Check for dangerous methods
        dangerous = set(allowed_methods) & DANGEROUS_METHODS
        webdav = set(allowed_methods) & RISKY_METHODS

        if "TRACE" in dangerous:
            findings.append(Finding.medium(
                "TRACE method enabled",
                description="TRACE can be used for Cross-Site Tracing (XST) attacks",
                evidence=f"Allow: {', '.join(allowed_methods)}",
                remediation="Disable TRACE method on the web server",
                tags=["scanning", "http-methods"],
            ))

        if "PUT" in dangerous or "DELETE" in dangerous:
            findings.append(Finding.high(
                f"Dangerous methods enabled: {', '.join(dangerous - {'TRACE'})}",
                description="PUT/DELETE methods may allow unauthorized file modification",
                evidence=f"Allow: {', '.join(allowed_methods)}",
                remediation="Disable PUT and DELETE methods unless required by the API",
                tags=["scanning", "http-methods"],
            ))

        if webdav:
            findings.append(Finding.medium(
                f"WebDAV methods enabled: {', '.join(webdav)}",
                description="WebDAV methods may expose additional attack surface",
                evidence=f"Allow: {', '.join(allowed_methods)}",
                remediation="Disable WebDAV if not needed",
                tags=["scanning", "http-methods", "webdav"],
            ))

        if not findings:
            findings.append(Finding.info(
                f"Allowed methods: {', '.join(allowed_methods)}",
                tags=["scanning", "http-methods"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"methods": allowed_methods},
        )
