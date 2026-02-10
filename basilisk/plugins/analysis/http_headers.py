"""HTTP security headers analyzer plugin."""

from __future__ import annotations

from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

# Security headers to check
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "medium",
        "title": "Missing HSTS header",
        "remediation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "title": "Missing Content-Security-Policy",
        "remediation": "Implement a Content-Security-Policy header",
    },
    "X-Frame-Options": {
        "severity": "low",
        "title": "Missing X-Frame-Options",
        "remediation": "Add X-Frame-Options: DENY or SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "title": "Missing X-Content-Type-Options",
        "remediation": "Add X-Content-Type-Options: nosniff",
    },
    "X-XSS-Protection": {
        "severity": "low",
        "title": "Missing X-XSS-Protection",
        "remediation": "Add X-XSS-Protection: 1; mode=block",
    },
    "Referrer-Policy": {
        "severity": "low",
        "title": "Missing Referrer-Policy",
        "remediation": "Add Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "low",
        "title": "Missing Permissions-Policy",
        "remediation": "Add Permissions-Policy header to control browser features",
    },
}

# Information disclosure headers
INFO_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator", "Via"]


class HttpHeadersPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="http_headers",
        display_name="HTTP Security Headers",
        category=PluginCategory.ANALYSIS,
        description="Checks for missing security headers and info disclosure",
        depends_on=["dns_enum"],
        produces=["http_info"],
        timeout=15.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        findings: list[Finding] = []
        headers_data: dict = {}

        # Try HTTPS first, fall back to HTTP
        for scheme in ("https", "http"):
            url = f"{scheme}://{target.host}"
            try:
                resp = await ctx.http.get(url, timeout=10.0)
                async with resp:
                    headers = dict(resp.headers)
                    headers_data = {
                        "url": str(resp.url),
                        "status": resp.status,
                        "headers": headers,
                        "scheme": scheme,
                    }
                    findings.extend(self._check_security_headers(headers, target.host))
                    findings.extend(self._check_info_disclosure(headers, target.host))
                    break  # Success, don't try HTTP
            except Exception:
                continue

        if not headers_data:
            return PluginResult(
                plugin=self.meta.name,
                target=target.host,
                status="partial",
                findings=[Finding.info(
                    f"Could not connect to {target.host} via HTTP/HTTPS",
                )],
            )

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data=headers_data,
        )

    def _check_security_headers(
        self, headers: dict[str, str], host: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        present: list[str] = []
        missing: list[str] = []

        for header_name, config in SECURITY_HEADERS.items():
            if header_name.lower() in {k.lower() for k in headers}:
                present.append(header_name)
            else:
                missing.append(header_name)
                severity = config["severity"]
                factory = getattr(Finding, severity)
                findings.append(factory(
                    f"{config['title']} on {host}",
                    description=f"The {header_name} header is not set",
                    remediation=config["remediation"],
                    tags=["headers", header_name.lower()],
                ))

        # CORS check
        acao = None
        for k, v in headers.items():
            if k.lower() == "access-control-allow-origin":
                acao = v
                break
        if acao == "*":
            findings.append(Finding.medium(
                f"Wildcard CORS on {host}",
                description="Access-Control-Allow-Origin is set to '*'",
                evidence=f"Access-Control-Allow-Origin: {acao}",
                remediation="Restrict CORS to specific origins",
                tags=["headers", "cors"],
            ))

        # Clickjacking: check CSP frame-ancestors if X-Frame-Options missing
        if "X-Frame-Options" not in present:
            csp = ""
            for k, v in headers.items():
                if k.lower() == "content-security-policy":
                    csp = v
                    break
            if "frame-ancestors" not in csp.lower():
                findings.append(Finding.medium(
                    f"Clickjacking: no framing protection on {host}",
                    description="Missing X-Frame-Options and CSP frame-ancestors",
                    remediation="Add X-Frame-Options: DENY or CSP frame-ancestors 'none'",
                    tags=["headers", "clickjacking"],
                ))

        return findings

    def _check_info_disclosure(
        self, headers: dict[str, str], host: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        for header_name in INFO_HEADERS:
            for k, v in headers.items():
                if k.lower() == header_name.lower():
                    findings.append(Finding.low(
                        f"Information disclosure: {header_name} on {host}",
                        description=f"The {header_name} header reveals server info",
                        evidence=f"{header_name}: {v}",
                        remediation=f"Remove or obfuscate the {header_name} header",
                        tags=["headers", "info-disclosure"],
                    ))
                    break

        return findings
