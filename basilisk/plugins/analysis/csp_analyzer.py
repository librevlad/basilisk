"""Content Security Policy (CSP) analyzer."""

from __future__ import annotations

from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

DANGEROUS_DIRECTIVES = {
    "unsafe-inline": "Allows inline scripts/styles (XSS risk)",
    "unsafe-eval": "Allows eval() (code injection risk)",
    "data:": "Allows data: URIs (bypass for script injection)",
    "*": "Wildcard allows any source",
}


class CspAnalyzerPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="csp_analyzer",
        display_name="CSP Analyzer",
        category=PluginCategory.ANALYSIS,
        description="Analyzes Content Security Policy for weaknesses",
        produces=["csp_analysis"],
        timeout=10.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        findings: list[Finding] = []
        csp_header = ""

        for scheme in ("https", "http"):
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(
                        f"{scheme}://{target.host}/", timeout=8.0,
                    )
                    csp_header = (
                        resp.headers.get("Content-Security-Policy", "")
                        or resp.headers.get("Content-Security-Policy-Report-Only", "")
                    )
                    if csp_header:
                        break
            except Exception:
                continue

        if not csp_header:
            findings.append(Finding.medium(
                "No Content-Security-Policy header",
                description="Missing CSP leaves the site vulnerable to XSS attacks",
                remediation="Implement a Content-Security-Policy header",
                tags=["analysis", "csp"],
            ))
            return PluginResult.success(
                self.meta.name, target.host,
                findings=findings,
                data={"csp": None},
            )

        # Parse CSP directives
        directives: dict[str, list[str]] = {}
        for part in csp_header.split(";"):
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            if tokens:
                directives[tokens[0]] = tokens[1:] if len(tokens) > 1 else []

        # Check for dangerous values
        for directive, values in directives.items():
            for val in values:
                val_lower = val.strip("'").lower()
                if val_lower in DANGEROUS_DIRECTIVES:
                    severity = "high" if val_lower == "unsafe-eval" else "medium"
                    findings.append(getattr(Finding, severity)(
                        f"CSP {directive}: '{val_lower}' is dangerous",
                        description=DANGEROUS_DIRECTIVES[val_lower],
                        evidence=f"{directive} {' '.join(values)}",
                        remediation=f"Remove '{val_lower}' from {directive}",
                        tags=["analysis", "csp"],
                    ))

        # Check for missing default-src
        if "default-src" not in directives:
            findings.append(Finding.low(
                "CSP missing default-src directive",
                description="Without default-src, unlisted resources have no restriction",
                remediation="Add default-src 'self' as a baseline",
                tags=["analysis", "csp"],
            ))

        # Check for missing script-src
        if "script-src" not in directives and "default-src" not in directives:
            findings.append(Finding.medium(
                "CSP has no script-src or default-src",
                remediation="Define script-src to control script loading",
                tags=["analysis", "csp"],
            ))

        # Check for known CSP bypass domains
        bypass_domains = [
            "*.googleapis.com", "*.gstatic.com", "*.google.com",
            "*.cloudflare.com", "*.cloudfront.net", "*.amazonaws.com",
            "*.azureedge.net", "*.azurewebsites.net",
            "cdn.jsdelivr.net", "cdnjs.cloudflare.com",
            "unpkg.com", "raw.githubusercontent.com",
            "*.herokuapp.com", "*.firebaseapp.com",
            "*.appspot.com", "accounts.google.com",
            "*.facebook.com", "*.fbcdn.net",
            "*.twitter.com", "*.twimg.com",
            "*.youtube.com",
        ]
        csp_lower = csp_header.lower()
        for domain in bypass_domains:
            domain_check = domain.lstrip("*.")
            if domain_check in csp_lower:
                findings.append(Finding.low(
                    f"CSP allows known bypass domain: {domain_check}",
                    description=f"{domain_check} in CSP may host attacker content",
                    evidence=csp_header[:200],
                    remediation=f"Review if {domain_check} is necessary in CSP",
                    tags=["analysis", "csp", "bypass"],
                ))
                break  # Report only first bypass domain

        if not findings:
            findings.append(Finding.info(
                f"CSP configured with {len(directives)} directives",
                evidence=csp_header[:200],
                tags=["analysis", "csp"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"csp": csp_header, "directives": directives},
        )
