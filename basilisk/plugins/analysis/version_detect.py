"""Software version detection from headers, pages, and error messages."""

from __future__ import annotations

import re
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class VersionDetectPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="version_detect",
        display_name="Version Detector",
        category=PluginCategory.ANALYSIS,
        description="Detects software versions from headers, pages, and error messages",
        produces=["versions"],
        timeout=10.0,
    )

    VERSION_PATTERNS = [
        ("Server", r"(Apache|Nginx|IIS|LiteSpeed)[/ ]*([\d.]+)?"),
        ("PHP", r"PHP[/ ]*([\d.]+)"),
        ("OpenSSL", r"OpenSSL[/ ]*([\d.a-z]+)"),
        ("ASP.NET", r"ASP\.NET[/ ]*([\d.]+)"),
        ("Express", r"Express[/ ]*([\d.]+)?"),
        ("WordPress", r"WordPress[/ ]*([\d.]+)"),
        ("jQuery", r"jquery[/-]([\d.]+)"),
        ("Bootstrap", r"bootstrap[/-]([\d.]+)"),
        ("React", r"react[/-]([\d.]+)"),
        ("Angular", r"angular(?:\.min)?[/-]([\d.]+)"),
        ("Vue", r"vue[/-]([\d.]+)"),
    ]

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        findings: list[Finding] = []
        versions: dict[str, str] = {}

        headers_text = ""
        body = ""

        for scheme in ("https", "http"):
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(
                        f"{scheme}://{target.host}/", timeout=8.0,
                    )
                    headers_text = "\n".join(
                        f"{k}: {v}" for k, v in resp.headers.items()
                    )
                    body = await resp.text(encoding="utf-8", errors="replace")
                    break
            except Exception:
                continue

        combined = f"{headers_text}\n{body}"

        for name, pattern in self.VERSION_PATTERNS:
            match = re.search(pattern, combined, re.IGNORECASE)
            if match:
                version = match.group(2) if match.lastindex and match.lastindex >= 2 else ""
                versions[name] = version or "detected"

        # Server-side versions are higher risk
        server_side = {"Server", "PHP", "OpenSSL", "ASP.NET", "Express", "WordPress"}
        for name, ver in versions.items():
            if name in server_side:
                findings.append(Finding.low(
                    f"{name} version disclosed: {ver}",
                    description="Server-side version disclosure aids targeted attacks",
                    remediation=f"Hide {name} version information",
                    tags=["analysis", "version", "info-disclosure"],
                ))
            else:
                findings.append(Finding.info(
                    f"{name}: {ver}",
                    tags=["analysis", "version"],
                ))

        if not versions:
            findings.append(Finding.info(
                "No software versions detected",
                tags=["analysis", "version"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"versions": versions},
        )
