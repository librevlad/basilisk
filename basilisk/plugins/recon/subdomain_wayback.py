"""Wayback Machine subdomain and URL discovery."""

from __future__ import annotations

import re
from typing import ClassVar
from urllib.parse import urlparse

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class SubdomainWaybackPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="subdomain_wayback",
        display_name="Wayback Machine Discovery",
        category=PluginCategory.RECON,
        description="Discovers subdomains and URLs via Wayback Machine CDX API",
        provides="subdomains",
        produces=["subdomains", "wayback_urls"],
        timeout=30.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        subdomains: set[str] = set()
        urls: set[str] = set()
        api_url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url=*.{target.host}/*&output=text&fl=original"
            f"&collapse=urlkey&limit=500"
        )

        try:
            async with ctx.rate:
                resp = await ctx.http.get(api_url, timeout=25.0)
                if resp.status == 200:
                    text = await resp.text(encoding="utf-8", errors="replace")
                    for line in text.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        urls.add(line)
                        try:
                            parsed = urlparse(line)
                            host = parsed.hostname or ""
                            host = host.lower().rstrip(".")
                            if host and host != target.host and host.endswith(
                                f".{target.host}"
                            ):
                                subdomains.add(host)
                        except Exception:
                            continue
        except Exception:
            pass

        interesting = [u for u in urls if re.search(
            r"\.(php|asp|aspx|jsp|json|xml|yaml|yml|sql|bak|conf|env|log)(\?|$)",
            u, re.IGNORECASE,
        )]

        findings: list[Finding] = [Finding.info(
            f"Wayback Machine: {len(subdomains)} subdomains, {len(urls)} URLs",
            evidence=", ".join(sorted(subdomains)[:15]) or "none",
            tags=["recon", "subdomains", "wayback"],
        )]

        if interesting:
            findings.append(Finding.low(
                f"Wayback: {len(interesting)} interesting URLs archived",
                evidence="\n".join(interesting[:10]),
                tags=["recon", "wayback"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "subdomains": sorted(subdomains),
                "urls_found": len(urls),
                "interesting_urls": interesting[:50],
            },
        )
