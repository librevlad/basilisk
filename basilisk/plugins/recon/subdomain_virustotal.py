"""VirusTotal passive DNS subdomain enumeration."""

from __future__ import annotations

import re
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class SubdomainVirusTotalPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="subdomain_virustotal",
        display_name="VirusTotal Subdomains",
        category=PluginCategory.RECON,
        description="Discovers subdomains via VirusTotal passive DNS",
        provides="subdomains",
        produces=["subdomains"],
        timeout=20.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        subdomains: set[str] = set()
        url = f"https://www.virustotal.com/ui/domains/{target.host}/subdomains?limit=40"

        try:
            async with ctx.rate:
                resp = await ctx.http.get(url, timeout=15.0)
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    for item in data.get("data", []):
                        sub = item.get("id", "").strip().lower()
                        if sub and sub != target.host and sub.endswith(f".{target.host}"):
                            subdomains.add(sub)
        except Exception:
            # Fallback: try scraping search page
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(
                        f"https://www.virustotal.com/gui/domain/{target.host}/relations",
                        timeout=15.0,
                    )
                    body = await resp.text(encoding="utf-8", errors="replace")
                    pattern = rf"([\w.-]+\.{re.escape(target.host)})"
                    for m in re.findall(pattern, body, re.IGNORECASE):
                        sub = m.strip().lower()
                        if sub != target.host:
                            subdomains.add(sub)
            except Exception:
                pass

        findings = [Finding.info(
            f"VirusTotal: {len(subdomains)} subdomains",
            evidence=", ".join(sorted(subdomains)[:20]) or "none",
            tags=["recon", "subdomains"],
        )]

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"subdomains": sorted(subdomains)},
        )
