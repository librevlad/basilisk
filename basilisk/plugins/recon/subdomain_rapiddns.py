"""Subdomain discovery via RapidDNS."""

from __future__ import annotations

import re
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class SubdomainRapidDnsPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="subdomain_rapiddns",
        display_name="Subdomains (RapidDNS)",
        category=PluginCategory.RECON,
        description="Discovers subdomains via RapidDNS database",
        produces=["subdomains"],
        provides="subdomains",
        timeout=20.0,
        requires_http=False,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        url = f"https://rapiddns.io/subdomain/{target.host}?full=1"
        try:
            async with ctx.rate:
                text = await ctx.http.fetch_text(url, timeout=15.0)
        except Exception as e:
            return PluginResult.fail(
                self.meta.name, target.host, error=f"RapidDNS request failed: {e}"
            )

        if not text:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info("RapidDNS returned no data")],
                data={"subdomains": []},
            )

        # Parse HTML table for subdomains
        pattern = re.compile(
            r"<td>([a-zA-Z0-9._-]+\." + re.escape(target.host) + r")</td>",
            re.IGNORECASE,
        )
        subdomains = {m.lower() for m in pattern.findall(text)}
        subdomains.discard(target.host)
        sorted_subs = sorted(subdomains)

        findings = [
            Finding.info(
                f"RapidDNS: {len(sorted_subs)} subdomains found",
                evidence=", ".join(sorted_subs[:20]),
                tags=["recon", "subdomains", "rapiddns"],
            )
        ]

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"subdomains": sorted_subs},
        )
