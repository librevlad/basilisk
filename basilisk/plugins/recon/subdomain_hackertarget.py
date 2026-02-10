"""Subdomain discovery via HackerTarget API."""

from __future__ import annotations

from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class SubdomainHackerTargetPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="subdomain_hackertarget",
        display_name="Subdomains (HackerTarget)",
        category=PluginCategory.RECON,
        description="Discovers subdomains via HackerTarget hostsearch API",
        produces=["subdomains"],
        provides="subdomains",
        timeout=20.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        url = f"https://api.hackertarget.com/hostsearch/?q={target.host}"
        try:
            async with ctx.rate:
                text = await ctx.http.fetch_text(url, timeout=15.0)
        except Exception as e:
            return PluginResult.fail(
                self.meta.name, target.host, error=f"HackerTarget request failed: {e}"
            )

        if not text or "error" in text.lower()[:50]:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info("HackerTarget returned no data")],
                data={"subdomains": []},
            )

        subdomains: set[str] = set()
        for line in text.strip().splitlines():
            parts = line.split(",")
            if parts:
                host = parts[0].strip().lower()
                if host.endswith(f".{target.host}") or host == target.host:
                    subdomains.add(host)

        subdomains.discard(target.host)
        sorted_subs = sorted(subdomains)

        findings = [
            Finding.info(
                f"HackerTarget: {len(sorted_subs)} subdomains found",
                evidence=", ".join(sorted_subs[:20]),
                tags=["recon", "subdomains", "hackertarget"],
            )
        ]

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"subdomains": sorted_subs},
        )
