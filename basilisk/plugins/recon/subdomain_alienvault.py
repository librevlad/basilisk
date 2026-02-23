"""AlienVault OTX passive DNS subdomain enumeration."""

from __future__ import annotations

from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target, TargetType


class SubdomainAlienVaultPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="subdomain_alienvault",
        display_name="AlienVault OTX Subdomains",
        category=PluginCategory.RECON,
        description="Discovers subdomains via AlienVault OTX passive DNS",
        provides="subdomains",
        produces=["subdomains"],
        timeout=20.0,
        requires_http=False,
    )

    def accepts(self, target: Target) -> bool:
        return target.type == TargetType.DOMAIN

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        subdomains: set[str] = set()
        url = (
            f"https://otx.alienvault.com/api/v1/indicators/domain"
            f"/{target.host}/passive_dns"
        )

        try:
            async with ctx.rate:
                resp = await ctx.http.get(url, timeout=15.0)
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    for entry in data.get("passive_dns", []):
                        hostname = entry.get("hostname", "").strip().lower()
                        if (
                            hostname
                            and hostname != target.host
                            and hostname.endswith(f".{target.host}")
                        ):
                            subdomains.add(hostname)
                elif resp.status in (429, 403):
                    return PluginResult.success(
                        self.meta.name, target.host,
                        findings=[Finding.info(
                            f"AlienVault OTX: HTTP {resp.status} — API rate limited or"
                            " requires authentication",
                            tags=["recon", "subdomains"],
                        )],
                        data={"subdomains": []},
                    )
        except Exception:
            pass

        findings = [Finding.info(
            f"AlienVault OTX: {len(subdomains)} subdomains",
            evidence=", ".join(sorted(subdomains)[:20]) or "none",
            tags=["recon", "subdomains"],
        )]

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"subdomains": sorted(subdomains)},
        )
