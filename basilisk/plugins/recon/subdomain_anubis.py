"""Subdomain discovery via Anubis (jldc.me) API."""

from __future__ import annotations

from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class SubdomainAnubisPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="subdomain_anubis",
        display_name="Subdomains (Anubis)",
        category=PluginCategory.RECON,
        description="Discovers subdomains via Anubis (jldc.me) aggregation API (free, no key)",
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

        url = f"https://jldc.me/anubis/subdomains/{target.host}"

        try:
            async with ctx.rate:
                resp = await ctx.http.get(url, timeout=15.0)
                if resp.status == 429:
                    return PluginResult.success(
                        self.meta.name, target.host,
                        findings=[Finding.info(
                            "Anubis: rate limited",
                            tags=["recon", "subdomains", "anubis"],
                        )],
                        data={"subdomains": []},
                    )
                if resp.status != 200:
                    return PluginResult.success(
                        self.meta.name, target.host,
                        findings=[Finding.info(
                            f"Anubis: HTTP {resp.status}",
                            tags=["recon", "subdomains", "anubis"],
                        )],
                        data={"subdomains": []},
                    )
                data = await resp.json(content_type=None)
        except Exception as e:
            return PluginResult.fail(
                self.meta.name, target.host,
                error=f"Anubis request failed: {e}",
            )

        subdomains: set[str] = set()
        if isinstance(data, list):
            for name in data:
                if not isinstance(name, str):
                    continue
                name = name.strip().lower()
                if (
                    name
                    and name != target.host
                    and name.endswith(f".{target.host}")
                ):
                    subdomains.add(name)

        sorted_subs = sorted(subdomains)
        findings = [Finding.info(
            f"Anubis: {len(sorted_subs)} subdomains found",
            evidence=", ".join(sorted_subs[:20]) or "none",
            tags=["recon", "subdomains", "anubis"],
        )]

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"subdomains": sorted_subs},
        )
