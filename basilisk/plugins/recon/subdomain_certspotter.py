"""Subdomain discovery via Certspotter (Certificate Transparency)."""

from __future__ import annotations

from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class SubdomainCertspotterPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="subdomain_certspotter",
        display_name="Subdomains (Certspotter)",
        category=PluginCategory.RECON,
        description="Discovers subdomains via Certspotter CT log API (free, no key)",
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

        url = (
            f"https://api.certspotter.com/v1/issuances"
            f"?domain={target.host}&include_subdomains=true&expand=dns_names"
        )

        try:
            async with ctx.rate:
                resp = await ctx.http.get(url, timeout=15.0)
                if resp.status == 429:
                    return PluginResult.success(
                        self.meta.name, target.host,
                        findings=[Finding.info(
                            "Certspotter: rate limited",
                            tags=["recon", "subdomains", "certspotter"],
                        )],
                        data={"subdomains": []},
                    )
                if resp.status != 200:
                    return PluginResult.success(
                        self.meta.name, target.host,
                        findings=[Finding.info(
                            f"Certspotter: HTTP {resp.status}",
                            tags=["recon", "subdomains", "certspotter"],
                        )],
                        data={"subdomains": []},
                    )
                data = await resp.json(content_type=None)
        except Exception as e:
            return PluginResult.fail(
                self.meta.name, target.host,
                error=f"Certspotter request failed: {e}",
            )

        subdomains: set[str] = set()
        if isinstance(data, list):
            for entry in data:
                for name in entry.get("dns_names", []):
                    name = name.strip().lower().lstrip("*.")
                    if (
                        name
                        and name != target.host
                        and name.endswith(f".{target.host}")
                    ):
                        subdomains.add(name)

        sorted_subs = sorted(subdomains)
        findings = [Finding.info(
            f"Certspotter: {len(sorted_subs)} subdomains found",
            evidence=", ".join(sorted_subs[:20]) or "none",
            tags=["recon", "subdomains", "certspotter"],
        )]

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"subdomains": sorted_subs},
        )
