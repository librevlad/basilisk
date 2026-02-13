"""DNSDumpster subdomain enumeration via web scraping."""

from __future__ import annotations

import re
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class SubdomainDnsDumpsterPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="subdomain_dnsdumpster",
        display_name="DNSDumpster Subdomains",
        category=PluginCategory.RECON,
        description="Discovers subdomains via DNSDumpster API",
        provides="subdomains",
        produces=["subdomains"],
        timeout=20.0,
        requires_http=False,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        subdomains: set[str] = set()

        # Try the API endpoint first (JSON) — requires API key since 2025
        try:
            async with ctx.rate:
                resp = await ctx.http.get(
                    f"https://api.dnsdumpster.com/domain/{target.host}",
                    timeout=15.0,
                )
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    for entry in data.get("dns_records", {}).get("host", []):
                        host = entry.get("host", "").strip().lower()
                        if (
                            host
                            and host != target.host
                            and host.endswith(f".{target.host}")
                        ):
                            subdomains.add(host)
        except Exception:
            pass

        # Fallback: scrape the HTML search results page
        if not subdomains:
            try:
                async with ctx.rate:
                    # GET the page first (to work with the public search form)
                    resp = await ctx.http.get(
                        f"https://dnsdumpster.com/?q={target.host}",
                        timeout=15.0,
                    )
                    if resp.status == 200:
                        body = await resp.text(encoding="utf-8", errors="replace")
                        pattern = rf"([\w.-]+\.{re.escape(target.host)})"
                        matches = re.findall(pattern, body, re.IGNORECASE)
                        for m in matches:
                            sub = m.strip().lower().rstrip(".")
                            if sub != target.host and sub.endswith(f".{target.host}"):
                                subdomains.add(sub)
            except Exception:
                pass

        findings = [Finding.info(
            f"DNSDumpster: {len(subdomains)} subdomains",
            evidence=", ".join(sorted(subdomains)[:20]) or "none",
            tags=["recon", "subdomains"],
        )]

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"subdomains": sorted(subdomains)},
        )
