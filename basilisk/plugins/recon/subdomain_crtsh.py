"""Subdomain discovery via crt.sh (Certificate Transparency logs)."""

from __future__ import annotations

import re
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class SubdomainCrtshPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="subdomain_crtsh",
        display_name="Subdomains (crt.sh)",
        category=PluginCategory.RECON,
        description="Discovers subdomains via Certificate Transparency logs (crt.sh)",
        produces=["subdomains"],
        provides="subdomains",
        timeout=30.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        url = f"https://crt.sh/?q=%.{target.host}&output=json"
        try:
            async with ctx.rate:
                text = await ctx.http.fetch_text(url, timeout=25.0)
        except Exception as e:
            return PluginResult.fail(
                self.meta.name, target.host, error=f"crt.sh request failed: {e}"
            )

        if not text:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info("crt.sh returned no data")],
                data={"subdomains": []},
            )

        subdomains: set[str] = set()
        import json

        try:
            entries = json.loads(text)
        except json.JSONDecodeError:
            return PluginResult.fail(
                self.meta.name, target.host, error="crt.sh returned invalid JSON"
            )

        for entry in entries:
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower()
                name = re.sub(r"^\*\.", "", name)
                if name.endswith(f".{target.host}") or name == target.host:
                    subdomains.add(name)

        subdomains.discard(target.host)
        sorted_subs = sorted(subdomains)

        findings = [
            Finding.info(
                f"crt.sh: {len(sorted_subs)} subdomains found",
                evidence=", ".join(sorted_subs[:20]),
                tags=["recon", "subdomains", "crt.sh"],
            )
        ]

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"subdomains": sorted_subs},
        )
