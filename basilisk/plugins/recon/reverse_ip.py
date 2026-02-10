"""Reverse IP lookup — find other domains hosted on the same IP."""

from __future__ import annotations

from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class ReverseIpPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="reverse_ip",
        display_name="Reverse IP Lookup",
        category=PluginCategory.RECON,
        description="Finds other domains sharing the same IP address",
        depends_on=["dns_enum"],
        produces=["shared_hosts"],
        timeout=15.0,
    )

    def accepts(self, target: Target) -> bool:
        return bool(target.ips)

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        all_hosts: set[str] = set()

        for ip in target.ips[:3]:  # Check first 3 IPs
            url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
            try:
                async with ctx.rate:
                    text = await ctx.http.fetch_text(url, timeout=10.0)
            except Exception:
                continue

            if not text or "error" in text.lower()[:50]:
                continue

            for line in text.strip().splitlines():
                host = line.strip().lower()
                if host and host != target.host:
                    all_hosts.add(host)

        sorted_hosts = sorted(all_hosts)

        findings = []
        if sorted_hosts:
            findings.append(Finding.info(
                f"Reverse IP: {len(sorted_hosts)} shared hosts found",
                evidence=", ".join(sorted_hosts[:20]),
                tags=["recon", "reverse-ip"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"shared_hosts": sorted_hosts},
        )
