"""IPv6 support detection."""

from __future__ import annotations

from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class Ipv6ScanPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="ipv6_scan",
        display_name="IPv6 Scanner",
        category=PluginCategory.SCANNING,
        description="Detects IPv6 support and dual-stack configuration",
        depends_on=["dns_enum"],
        produces=["ipv6_info"],
        timeout=10.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.dns is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="DNS client not available"
            )

        findings: list[Finding] = []
        ipv6_addrs: list[str] = []

        # Check AAAA records
        try:
            aaaa_records = await ctx.dns.resolve(target.host, "AAAA")
            ipv6_addrs = [r.value for r in aaaa_records] if aaaa_records else []
        except Exception:
            pass

        # Check A records for comparison
        ipv4_addrs: list[str] = []
        try:
            a_records = await ctx.dns.resolve(target.host, "A")
            ipv4_addrs = [r.value for r in a_records] if a_records else []
        except Exception:
            pass

        if ipv6_addrs:
            findings.append(Finding.info(
                f"IPv6 enabled: {len(ipv6_addrs)} AAAA record(s)",
                evidence=", ".join(ipv6_addrs),
                tags=["scanning", "ipv6"],
            ))
            if ipv4_addrs:
                findings.append(Finding.info(
                    "Dual-stack configuration (IPv4 + IPv6)",
                    evidence=f"IPv4: {', '.join(ipv4_addrs)}, IPv6: {', '.join(ipv6_addrs)}",
                    tags=["scanning", "ipv6"],
                ))
        else:
            findings.append(Finding.info(
                "No IPv6 (AAAA) records found",
                tags=["scanning", "ipv6"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "ipv6_addresses": ipv6_addrs,
                "ipv4_addresses": ipv4_addrs,
                "dual_stack": bool(ipv6_addrs and ipv4_addrs),
            },
        )
