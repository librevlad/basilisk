"""DNS Enumeration plugin — resolves all record types for a target."""

from __future__ import annotations

from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class DnsEnumPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="dns_enum",
        display_name="DNS Enumeration",
        category=PluginCategory.RECON,
        description="Resolves A, AAAA, MX, NS, TXT, SOA, CNAME records",
        produces=["dns_records", "ips"],
        timeout=15.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.dns is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="DNS client not available"
            )

        records = await ctx.dns.resolve_all(target.host)
        if not records:
            return PluginResult(
                plugin=self.meta.name,
                target=target.host,
                status="partial",
                findings=[Finding.info(f"No DNS records found for {target.host}")],
            )

        ips = [r.value for r in records if r.type.value in ("A", "AAAA")]
        target.ips = ips

        findings: list[Finding] = []
        record_data = [
            {"type": r.type.value, "name": r.name, "value": r.value, "ttl": r.ttl}
            for r in records
        ]

        # Check for interesting records
        txt_records = [r for r in records if r.type.value == "TXT"]
        for txt in txt_records:
            val = txt.value.lower()
            if "v=spf1" in val and "~all" in val:
                findings.append(Finding.low(
                    "SPF with softfail (~all)",
                    description="SPF record uses ~all instead of -all",
                    evidence=txt.value,
                    remediation="Consider using -all for strict SPF",
                    tags=["dns", "spf"],
                ))

        mx_records = [r for r in records if r.type.value == "MX"]
        if not mx_records:
            findings.append(Finding.info(
                "No MX records",
                description=f"No mail exchangers configured for {target.host}",
                tags=["dns"],
            ))

        findings.append(Finding.info(
            f"DNS: {len(records)} records, {len(ips)} IPs",
            evidence=", ".join(f"{r.type.value}={r.value}" for r in records[:10]),
            tags=["dns"],
        ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"records": record_data, "ips": ips},
        )
