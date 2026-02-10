"""DNS zone transfer (AXFR) attempt."""

from __future__ import annotations

import asyncio
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class DnsZoneTransferPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="dns_zone_transfer",
        display_name="DNS Zone Transfer",
        category=PluginCategory.RECON,
        description="Attempts DNS zone transfer (AXFR) against nameservers",
        depends_on=["dns_enum"],
        produces=["zone_records"],
        timeout=30.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.dns is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="DNS client not available"
            )

        findings: list[Finding] = []
        zone_records: list[str] = []

        # Get NS records
        ns_records = await ctx.dns.resolve(target.host, "NS")
        if not ns_records:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info("No NS records found, skipping AXFR")],
                data={"zone_transfer": False},
            )

        nameservers = [r.value.rstrip(".") for r in ns_records]

        for ns in nameservers:
            try:
                records = await asyncio.wait_for(
                    self._try_axfr(target.host, ns),
                    timeout=15.0,
                )
                if records:
                    zone_records.extend(records)
                    findings.append(Finding.critical(
                        f"Zone transfer allowed on {ns}",
                        description=(
                            f"Nameserver {ns} allows AXFR zone transfer for "
                            f"{target.host}. This exposes all DNS records."
                        ),
                        evidence=f"Received {len(records)} records from {ns}",
                        remediation=(
                            "Restrict zone transfers to authorized "
                            "secondary nameservers only"
                        ),
                        tags=["recon", "dns", "zone-transfer"],
                    ))
            except Exception:
                continue

        if not findings:
            findings.append(Finding.info(
                f"Zone transfer denied by all {len(nameservers)} nameservers",
                tags=["recon", "dns"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "zone_transfer": bool(zone_records),
                "records_count": len(zone_records),
                "nameservers_tested": nameservers,
            },
        )

    async def _try_axfr(self, domain: str, nameserver: str) -> list[str]:
        """Attempt AXFR zone transfer. Returns list of record strings."""
        import dns.asyncquery
        import dns.query
        import dns.zone

        try:
            zone = await asyncio.to_thread(
                dns.zone.from_xfr, dns.query.xfr(nameserver, domain, timeout=10)
            )
            return [zone[name].to_text(name) for name in zone.nodes]
        except Exception:
            return []
