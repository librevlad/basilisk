"""DNSSEC validation check."""

from __future__ import annotations

from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class DnssecCheckPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="dnssec_check",
        display_name="DNSSEC Check",
        category=PluginCategory.SCANNING,
        description="Checks if DNSSEC is enabled for the domain",
        depends_on=["dns_enum"],
        produces=["dnssec_info"],
        timeout=10.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.dns is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="DNS client not available"
            )

        findings: list[Finding] = []
        has_dnssec = False

        # Check for DNSKEY records
        try:
            dnskey_records = await ctx.dns.resolve(target.host, "DNSKEY")
            if dnskey_records:
                has_dnssec = True
        except Exception:
            pass

        # Also check for DS records at parent
        if not has_dnssec:
            try:
                ds_records = await ctx.dns.resolve(target.host, "DS")
                if ds_records:
                    has_dnssec = True
            except Exception:
                pass

        if has_dnssec:
            findings.append(Finding.info(
                "DNSSEC is enabled",
                description="Domain has DNSKEY/DS records, DNS responses are signed",
                tags=["scanning", "dns", "dnssec"],
            ))
        else:
            findings.append(Finding.low(
                "DNSSEC not enabled",
                description=(
                    "Domain does not have DNSSEC configured. DNS responses "
                    "could be spoofed via cache poisoning attacks."
                ),
                remediation="Enable DNSSEC for the domain",
                tags=["scanning", "dns", "dnssec"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"dnssec_enabled": has_dnssec},
        )
