"""ASN lookup — discovers AS number, network range, and organization."""

from __future__ import annotations

from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class AsnLookupPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="asn_lookup",
        display_name="ASN Lookup",
        category=PluginCategory.RECON,
        description="Discovers ASN, network range, and organization for target IP",
        depends_on=["dns_enum"],
        produces=["asn_info"],
        timeout=15.0,
        requires_http=False,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        ip = target.ips[0] if target.ips else None
        if not ip and ctx.dns:
                records = await ctx.dns.resolve(target.host, "A")
                if records:
                    ip = records[0].value

        if not ip:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info("No IP to look up ASN for")],
                data={},
            )

        asn_data: dict = {}

        # Use ip-api.com (free, no key required, ~45 req/min limit)
        error_msg = ""
        try:
            async with ctx.rate:
                resp = await ctx.http.get(
                    f"http://ip-api.com/json/{ip}?fields=as,org,isp,country,city,query",
                    timeout=10.0,
                )
                if resp.status == 200:
                    asn_data = await resp.json(content_type=None)
                elif resp.status == 429:
                    error_msg = "ip-api.com rate limited"
                else:
                    error_msg = f"ip-api.com returned HTTP {resp.status}"
        except Exception as e:
            error_msg = f"ip-api.com request failed: {type(e).__name__}"

        if not asn_data:
            msg = f"ASN lookup failed for {ip}"
            if error_msg:
                msg += f" ({error_msg})"
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info(msg, tags=["recon", "asn"])],
                data={"ip": ip},
            )

        findings = [Finding.info(
            f"ASN: {asn_data.get('as', 'unknown')}",
            evidence=(
                f"IP: {ip}, Org: {asn_data.get('org', '?')}, "
                f"ISP: {asn_data.get('isp', '?')}, "
                f"Location: {asn_data.get('city', '?')}, {asn_data.get('country', '?')}"
            ),
            tags=["recon", "asn"],
        )]

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "ip": ip,
                "asn": asn_data.get("as", ""),
                "org": asn_data.get("org", ""),
                "isp": asn_data.get("isp", ""),
                "country": asn_data.get("country", ""),
                "city": asn_data.get("city", ""),
            },
        )
