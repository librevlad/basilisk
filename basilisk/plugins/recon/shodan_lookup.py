"""Shodan passive port discovery — finds open ports and services via Shodan API."""

from __future__ import annotations

import json
import os
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class ShodanLookupPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="shodan_lookup",
        display_name="Shodan Passive Lookup",
        category=PluginCategory.RECON,
        description="Discovers open ports and services via Shodan API",
        depends_on=["dns_enum"],
        produces=["shodan_ports", "shodan_services"],
        timeout=20.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        api_key = (
            ctx.state.get("SHODAN_API_KEY", "")
            or os.environ.get("SHODAN_API_KEY", "")
        )
        if not api_key:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info(
                    "Shodan API key not configured (set shodan_api_key in config)",
                    tags=["recon", "shodan"],
                )],
                data={},
            )

        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        # Resolve IP from dns_enum
        ip = ""
        dns_key = f"dns_enum:{target.host}"
        dns_result = ctx.pipeline.get(dns_key)
        if dns_result and dns_result.ok:
            a_records = dns_result.data.get("a_records", [])
            if a_records:
                ip = a_records[0] if isinstance(a_records[0], str) else str(a_records[0])

        if not ip and ctx.dns:
            try:
                records = await ctx.dns.resolve(target.host, "A")
                if records:
                    ip = str(records[0])
            except Exception:
                pass

        if not ip:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info("Could not resolve IP for Shodan lookup")],
                data={},
            )

        # Query Shodan
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        try:
            async with ctx.rate:
                resp = await ctx.http.get(url, timeout=15.0)
                if resp.status == 401:
                    return PluginResult.success(
                        self.meta.name, target.host,
                        findings=[Finding.info("Shodan API key invalid")],
                        data={},
                    )
                if resp.status == 404:
                    return PluginResult.success(
                        self.meta.name, target.host,
                        findings=[Finding.info(f"No Shodan data for {ip}")],
                        data={},
                    )
                if resp.status != 200:
                    return PluginResult.success(
                        self.meta.name, target.host,
                        findings=[Finding.info(f"Shodan API returned HTTP {resp.status}")],
                        data={},
                    )

                body = await resp.text(encoding="utf-8", errors="replace")
                data = json.loads(body)
        except Exception as e:
            return PluginResult.fail(
                self.meta.name, target.host, error=f"Shodan query failed: {e}"
            )

        findings: list[Finding] = []
        shodan_ports: list[int] = data.get("ports", [])
        org = data.get("org", "")
        asn = data.get("asn", "")
        os_info = data.get("os", "")

        # Extract service details
        services: list[dict] = []
        for item in data.get("data", []):
            svc = {
                "port": item.get("port"),
                "transport": item.get("transport", "tcp"),
                "product": item.get("product", ""),
                "version": item.get("version", ""),
                "banner": (item.get("data", "") or "")[:200],
            }
            services.append(svc)

        # Cross-reference with port_scan
        port_key = f"port_scan:{target.host}"
        port_result = ctx.pipeline.get(port_key)
        our_ports: set[int] = set()
        if port_result and port_result.ok:
            our_ports = {p["port"] for p in port_result.data.get("open_ports", [])}

        missed_ports = set(shodan_ports) - our_ports
        if missed_ports:
            findings.append(Finding.medium(
                f"Shodan found {len(missed_ports)} ports missed by active scan",
                description=f"Ports: {sorted(missed_ports)}",
                evidence=f"Active scan found: {sorted(our_ports)}, Shodan: {sorted(shodan_ports)}",
                remediation="Expand port scan range to include these ports",
                tags=["recon", "shodan", "ports"],
            ))

        if services:
            svc_summary = ", ".join(
                f"{s['port']}/{s['transport']}({s['product'] or '?'})"
                for s in services[:10]
            )
            findings.append(Finding.info(
                f"Shodan: {len(shodan_ports)} open ports on {ip}",
                evidence=f"Services: {svc_summary}",
                tags=["recon", "shodan"],
            ))

        if not findings:
            findings.append(Finding.info(
                f"Shodan: no additional data for {ip}",
                tags=["recon", "shodan"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "ip": ip,
                "ports": shodan_ports,
                "services": services,
                "org": org,
                "asn": asn,
                "os": os_info,
                "missed_ports": sorted(missed_ports),
            },
        )
