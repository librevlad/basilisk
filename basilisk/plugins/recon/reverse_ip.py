"""Reverse IP lookup — find other domains hosted on the same IP.

Enhanced with multiple data sources (HackerTarget, ViewDNS, PTR lookup),
result deduplication, domain validation, and shared hosting detection.
"""

from __future__ import annotations

import re
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

# Simple pattern: valid domain label chars, at least one dot, valid TLD
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,63}$"
)

# Threshold for shared-hosting detection
_SHARED_HOSTING_THRESHOLD = 20


class ReverseIpPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="reverse_ip",
        display_name="Reverse IP Lookup",
        category=PluginCategory.RECON,
        description=(
            "Finds other domains sharing the same IP via HackerTarget, "
            "ViewDNS.info HTML scrape, and PTR DNS lookup"
        ),
        depends_on=["dns_enum"],
        produces=["shared_hosts"],
        timeout=20.0,
    )

    def accepts(self, target: Target) -> bool:
        return bool(target.ips)

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None and ctx.dns is None:
            return PluginResult.fail(
                self.meta.name, target.host,
                error="Neither HTTP nor DNS client available",
            )

        # Collect per-IP results from all sources
        per_ip: dict[str, set[str]] = {}

        for ip in target.ips[:3]:
            hosts: set[str] = set()

            # Source 1: HackerTarget API
            if ctx.http is not None:
                ht_hosts = await self._query_hackertarget(ctx, ip)
                hosts.update(ht_hosts)

            # Source 2: ViewDNS.info HTML scrape
            if ctx.http is not None and not ctx.should_stop:
                vd_hosts = await self._query_viewdns(ctx, ip)
                hosts.update(vd_hosts)

            # Source 3: PTR record via DNS
            if ctx.dns is not None and not ctx.should_stop:
                ptr_hosts = await self._query_ptr(ctx, ip)
                hosts.update(ptr_hosts)

            # Remove target itself and validate
            hosts.discard(target.host)
            validated = {h for h in hosts if self._is_valid_domain(h)}
            per_ip[ip] = validated

        # Merge and deduplicate across all IPs
        all_hosts: set[str] = set()
        for hosts in per_ip.values():
            all_hosts.update(hosts)

        sorted_hosts = sorted(all_hosts)

        # Build findings
        findings: list[Finding] = []

        if sorted_hosts:
            findings.append(Finding.info(
                f"Reverse IP: {len(sorted_hosts)} shared hosts found",
                evidence=", ".join(sorted_hosts[:20]),
                tags=["recon", "reverse-ip"],
            ))

            # Shared hosting detection
            for ip, hosts in per_ip.items():
                if len(hosts) >= _SHARED_HOSTING_THRESHOLD:
                    findings.append(Finding.low(
                        f"Potential shared hosting on {ip} "
                        f"({len(hosts)} domains)",
                        description=(
                            "Many domains share this IP address, indicating shared "
                            "hosting. Other tenants' vulnerabilities could affect "
                            "the target."
                        ),
                        evidence=", ".join(sorted(hosts)[:15]),
                        remediation=(
                            "Consider dedicated hosting or a CDN to isolate from "
                            "co-tenants"
                        ),
                        tags=["recon", "reverse-ip", "shared-hosting"],
                    ))
        else:
            findings.append(Finding.info(
                "Reverse IP: no shared hosts found",
                tags=["recon", "reverse-ip"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "shared_hosts": sorted_hosts,
                "per_ip": {ip: sorted(hosts) for ip, hosts in per_ip.items()},
            },
        )

    # ------------------------------------------------------------------
    # Data sources
    # ------------------------------------------------------------------

    @staticmethod
    async def _query_hackertarget(ctx, ip: str) -> set[str]:
        """Query api.hackertarget.com for reverse IP data."""
        hosts: set[str] = set()
        url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
        try:
            async with ctx.rate:
                text = await ctx.http.fetch_text(url, timeout=10.0)
            if not text or "error" in text.lower()[:50]:
                return hosts
            for line in text.strip().splitlines():
                host = line.strip().lower()
                if host:
                    hosts.add(host)
        except Exception:
            pass
        return hosts

    @staticmethod
    async def _query_viewdns(ctx, ip: str) -> set[str]:
        """Scrape ViewDNS.info reverse IP page for domain names."""
        hosts: set[str] = set()
        url = f"https://viewdns.info/reverseip/?host={ip}&t=1"
        try:
            async with ctx.rate:
                resp = await ctx.http.get(
                    url, timeout=10.0,
                    headers={"User-Agent": "Mozilla/5.0"},
                )
                if resp.status != 200:
                    return hosts
                body = await resp.text(encoding="utf-8", errors="replace")

            # ViewDNS puts results in table rows like <td>domain.com</td>
            for match in re.findall(
                r"<td>([a-zA-Z0-9][\w.-]+\.[a-zA-Z]{2,})</td>", body,
            ):
                hosts.add(match.strip().lower())
        except Exception:
            pass
        return hosts

    @staticmethod
    async def _query_ptr(ctx, ip: str) -> set[str]:
        """PTR record lookup via DNS client."""
        hosts: set[str] = set()
        try:
            ptr_results = await ctx.dns.reverse_lookup(ip)
            for name in ptr_results:
                cleaned = name.strip(".").lower()
                if cleaned:
                    hosts.add(cleaned)
        except Exception:
            pass
        return hosts

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    @staticmethod
    def _is_valid_domain(value: str) -> bool:
        """Return True if value looks like a valid domain name."""
        if not value or len(value) > 253:
            return False
        # Reject bare IPs and common error strings
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value):
            return False
        return bool(_DOMAIN_RE.match(value))
