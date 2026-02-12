"""IPv6 support detection, connectivity, and security analysis."""

from __future__ import annotations

import ipaddress
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

# Well-known 6to4 prefix (2002::/16) — deprecated, security risk (RFC 7526)
_6TO4_PREFIX = ipaddress.IPv6Network("2002::/16")

# Teredo prefix (2001:0000::/32) — deprecated tunneling, security risk
_TEREDO_PREFIX = ipaddress.IPv6Network("2001::/32")

# Documentation prefix — should not appear in production DNS
_DOC_PREFIX = ipaddress.IPv6Network("2001:db8::/32")


def _classify_ipv6(addr_str: str) -> dict[str, bool]:
    """Classify an IPv6 address for security properties."""
    try:
        addr = ipaddress.IPv6Address(addr_str)
    except ValueError:
        return {}
    return {
        "is_link_local": addr.is_link_local,            # fe80::/10
        "is_loopback": addr.is_loopback,                 # ::1
        "is_6to4": addr in _6TO4_PREFIX,                  # 2002::/16
        "is_teredo": addr in _TEREDO_PREFIX,              # 2001::/32
        "is_documentation": addr in _DOC_PREFIX,          # 2001:db8::/32
        "is_private": addr.is_private,
        "is_global": addr.is_global,
    }


def _extract_subnet(addr_str: str, prefix_len: int = 64) -> str | None:
    """Extract the /prefix_len subnet from an IPv6 address."""
    try:
        net = ipaddress.IPv6Network(f"{addr_str}/{prefix_len}", strict=False)
        return str(net)
    except ValueError:
        return None


class Ipv6ScanPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="ipv6_scan",
        display_name="IPv6 Scanner",
        category=PluginCategory.SCANNING,
        description="Detects IPv6 support, connectivity, and security issues",
        depends_on=["dns_enum"],
        produces=["ipv6_info"],
        timeout=30.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.dns is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="DNS client not available"
            )

        findings: list[Finding] = []
        ipv6_addrs: list[str] = []
        ipv4_addrs: list[str] = []

        # ── Resolve AAAA records ──────────────────────────────────────
        try:
            aaaa_records = await ctx.dns.resolve(target.host, "AAAA")
            ipv6_addrs = [r.value for r in aaaa_records] if aaaa_records else []
        except Exception:
            pass

        # ── Resolve A records for comparison ──────────────────────────
        try:
            a_records = await ctx.dns.resolve(target.host, "A")
            ipv4_addrs = [r.value for r in a_records] if a_records else []
        except Exception:
            pass

        has_ipv6 = bool(ipv6_addrs)
        dual_stack = bool(ipv6_addrs and ipv4_addrs)
        ipv6_reachable = False
        discrepancy_detected = False

        if not has_ipv6:
            findings.append(Finding.info(
                "No IPv6 (AAAA) records found",
                tags=["scanning", "ipv6"],
            ))
            return PluginResult.success(
                self.meta.name, target.host,
                findings=findings,
                data={
                    "ipv6_addresses": [],
                    "ipv4_addresses": ipv4_addrs,
                    "has_ipv6": False,
                    "dual_stack": False,
                    "ipv6_reachable": False,
                    "discrepancy": False,
                },
            )

        findings.append(Finding.info(
            f"IPv6 enabled: {len(ipv6_addrs)} AAAA record(s)",
            evidence=", ".join(ipv6_addrs),
            tags=["scanning", "ipv6"],
        ))

        if dual_stack:
            findings.append(Finding.info(
                "Dual-stack configuration (IPv4 + IPv6)",
                evidence=(
                    f"IPv4: {', '.join(ipv4_addrs)}, "
                    f"IPv6: {', '.join(ipv6_addrs)}"
                ),
                tags=["scanning", "ipv6"],
            ))

        # ── IPv6-specific security checks ─────────────────────────────
        for addr_str in ipv6_addrs:
            props = _classify_ipv6(addr_str)
            if not props:
                continue

            if props.get("is_link_local"):
                findings.append(Finding.medium(
                    f"Link-local IPv6 address in DNS: {addr_str}",
                    description=(
                        "Link-local addresses (fe80::/10) should never appear "
                        "in public DNS. This may leak internal network topology."
                    ),
                    remediation="Remove link-local AAAA records from public DNS",
                    tags=["scanning", "ipv6", "misconfiguration"],
                ))

            if props.get("is_6to4"):
                findings.append(Finding.medium(
                    f"Deprecated 6to4 tunnel address detected: {addr_str}",
                    description=(
                        "6to4 (2002::/16) is deprecated per RFC 7526 due to "
                        "security risks including traffic interception and "
                        "routing instability."
                    ),
                    remediation="Migrate from 6to4 to native IPv6 connectivity",
                    tags=["scanning", "ipv6", "deprecated"],
                ))

            if props.get("is_teredo"):
                findings.append(Finding.medium(
                    f"Teredo tunnel address detected: {addr_str}",
                    description=(
                        "Teredo (2001::/32) tunneling is deprecated for "
                        "server use. It bypasses firewalls by design and "
                        "is vulnerable to relay attacks."
                    ),
                    remediation="Replace Teredo with native IPv6 connectivity",
                    tags=["scanning", "ipv6", "deprecated"],
                ))

            if props.get("is_documentation"):
                findings.append(Finding.low(
                    f"Documentation prefix in DNS: {addr_str}",
                    description=(
                        "Address 2001:db8::/32 is reserved for documentation "
                        "and must not be used in production (RFC 3849)."
                    ),
                    remediation="Replace documentation prefix with real IPv6 address",
                    tags=["scanning", "ipv6", "misconfiguration"],
                ))

            if props.get("is_loopback"):
                findings.append(Finding.low(
                    f"Loopback IPv6 address in DNS: {addr_str}",
                    description="::1 in public DNS is a misconfiguration.",
                    remediation="Remove loopback AAAA record from public DNS",
                    tags=["scanning", "ipv6", "misconfiguration"],
                ))

        # ── Multiple AAAA subnet analysis ─────────────────────────────
        if len(ipv6_addrs) > 1:
            subnets = set()
            for addr_str in ipv6_addrs:
                subnet = _extract_subnet(addr_str)
                if subnet:
                    subnets.add(subnet)
            if len(subnets) > 1:
                findings.append(Finding.info(
                    f"Multiple IPv6 subnets detected ({len(subnets)} /64 blocks)",
                    description=(
                        "IPv6 addresses span multiple /64 subnets, indicating "
                        "multi-homed hosting or load balancing across segments."
                    ),
                    evidence=", ".join(sorted(subnets)),
                    tags=["scanning", "ipv6"],
                ))
            else:
                findings.append(Finding.info(
                    f"All {len(ipv6_addrs)} IPv6 addresses in same /64 subnet",
                    evidence=", ".join(sorted(subnets)),
                    tags=["scanning", "ipv6"],
                ))

        # ── IPv6 connectivity test ────────────────────────────────────
        reachable_ports: list[int] = []
        if ctx.net is not None:
            test_addr = ipv6_addrs[0]
            for port in (443, 80):
                if ctx.should_stop:
                    break
                try:
                    result = await ctx.net.check_port(test_addr, port, timeout=5.0)
                    if result.state.value == "open":
                        reachable_ports.append(port)
                        ipv6_reachable = True
                except Exception:
                    pass

            if ipv6_reachable:
                findings.append(Finding.info(
                    f"IPv6 reachable on port(s): {', '.join(map(str, reachable_ports))}",
                    evidence=f"Connected to [{test_addr}]",
                    tags=["scanning", "ipv6"],
                ))
            else:
                findings.append(Finding.info(
                    "IPv6 address not reachable on port 80/443",
                    description=(
                        "AAAA records exist but TCP connections to the IPv6 "
                        "address failed. The host may only serve traffic on IPv4."
                    ),
                    evidence=f"Tested [{test_addr}]:80 and :443",
                    tags=["scanning", "ipv6"],
                ))

        # ── IPv4 vs IPv6 HTTP response discrepancy ────────────────────
        if dual_stack and ipv6_reachable and ctx.http is not None:
            discrepancy_detected = await self._check_discrepancy(
                target, ctx, ipv6_addrs[0], findings,
            )

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "ipv6_addresses": ipv6_addrs,
                "ipv4_addresses": ipv4_addrs,
                "has_ipv6": has_ipv6,
                "dual_stack": dual_stack,
                "ipv6_reachable": ipv6_reachable,
                "reachable_ports": reachable_ports,
                "discrepancy": discrepancy_detected,
                "subnet_count": len({
                    _extract_subnet(a) for a in ipv6_addrs
                    if _extract_subnet(a)
                }),
            },
        )

    async def _check_discrepancy(
        self,
        target: Target,
        ctx,
        ipv6: str,
        findings: list[Finding],
    ) -> bool:
        """Compare HTTP responses via IPv4 and IPv6 to detect WAF bypass."""
        ipv4_status: int | None = None
        ipv6_status: int | None = None
        ipv4_server = ""
        ipv6_server = ""
        ipv4_body_len = 0
        ipv6_body_len = 0

        # Fetch via normal hostname (IPv4 will typically be preferred)
        for scheme in ("https", "http"):
            if ctx.should_stop:
                return False
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(
                        f"{scheme}://{target.host}/",
                        timeout=8.0,
                    )
                    ipv4_status = resp.status
                    ipv4_server = resp.headers.get("Server", "")
                    body = await resp.text(encoding="utf-8", errors="replace")
                    ipv4_body_len = len(body)
                    break
            except Exception:
                continue

        # Fetch via IPv6 literal with Host header
        for scheme in ("https", "http"):
            if ctx.should_stop:
                return False
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(
                        f"{scheme}://[{ipv6}]/",
                        headers={"Host": target.host},
                        timeout=8.0,
                    )
                    ipv6_status = resp.status
                    ipv6_server = resp.headers.get("Server", "")
                    body = await resp.text(encoding="utf-8", errors="replace")
                    ipv6_body_len = len(body)
                    break
            except Exception:
                continue

        if ipv4_status is None or ipv6_status is None:
            return False

        # Detect discrepancies
        discrepancy = False

        if ipv4_server.lower() != ipv6_server.lower():
            discrepancy = True
            findings.append(Finding.medium(
                "Different Server header on IPv4 vs IPv6",
                description=(
                    "The Server header differs between IPv4 and IPv6 responses. "
                    "This may indicate the IPv6 endpoint bypasses a WAF or "
                    "reverse proxy that only protects IPv4 traffic."
                ),
                evidence=f"IPv4: {ipv4_server!r}, IPv6: {ipv6_server!r}",
                remediation=(
                    "Ensure WAF/proxy covers both IPv4 and IPv6 endpoints"
                ),
                tags=["scanning", "ipv6", "waf-bypass"],
            ))

        if ipv4_status != ipv6_status:
            discrepancy = True
            findings.append(Finding.low(
                "Different HTTP status on IPv4 vs IPv6",
                evidence=f"IPv4: {ipv4_status}, IPv6: {ipv6_status}",
                tags=["scanning", "ipv6", "discrepancy"],
            ))

        # Large body size difference can indicate different backends
        if ipv4_body_len and ipv6_body_len:
            ratio = abs(ipv4_body_len - ipv6_body_len) / max(
                ipv4_body_len, ipv6_body_len
            )
            if ratio > 0.3:
                discrepancy = True
                findings.append(Finding.low(
                    "Significant body size difference between IPv4 and IPv6",
                    description=(
                        f"Response body lengths differ by {ratio:.0%}, "
                        "suggesting different backends or content."
                    ),
                    evidence=(
                        f"IPv4: {ipv4_body_len} bytes, "
                        f"IPv6: {ipv6_body_len} bytes"
                    ),
                    tags=["scanning", "ipv6", "discrepancy"],
                ))

        if not discrepancy:
            findings.append(Finding.info(
                "IPv4 and IPv6 responses are consistent",
                evidence=(
                    f"Both return status {ipv4_status}, "
                    f"Server: {ipv4_server!r}"
                ),
                tags=["scanning", "ipv6"],
            ))

        return discrepancy
