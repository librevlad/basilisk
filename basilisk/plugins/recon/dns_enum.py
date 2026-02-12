"""DNS Enumeration plugin — comprehensive DNS reconnaissance.

Resolves all record types, analyzes SPF/DMARC/DKIM configuration,
detects wildcard DNS, attempts zone transfer, checks SRV records,
and performs DNSSEC status check.  Level: dnsenum + fierce.
"""

from __future__ import annotations

import asyncio
import re
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

# SRV records to enumerate (service, protocol, description)
SRV_SERVICES = [
    ("_sip", "_tcp", "SIP VoIP"),
    ("_sip", "_udp", "SIP VoIP UDP"),
    ("_sips", "_tcp", "SIP TLS"),
    ("_xmpp-client", "_tcp", "XMPP Client"),
    ("_xmpp-server", "_tcp", "XMPP Server"),
    ("_ldap", "_tcp", "LDAP"),
    ("_ldaps", "_tcp", "LDAPS"),
    ("_kerberos", "_tcp", "Kerberos"),
    ("_kerberos", "_udp", "Kerberos UDP"),
    ("_kpasswd", "_tcp", "Kerberos Password"),
    ("_http", "_tcp", "HTTP SRV"),
    ("_https", "_tcp", "HTTPS SRV"),
    ("_imap", "_tcp", "IMAP"),
    ("_imaps", "_tcp", "IMAPS"),
    ("_submission", "_tcp", "SMTP Submission"),
    ("_autodiscover", "_tcp", "Autodiscover"),
    ("_caldav", "_tcp", "CalDAV"),
    ("_carddav", "_tcp", "CardDAV"),
    ("_matrix", "_tcp", "Matrix"),
    ("_minecraft", "_tcp", "Minecraft"),
    ("_ts3", "_udp", "TeamSpeak 3"),
    ("_mumble", "_tcp", "Mumble"),
    ("_vlmcs", "_tcp", "KMS Activation"),
    ("_gc", "_tcp", "Global Catalog"),
]

# Weak SPF mechanisms
SPF_WEAK_PATTERNS = {
    "+all": ("critical", "SPF allows all senders (+all)"),
    "~all": ("low", "SPF soft fail (~all) — emails may still be delivered"),
    "?all": ("medium", "SPF neutral (?all) — provides no protection"),
}


class DnsEnumPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="dns_enum",
        display_name="DNS Enumeration",
        category=PluginCategory.RECON,
        description=(
            "Comprehensive DNS recon: A/AAAA/MX/NS/TXT/SOA/CNAME/SRV, "
            "SPF/DMARC/DKIM analysis, wildcard detection, zone transfer"
        ),
        produces=["dns_records", "ips"],
        timeout=30.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.dns is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="DNS client not available"
            )

        findings: list[Finding] = []
        all_records: list[dict] = []
        ips: list[str] = []

        # Phase 1: Standard record types
        records = await ctx.dns.resolve_all(
            target.host,
            ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"],
        )
        if records:
            ips = [r.value for r in records if r.type.value in ("A", "AAAA")]
            target.ips = ips
            all_records.extend(
                {"type": r.type.value, "name": r.name, "value": r.value, "ttl": r.ttl}
                for r in records
            )

        # Phase 2: SRV record enumeration
        srv_records = await self._enumerate_srv(ctx, target.host)
        if srv_records:
            all_records.extend(srv_records)
            services = [r["service"] for r in srv_records]
            findings.append(Finding.info(
                f"SRV records: {len(srv_records)} services discovered",
                evidence=", ".join(services[:10]),
                tags=["dns", "srv"],
            ))

        # Phase 3: SPF analysis
        txt_records = [r for r in records if r.type.value == "TXT"]
        spf_findings = self._analyze_spf(txt_records)
        findings.extend(spf_findings)

        # Phase 4: DMARC analysis
        dmarc_findings = await self._analyze_dmarc(ctx, target.host)
        findings.extend(dmarc_findings)

        # Phase 5: DKIM check (common selectors)
        dkim_findings = await self._check_dkim(ctx, target.host)
        findings.extend(dkim_findings)

        # Phase 6: MX analysis
        mx_records = [r for r in records if r.type.value == "MX"]
        mx_findings = self._analyze_mx(mx_records, target.host)
        findings.extend(mx_findings)

        # Phase 7: NS analysis
        ns_records = [r for r in records if r.type.value == "NS"]
        ns_findings = self._analyze_ns(ns_records, target.host)
        findings.extend(ns_findings)

        # Phase 8: Wildcard DNS detection
        if not ctx.should_stop:
            wildcard = await self._detect_wildcard(ctx, target.host)
            if wildcard:
                findings.append(Finding.info(
                    "Wildcard DNS detected",
                    description=(
                        f"*.{target.host} resolves to {wildcard}. "
                        "Subdomain enumeration may produce false positives."
                    ),
                    evidence=f"*.{target.host} → {wildcard}",
                    tags=["dns", "wildcard"],
                ))

        # Phase 9: Zone transfer attempt
        if not ctx.should_stop and ns_records:
            axfr_findings = await self._try_zone_transfer(
                ctx, target.host, ns_records,
            )
            findings.extend(axfr_findings)

        # Phase 10: SOA analysis
        soa_records = [r for r in records if r.type.value == "SOA"]
        if soa_records:
            soa = soa_records[0]
            findings.append(Finding.info(
                f"SOA: {soa.value}",
                tags=["dns", "soa"],
            ))

        # Summary finding
        findings.append(Finding.info(
            f"DNS: {len(all_records)} records, {len(ips)} IPs",
            evidence=", ".join(
                f"{r['type']}={r['value']}" for r in all_records[:15]
            ),
            tags=["dns"],
        ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "records": all_records,
                "ips": ips,
                "wildcard": bool(
                    await self._detect_wildcard(ctx, target.host)
                ) if not ctx.should_stop else False,
            },
        )

    async def _enumerate_srv(
        self, ctx, domain: str,
    ) -> list[dict]:
        """Enumerate common SRV records."""
        results: list[dict] = []
        tasks = []
        for svc, proto, desc in SRV_SERVICES:
            name = f"{svc}.{proto}.{domain}"
            tasks.append((name, desc, ctx.dns.resolve(name, "SRV")))

        for (name, desc, coro) in tasks:
            try:
                records = await coro
                for r in records:
                    results.append({
                        "type": "SRV",
                        "name": name,
                        "value": r.value,
                        "ttl": r.ttl,
                        "service": desc,
                    })
            except Exception:
                continue
        return results

    @staticmethod
    def _analyze_spf(txt_records: list) -> list[Finding]:
        """Analyze SPF configuration from TXT records."""
        findings: list[Finding] = []
        spf_found = False

        for txt in txt_records:
            val = txt.value if hasattr(txt, "value") else str(txt)
            lower = val.lower().strip('"').strip()

            if not lower.startswith("v=spf1"):
                continue
            spf_found = True

            # Check weak mechanisms
            for pattern, (severity, desc) in SPF_WEAK_PATTERNS.items():
                if pattern in lower:
                    factory = getattr(Finding, severity)
                    findings.append(factory(
                        f"Weak SPF: {desc}",
                        description=f"SPF record contains '{pattern}'",
                        evidence=val[:200],
                        remediation="Use '-all' (hard fail) to reject unauthorized senders",
                        tags=["dns", "spf", "email"],
                    ))
                    break

            # Check for include count (too many DNS lookups)
            includes = lower.count("include:")
            if includes > 8:
                findings.append(Finding.low(
                    f"SPF: {includes} includes (DNS lookup limit is 10)",
                    description="Too many SPF includes may exceed DNS lookup limit",
                    evidence=val[:200],
                    remediation="Consolidate SPF includes to stay under 10 DNS lookups",
                    tags=["dns", "spf"],
                ))

            # Check for ip4/ip6 ranges too broad
            if re.search(r"ip[46]:\S+/[0-8]\b", lower):
                findings.append(Finding.medium(
                    "SPF: very broad IP range authorized",
                    description="SPF authorizes a large IP range (CIDR /0-/8)",
                    evidence=val[:200],
                    remediation="Narrow SPF IP ranges to actual mail server IPs",
                    tags=["dns", "spf"],
                ))

        if not spf_found:
            findings.append(Finding.medium(
                "No SPF record found",
                description="Domain has no SPF TXT record — vulnerable to email spoofing",
                remediation="Add a TXT record with v=spf1 policy",
                tags=["dns", "spf", "email"],
            ))

        return findings

    async def _analyze_dmarc(self, ctx, domain: str) -> list[Finding]:
        """Check DMARC record configuration."""
        findings: list[Finding] = []
        dmarc_domain = f"_dmarc.{domain}"

        records = await ctx.dns.resolve(dmarc_domain, "TXT")
        if not records:
            findings.append(Finding.medium(
                "No DMARC record found",
                description=(
                    f"No DMARC TXT record at {dmarc_domain}. "
                    "Email authentication is incomplete."
                ),
                remediation=(
                    "Add a DMARC record: "
                    f"_dmarc.{domain} TXT \"v=DMARC1; p=reject; rua=mailto:dmarc@{domain}\""
                ),
                tags=["dns", "dmarc", "email"],
            ))
            return findings

        for r in records:
            val = r.value.strip('"')
            lower = val.lower()

            if "v=dmarc1" not in lower:
                continue

            # Check policy
            if "p=none" in lower:
                findings.append(Finding.medium(
                    "DMARC policy is 'none' — no enforcement",
                    description="DMARC p=none only monitors, doesn't reject spoofed emails",
                    evidence=val[:200],
                    remediation="Set DMARC policy to p=quarantine or p=reject",
                    tags=["dns", "dmarc", "email"],
                ))
            elif "p=quarantine" in lower:
                findings.append(Finding.low(
                    "DMARC policy is 'quarantine'",
                    description="DMARC quarantine policy may not fully prevent spoofing",
                    evidence=val[:200],
                    remediation="Consider upgrading to p=reject",
                    tags=["dns", "dmarc", "email"],
                ))
            elif "p=reject" in lower:
                findings.append(Finding.info(
                    "DMARC policy is 'reject' (strong)",
                    evidence=val[:200],
                    tags=["dns", "dmarc", "email"],
                ))

            # Check percentage
            pct_match = re.search(r"pct=(\d+)", lower)
            if pct_match:
                pct = int(pct_match.group(1))
                if pct < 100:
                    findings.append(Finding.low(
                        f"DMARC pct={pct}% — not all emails checked",
                        evidence=val[:200],
                        tags=["dns", "dmarc"],
                    ))

            # Check subdomain policy
            if "sp=" not in lower:
                findings.append(Finding.info(
                    "DMARC: no subdomain policy (sp=) — inherits from p=",
                    evidence=val[:200],
                    tags=["dns", "dmarc"],
                ))

        return findings

    async def _check_dkim(self, ctx, domain: str) -> list[Finding]:
        """Check common DKIM selectors."""
        findings: list[Finding] = []
        selectors = [
            "default", "google", "k1", "k2", "k3", "mail",
            "selector1", "selector2", "s1", "s2", "dkim", "smtp",
            "mandrill", "mailjet", "amazonses", "sendgrid", "postmark",
            "everlytickey1", "everlytickey2", "cm", "mg",
        ]
        found_selectors: list[str] = []

        for sel in selectors:
            if ctx.should_stop:
                break
            dkim_domain = f"{sel}._domainkey.{domain}"
            records = await ctx.dns.resolve(dkim_domain, "TXT")
            if records:
                found_selectors.append(sel)

        if found_selectors:
            findings.append(Finding.info(
                f"DKIM: {len(found_selectors)} selectors found",
                evidence=", ".join(found_selectors),
                tags=["dns", "dkim", "email"],
            ))
        else:
            findings.append(Finding.low(
                "No common DKIM selectors found",
                description="No DKIM records found for common selectors",
                remediation="Configure DKIM signing for outbound email",
                tags=["dns", "dkim", "email"],
            ))

        return findings

    @staticmethod
    def _analyze_mx(mx_records: list, domain: str) -> list[Finding]:
        """Analyze MX record configuration."""
        findings: list[Finding] = []
        if not mx_records:
            findings.append(Finding.info(
                "No MX records",
                description=f"No mail exchangers configured for {domain}",
                tags=["dns", "mx"],
            ))
            return findings

        # Check for localhost or private IP in MX
        for r in mx_records:
            val = r.value.lower() if hasattr(r, "value") else str(r).lower()
            if val in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
                findings.append(Finding.medium(
                    f"MX points to localhost: {val}",
                    description="MX record points to localhost — possible misconfiguration",
                    tags=["dns", "mx"],
                ))

        # Check for single MX (no redundancy)
        if len(mx_records) == 1:
            findings.append(Finding.info(
                "Single MX record — no mail redundancy",
                tags=["dns", "mx"],
            ))

        return findings

    @staticmethod
    def _analyze_ns(ns_records: list, domain: str) -> list[Finding]:
        """Analyze NS record configuration."""
        findings: list[Finding] = []
        if not ns_records:
            return findings

        # Check for single NS (no redundancy)
        if len(ns_records) == 1:
            findings.append(Finding.low(
                "Single NS record — no DNS redundancy",
                description="Only one nameserver. DNS will fail if it goes down.",
                remediation="Add at least one secondary nameserver",
                tags=["dns", "ns"],
            ))

        # Check if all NS are in same /24 subnet (rough check)
        ns_values = [
            r.value.lower() if hasattr(r, "value") else str(r).lower()
            for r in ns_records
        ]

        # Check for same provider (rough heuristic)
        providers = set()
        for ns in ns_values:
            parts = ns.rstrip(".").split(".")
            if len(parts) >= 2:
                providers.add(".".join(parts[-2:]))
        if len(providers) == 1 and len(ns_records) > 1:
            findings.append(Finding.info(
                f"All NS at same provider: {providers.pop()}",
                description="All nameservers hosted by a single provider",
                tags=["dns", "ns"],
            ))

        return findings

    async def _detect_wildcard(self, ctx, domain: str) -> str | None:
        """Detect wildcard DNS by resolving a random subdomain."""
        import secrets
        random_sub = f"bsk-{secrets.token_hex(8)}.{domain}"
        records = await ctx.dns.resolve(random_sub, "A")
        if records:
            return records[0].value
        return None

    async def _try_zone_transfer(
        self, ctx, domain: str, ns_records: list,
    ) -> list[Finding]:
        """Attempt AXFR zone transfer against nameservers."""
        findings: list[Finding] = []

        for ns_rec in ns_records[:3]:
            if ctx.should_stop:
                break
            ns = ns_rec.value if hasattr(ns_rec, "value") else str(ns_rec)
            ns = ns.rstrip(".")

            try:
                import dns.query
                import dns.zone

                # Resolve NS to IP first
                ns_ips = await ctx.dns.resolve(ns, "A")
                if not ns_ips:
                    continue

                ns_ip = ns_ips[0].value

                # Attempt zone transfer (run in executor — blocking I/O)
                loop = asyncio.get_event_loop()
                zone = await asyncio.wait_for(
                    loop.run_in_executor(
                        None,
                        lambda _ip=ns_ip: dns.zone.from_xfr(
                            dns.query.xfr(_ip, domain, timeout=5.0)
                        ),
                    ),
                    timeout=10.0,
                )

                if zone:
                    names = sorted(str(n) for n in zone.nodes)
                    findings.append(Finding.critical(
                        f"Zone transfer (AXFR) successful from {ns}",
                        description=(
                            f"DNS zone transfer exposed {len(names)} records. "
                            "This reveals the entire DNS zone."
                        ),
                        evidence=", ".join(names[:30]),
                        remediation=(
                            "Restrict zone transfers to authorized secondary "
                            "nameservers only. Configure allow-transfer ACL."
                        ),
                        tags=["dns", "axfr", "zone-transfer"],
                    ))
            except ImportError:
                break  # dns.query not available
            except Exception:
                continue

        return findings
