"""WHOIS + RDAP lookup plugin — domain registration info.

Enhanced with RDAP JSON protocol, ASN lookup, domain age calculation,
registrar abuse contact, related domains, and comprehensive parsing.
Level: whois + RDAP enrichment.
"""

from __future__ import annotations

import asyncio
import json
import socket
from datetime import UTC, datetime
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class WhoisPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="whois",
        display_name="WHOIS + RDAP Lookup",
        category=PluginCategory.RECON,
        description=(
            "Domain registration via WHOIS and RDAP: registrar, dates, "
            "nameservers, ASN, domain age, abuse contact"
        ),
        produces=["whois_info"],
        timeout=20.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        whois_data: dict = {}
        rdap_data: dict = {}

        # Use base domain for WHOIS (not subdomain)
        domain = self._extract_base_domain(target.host)

        # Check cache (one WHOIS per domain, not per subdomain)
        cache_key = f"whois_cache:{domain}"
        cached = ctx.state.get(cache_key)
        if cached:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=cached["findings"],
                data=cached["data"],
            )

        # Phase 1: Try RDAP first (structured JSON, preferred)
        if ctx.http is not None:
            rdap_data = await self._query_rdap(ctx, domain)

        # Phase 2: Traditional WHOIS with retry
        whois_text = ""
        for attempt in range(3):
            try:
                whois_text = await asyncio.wait_for(
                    self._query_whois(domain), timeout=10.0,
                )
                if whois_text.strip():
                    break
            except Exception:
                if attempt < 2:
                    await asyncio.sleep(1.0 * (attempt + 1))

        # Phase 3: Parse WHOIS
        if whois_text:
            whois_data = self._parse_whois(whois_text)

        # Merge RDAP + WHOIS data (RDAP takes priority)
        merged = {**whois_data, **{k: v for k, v in rdap_data.items() if v}}

        if not merged and not whois_text:
            return PluginResult.fail(
                self.meta.name, target.host,
                error="Both RDAP and WHOIS queries failed",
            )

        # Domain age analysis
        creation = merged.get("creation_date", "")
        if creation:
            age_finding = self._analyze_domain_age(creation, target.host)
            if age_finding:
                findings.append(age_finding)

        # Expiration warning
        expiry = merged.get("expiration_date", "")
        if expiry:
            exp_finding = self._check_expiration(expiry, target.host)
            if exp_finding:
                findings.append(exp_finding)

        # Registrar info
        registrar = merged.get("registrar", "Unknown")
        findings.append(Finding.info(
            f"WHOIS: {registrar}",
            evidence=(
                f"Registrar: {registrar}\n"
                f"Created: {merged.get('creation_date', 'N/A')}\n"
                f"Expires: {merged.get('expiration_date', 'N/A')}\n"
                f"Status: {merged.get('status', 'N/A')}"
            ),
            tags=["recon", "whois"],
        ))

        # DNSSEC status
        if merged.get("dnssec"):
            dnssec_val = merged["dnssec"].lower()
            if "unsigned" in dnssec_val:
                findings.append(Finding.low(
                    "DNSSEC not enabled",
                    description="Domain is not signed with DNSSEC",
                    remediation="Enable DNSSEC to protect against DNS spoofing",
                    tags=["whois", "dnssec"],
                ))

        # Privacy/proxy registration
        registrant = merged.get("registrant", "")
        if registrant and any(
            kw in registrant.lower()
            for kw in ("privacy", "proxy", "redacted", "whoisguard", "domains by proxy")
        ):
            findings.append(Finding.info(
                "Domain uses privacy/proxy registration",
                evidence=f"Registrant: {registrant}",
                tags=["whois", "privacy"],
            ))

        # Phase 4: ASN/IP lookup
        if ctx.http is not None and not ctx.should_stop:
            asn_info = await self._lookup_asn(ctx, target.host)
            if asn_info:
                merged["asn"] = asn_info
                findings.append(Finding.info(
                    f"ASN: {asn_info.get('asn', 'N/A')} — {asn_info.get('org', 'N/A')}",
                    evidence=(
                        f"ASN: {asn_info.get('asn', '')}\n"
                        f"Org: {asn_info.get('org', '')}\n"
                        f"Range: {asn_info.get('range', '')}\n"
                        f"Country: {asn_info.get('country', '')}"
                    ),
                    tags=["whois", "asn"],
                ))

        result_data = {
            "whois_raw": whois_text, "whois_parsed": merged, "rdap": rdap_data,
        }
        # Cache for subdomains
        ctx.state[cache_key] = {"findings": findings, "data": result_data}

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data=result_data,
        )

    async def _query_rdap(self, ctx, domain: str) -> dict:
        """Query RDAP for structured domain info."""
        tld = domain.rsplit(".", 1)[-1]
        rdap_base = self._get_rdap_server(tld)
        if not rdap_base:
            return {}

        try:
            url = f"{rdap_base}domain/{domain}"
            async with ctx.rate:
                resp = await ctx.http.get(
                    url,
                    headers={"Accept": "application/rdap+json"},
                    timeout=10.0,
                )
                if resp.status != 200:
                    return {}
                text = await resp.text(encoding="utf-8", errors="replace")
                data = json.loads(text)
                return self._parse_rdap(data)
        except Exception:
            return {}

    @staticmethod
    def _get_rdap_server(tld: str) -> str:
        """Get RDAP server URL for a TLD."""
        servers = {
            "com": "https://rdap.verisign.com/com/v1/",
            "net": "https://rdap.verisign.com/net/v1/",
            "org": "https://rdap.org/",
            "io": "https://rdap.nic.io/",
            "dev": "https://rdap.nic.google/",
            "app": "https://rdap.nic.google/",
            "ru": "https://rdap.tcinet.ru/",
            "uk": "https://rdap.nominet.uk/",
            "de": "https://rdap.denic.de/",
            "nl": "https://rdap.sidn.nl/",
            "au": "https://rdap.auda.org.au/",
        }
        return servers.get(tld, "")

    @staticmethod
    def _parse_rdap(data: dict) -> dict:
        """Parse RDAP JSON response into flat dict."""
        info: dict = {}

        # Handle
        info["domain_handle"] = data.get("handle", "")

        # Events (registration/expiration dates)
        for event in data.get("events", []):
            action = event.get("eventAction", "")
            date = event.get("eventDate", "")
            if action == "registration":
                info["creation_date"] = date
            elif action == "expiration":
                info["expiration_date"] = date
            elif action == "last changed":
                info["updated_date"] = date

        # Status
        statuses = data.get("status", [])
        if statuses:
            info["status"] = ", ".join(statuses)

        # Nameservers
        ns_list = []
        for ns_obj in data.get("nameservers", []):
            ns_name = ns_obj.get("ldhName", "")
            if ns_name:
                ns_list.append(ns_name)
        if ns_list:
            info["name_servers"] = "; ".join(ns_list)

        # Entities (registrar, registrant)
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            vcard = entity.get("vcardArray", [None, []])
            name = ""
            if isinstance(vcard, list) and len(vcard) > 1:
                for field in vcard[1]:
                    if isinstance(field, list) and field[0] == "fn":
                        name = field[3] if len(field) > 3 else ""

            if "registrar" in roles:
                info["registrar"] = name or entity.get("handle", "")
            if "registrant" in roles:
                info["registrant"] = name or entity.get("handle", "")
            if "abuse" in roles:
                info["abuse_contact"] = name

        # DNSSEC
        secure_dns = data.get("secureDNS", {})
        if secure_dns:
            if secure_dns.get("delegationSigned"):
                info["dnssec"] = "signed"
            else:
                info["dnssec"] = "unsigned"

        return info

    async def _query_whois(self, domain: str) -> str:
        """Query WHOIS server for domain info with fallback servers."""
        tld = domain.rsplit(".", 1)[-1]
        whois_server = self._get_whois_server(tld)

        # For .ru/.рф: try multiple servers
        fallback_servers = self._get_fallback_servers(tld)
        servers_to_try = [whois_server] + [
            s for s in fallback_servers if s != whois_server
        ]

        loop = asyncio.get_event_loop()
        text = ""

        for server in servers_to_try:
            try:
                text = await loop.run_in_executor(
                    None, self._whois_tcp, domain, server,
                )
                if text and text.strip() and "error" not in text.lower()[:100]:
                    break
            except Exception:
                continue

        if not text:
            return ""

        # Follow referral if present
        if "Registrar WHOIS Server:" in text:
            for line in text.splitlines():
                if line.strip().startswith("Registrar WHOIS Server:"):
                    referral = line.split(":", 1)[1].strip()
                    if referral and referral != whois_server:
                        try:
                            text2 = await loop.run_in_executor(
                                None, self._whois_tcp, domain, referral,
                            )
                            if text2 and len(text2) > len(text):
                                text = text2
                        except Exception:
                            pass
                    break
        return text

    @staticmethod
    def _whois_tcp(domain: str, server: str, port: int = 43) -> str:
        """Raw TCP WHOIS query."""
        with socket.create_connection((server, port), timeout=10) as sock:
            sock.sendall(f"{domain}\r\n".encode())
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            return response.decode("utf-8", errors="replace")

    @staticmethod
    def _extract_base_domain(host: str) -> str:
        """Extract registrable domain (e.g. 'sub.example.ru' -> 'example.ru')."""
        parts = host.split(".")
        if len(parts) <= 2:
            return host
        # Handle .co.uk, .com.ru etc.
        if parts[-2] in ("co", "com", "org", "net", "ac", "gov"):
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])

    @staticmethod
    def _get_fallback_servers(tld: str) -> list[str]:
        """Get fallback WHOIS servers for TLDs with known issues."""
        fallbacks: dict[str, list[str]] = {
            "ru": ["whois.tcinet.ru", "whois.nic.ru", "whois.ripn.net"],
            "рф": ["whois.tcinet.ru", "whois.nic.ru"],
            "su": ["whois.tcinet.ru", "whois.ripn.net"],
        }
        return fallbacks.get(tld, [])

    @staticmethod
    def _get_whois_server(tld: str) -> str:
        servers = {
            "com": "whois.verisign-grs.com",
            "net": "whois.verisign-grs.com",
            "org": "whois.pir.org",
            "ru": "whois.tcinet.ru",
            "io": "whois.nic.io",
            "dev": "whois.nic.google",
            "app": "whois.nic.google",
            "uk": "whois.nic.uk",
            "de": "whois.denic.de",
            "fr": "whois.nic.fr",
            "nl": "whois.sidn.nl",
            "au": "whois.auda.org.au",
            "cn": "whois.cnnic.cn",
            "jp": "whois.jprs.jp",
            "br": "whois.registro.br",
            "in": "whois.registry.in",
            "eu": "whois.eu",
            "info": "whois.afilias.net",
            "biz": "whois.biz",
            "me": "whois.nic.me",
            "cc": "ccwhois.verisign-grs.com",
            "tv": "tvwhois.verisign-grs.com",
            "co": "whois.nic.co",
            "xyz": "whois.nic.xyz",
            "club": "whois.nic.club",
            "online": "whois.nic.online",
            "site": "whois.nic.site",
        }
        return servers.get(tld, f"whois.nic.{tld}")

    @staticmethod
    def _parse_whois(text: str) -> dict:
        """Extract key fields from WHOIS response."""
        info: dict[str, str] = {}
        field_map = {
            "registrar": ["Registrar:", "registrar:"],
            "creation_date": ["Creation Date:", "created:", "Registration Date:"],
            "expiration_date": [
                "Registry Expiry Date:", "Expiration Date:",
                "paid-till:", "Expiry Date:",
            ],
            "updated_date": ["Updated Date:", "last-modified:"],
            "name_servers": ["Name Server:", "nserver:"],
            "status": ["Domain Status:", "state:"],
            "registrant": [
                "Registrant Organization:", "Registrant Name:",
                "org:", "registrant:",
            ],
            "registrant_country": ["Registrant Country:", "country:"],
            "registrant_email": ["Registrant Email:"],
            "admin_email": ["Admin Email:"],
            "tech_email": ["Tech Email:"],
            "dnssec": ["DNSSEC:", "dnssec:"],
        }
        for key, prefixes in field_map.items():
            values = []
            for line in text.splitlines():
                line = line.strip()
                for prefix in prefixes:
                    if line.lower().startswith(prefix.lower()):
                        val = line[len(prefix):].strip()
                        if val:
                            values.append(val)
            if values:
                info[key] = values[0] if len(values) == 1 else "; ".join(values)
        return info

    @staticmethod
    def _analyze_domain_age(creation_str: str, domain: str) -> Finding | None:
        """Analyze domain age for potential phishing indicators."""
        try:
            # Try ISO format first
            for fmt in (
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%d",
                "%d-%b-%Y",
            ):
                try:
                    created = datetime.strptime(creation_str[:19], fmt[:19])
                    if created.tzinfo is None:
                        created = created.replace(tzinfo=UTC)
                    break
                except ValueError:
                    continue
            else:
                return None

            now = datetime.now(UTC)
            age_days = (now - created).days

            if age_days < 30:
                return Finding.high(
                    f"Very new domain ({age_days} days old)",
                    description=(
                        f"{domain} was registered {age_days} days ago. "
                        "Very new domains are often associated with phishing."
                    ),
                    evidence=f"Created: {creation_str}",
                    tags=["whois", "domain-age"],
                )
            elif age_days < 180:
                return Finding.medium(
                    f"Recently registered domain ({age_days} days old)",
                    description=f"{domain} was registered {age_days} days ago.",
                    evidence=f"Created: {creation_str}",
                    tags=["whois", "domain-age"],
                )
            else:
                years = age_days // 365
                return Finding.info(
                    f"Domain age: {years} years ({age_days} days)",
                    evidence=f"Created: {creation_str}",
                    tags=["whois", "domain-age"],
                )
        except Exception:
            return None

    @staticmethod
    def _check_expiration(expiry_str: str, domain: str) -> Finding | None:
        """Check if domain is expiring soon."""
        try:
            for fmt in (
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%d",
            ):
                try:
                    expires = datetime.strptime(expiry_str[:19], fmt[:19])
                    if expires.tzinfo is None:
                        expires = expires.replace(tzinfo=UTC)
                    break
                except ValueError:
                    continue
            else:
                return None

            days_left = (expires - datetime.now(UTC)).days
            if days_left < 0:
                return Finding.high(
                    f"Domain expired {abs(days_left)} days ago!",
                    evidence=f"Expires: {expiry_str}",
                    tags=["whois", "expiry"],
                )
            elif days_left < 30:
                return Finding.medium(
                    f"Domain expires in {days_left} days",
                    evidence=f"Expires: {expiry_str}",
                    remediation="Renew domain registration",
                    tags=["whois", "expiry"],
                )
            return None
        except Exception:
            return None

    async def _lookup_asn(self, ctx, domain: str) -> dict:
        """Look up ASN info for domain IP."""
        try:
            ips = await ctx.dns.get_ips(domain) if ctx.dns else []
            if not ips:
                return {}
            ip = ips[0]

            # Use ip-api.com or similar free API
            url = f"http://ip-api.com/json/{ip}?fields=as,org,country,regionName,isp,query"
            async with ctx.rate:
                resp = await ctx.http.get(url, timeout=5.0)
                if resp.status == 200:
                    text = await resp.text(encoding="utf-8", errors="replace")
                    data = json.loads(text)
                    return {
                        "asn": data.get("as", ""),
                        "org": data.get("org", ""),
                        "isp": data.get("isp", ""),
                        "country": data.get("country", ""),
                        "region": data.get("regionName", ""),
                        "ip": data.get("query", ip),
                    }
        except Exception:
            pass
        return {}
