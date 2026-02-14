"""DNS client — async resolver using dnspython."""

from __future__ import annotations

import logging

import dns.asyncresolver
import dns.exception
import dns.rdatatype

from basilisk.models.types import DnsRecord, DnsRecordType

logger = logging.getLogger(__name__)

# Two-part TLDs where the registrable domain has 3 labels (e.g. example.co.uk)
_TWO_PART_TLDS = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz",
    "co.za", "org.za", "net.za", "gov.za",
    "com.br", "net.br", "org.br",
    "com.cn", "net.cn", "org.cn",
    "com.ru", "org.ru", "net.ru",
    "com.tw", "net.tw", "org.tw",
    "co.in", "net.in", "org.in", "gen.in",
    "co.kr", "or.kr", "ne.kr",
    "co.il", "org.il", "net.il", "ac.il",
    "com.mx", "net.mx", "org.mx",
    "com.ar", "net.ar", "org.ar",
    "com.tr", "net.tr", "org.tr", "gen.tr",
    "com.ua", "net.ua", "org.ua",
    "co.id", "or.id", "web.id",
    "com.sg", "net.sg", "org.sg",
    "com.my", "net.my", "org.my",
    "com.hk", "net.hk", "org.hk",
    "com.ng", "net.ng", "org.ng",
    "com.pk", "net.pk", "org.pk",
    "com.ph", "net.ph", "org.ph",
    "com.eg", "net.eg", "org.eg",
    "com.vn", "net.vn", "org.vn",
    "co.th", "or.th", "in.th",
    "com.pe", "net.pe", "org.pe",
    "com.co", "net.co", "org.co",
    "com.ve", "net.ve", "org.ve",
})


def is_root_domain(host: str) -> bool:
    """Check if *host* is a registrable (root) domain, not a subdomain.

    Examples:
        is_root_domain("example.com")      -> True
        is_root_domain("sub.example.com")   -> False
        is_root_domain("example.co.uk")     -> True
        is_root_domain("sub.example.co.uk") -> False
        is_root_domain("insales.ru")        -> True
        is_root_domain("auth.insales.ru")   -> False
    """
    host = host.rstrip(".").lower()
    parts = host.split(".")
    if len(parts) <= 1:
        # Single-label name (e.g. "localhost") — treat as root
        return True

    # Check for two-part TLDs
    if len(parts) >= 2:
        two_part = f"{parts[-2]}.{parts[-1]}"
        if two_part in _TWO_PART_TLDS:
            # Registrable domain has 3 labels (e.g. example.co.uk)
            return len(parts) <= 3

    # Standard TLD: registrable domain has 2 labels (e.g. example.com)
    return len(parts) <= 2


# Map string record types to dnspython rdatatype
_RECORD_MAP = {
    "A": dns.rdatatype.A,
    "AAAA": dns.rdatatype.AAAA,
    "CNAME": dns.rdatatype.CNAME,
    "MX": dns.rdatatype.MX,
    "NS": dns.rdatatype.NS,
    "TXT": dns.rdatatype.TXT,
    "SOA": dns.rdatatype.SOA,
    "PTR": dns.rdatatype.PTR,
    "SRV": dns.rdatatype.SRV,
}


class DnsClient:
    """Async DNS resolver with caching."""

    def __init__(
        self,
        nameservers: list[str] | None = None,
        timeout: float = 5.0,
        retries: int = 2,
    ):
        self.resolver = dns.asyncresolver.Resolver()
        if nameservers:
            self.resolver.nameservers = nameservers
        self.resolver.lifetime = timeout
        self.resolver.retry_servfail = retries > 0

    async def resolve(
        self,
        domain: str,
        record_type: str = "A",
    ) -> list[DnsRecord]:
        """Resolve DNS records for a domain."""
        rdtype = _RECORD_MAP.get(record_type.upper())
        if rdtype is None:
            return []

        try:
            answer = await self.resolver.resolve(domain, rdtype)
            records = []
            for rdata in answer:
                value = str(rdata)
                priority = None
                if record_type.upper() == "MX":
                    priority = rdata.preference
                    value = str(rdata.exchange).rstrip(".")
                elif record_type.upper() in ("CNAME", "NS", "PTR"):
                    value = value.rstrip(".")

                records.append(DnsRecord(
                    type=DnsRecordType(record_type.upper()),
                    name=domain,
                    value=value,
                    ttl=answer.ttl,
                    priority=priority,
                ))
            return records
        except dns.exception.DNSException as e:
            logger.debug("DNS %s query for %s failed: %s", record_type, domain, e)
            return []

    async def resolve_all(
        self,
        domain: str,
        record_types: list[str] | None = None,
    ) -> list[DnsRecord]:
        """Resolve multiple record types for a domain."""
        types = record_types or ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
        all_records: list[DnsRecord] = []
        for rt in types:
            records = await self.resolve(domain, rt)
            all_records.extend(records)
        return all_records

    async def get_ips(self, domain: str) -> list[str]:
        """Get all A/AAAA record IPs for a domain."""
        ips = []
        for rt in ("A", "AAAA"):
            records = await self.resolve(domain, rt)
            ips.extend(r.value for r in records)
        return ips

    async def reverse_lookup(self, ip: str) -> list[str]:
        """Reverse DNS lookup for an IP address."""
        try:
            from dns.reversename import from_address
            rev_name = from_address(ip)
            records = await self.resolve(str(rev_name), "PTR")
            return [r.value for r in records]
        except Exception as e:
            logger.debug("Reverse lookup for %s failed: %s", ip, e)
            return []
