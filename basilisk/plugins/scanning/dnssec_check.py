"""DNSSEC validation check — comprehensive analysis of DNS security extensions.

Analyzes DNSKEY algorithms and key sizes, DS digest types, RRSIG signatures
and expiration, NSEC/NSEC3 zone enumeration protection, algorithm strength,
and chain validation (DS to DNSKEY digest match).
"""

from __future__ import annotations

import hashlib
import struct
from typing import ClassVar

import dns.asyncresolver
import dns.exception
import dns.name
import dns.rdatatype

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target
from basilisk.utils.dns import is_root_domain

# ---------------------------------------------------------------------------
# DNSSEC algorithm registry (RFC 8624)
# ---------------------------------------------------------------------------
_ALGORITHMS: dict[int, tuple[str, str]] = {
    1: ("RSAMD5", "weak"),
    3: ("DSA", "weak"),
    5: ("RSASHA1", "weak"),
    6: ("DSA-NSEC3-SHA1", "weak"),
    7: ("RSASHA1-NSEC3-SHA1", "weak"),
    8: ("RSASHA256", "acceptable"),
    10: ("RSASHA512", "acceptable"),
    12: ("ECC-GOST", "acceptable"),
    13: ("ECDSAP256SHA256", "strong"),
    14: ("ECDSAP384SHA384", "strong"),
    15: ("ED25519", "strong"),
    16: ("ED448", "strong"),
}

# DS digest algorithms
_DS_DIGESTS: dict[int, tuple[str, str]] = {
    1: ("SHA-1", "weak"),
    2: ("SHA-256", "good"),
    3: ("GOST", "acceptable"),
    4: ("SHA-384", "best"),
}

# DNSKEY flags
_FLAG_SEP = 0x0001   # Secure Entry Point (KSK)
_FLAG_ZONE = 0x0100  # Zone Key


class DnssecCheckPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="dnssec_check",
        display_name="DNSSEC Check",
        category=PluginCategory.SCANNING,
        description=(
            "Comprehensive DNSSEC analysis: key algorithms, DS digests, "
            "RRSIG expiry, NSEC/NSEC3 detection, chain validation"
        ),
        depends_on=["dns_enum"],
        produces=["dnssec_info"],
        timeout=20.0,
        requires_http=False,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.dns is None:
            return PluginResult.fail(
                self.meta.name, target.host,
                error="DNS client not available",
            )

        findings: list[Finding] = []
        domain = target.host
        # Use the underlying dnspython resolver directly for DNSSEC types
        # because ctx.dns.resolve only supports standard record types
        resolver = ctx.dns.resolver

        # --- DNSKEY analysis ---
        dnskey_info = await self._analyze_dnskeys(
            domain, resolver, findings,
        )

        # --- DS record analysis ---
        ds_info = await self._analyze_ds(domain, resolver, findings)

        # --- RRSIG analysis ---
        rrsig_info = await self._analyze_rrsig(
            domain, resolver, findings,
        )

        # --- NSEC / NSEC3 detection (root domain only — zone walking is a zone-root concern) ---
        if is_root_domain(domain):
            nsec_info = await self._detect_nsec(
                domain, resolver, findings,
            )
        else:
            nsec_info = {"has_nsec": False, "has_nsec3": False}

        # --- Chain validation (DS matches DNSKEY) ---
        chain_valid = False
        if not ctx.should_stop:
            chain_valid = await self._validate_chain(
                domain, resolver, dnskey_info, ds_info, findings,
            )

        # --- Overall assessment ---
        has_dnssec = bool(dnskey_info["keys"]) or bool(ds_info["records"])

        if not has_dnssec and is_root_domain(domain):
            findings.append(Finding.low(
                "DNSSEC not enabled",
                description=(
                    "Domain does not have DNSSEC configured. DNS responses "
                    "could be spoofed via cache poisoning attacks."
                ),
                remediation="Enable DNSSEC for the domain at your registrar",
                tags=["scanning", "dns", "dnssec"],
            ))
        else:
            findings.insert(0, Finding.info(
                "DNSSEC is enabled",
                description=(
                    f"Keys: {len(dnskey_info['keys'])}, "
                    f"DS records: {len(ds_info['records'])}, "
                    f"RRSIG: {'present' if rrsig_info.get('expiry') else 'absent'}, "
                    f"Chain valid: {chain_valid}"
                ),
                tags=["scanning", "dns", "dnssec"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "dnssec_enabled": has_dnssec,
                "algorithms": dnskey_info["algorithms"],
                "key_sizes": dnskey_info["key_sizes"],
                "has_nsec3": nsec_info.get("has_nsec3", False),
                "ds_digest_types": ds_info["digest_types"],
                "rrsig_expiry": rrsig_info.get("expiry", ""),
                "chain_valid": chain_valid,
            },
        )

    # ------------------------------------------------------------------
    # DNSKEY analysis
    # ------------------------------------------------------------------

    async def _analyze_dnskeys(
        self,
        domain: str,
        resolver: dns.asyncresolver.Resolver,
        findings: list[Finding],
    ) -> dict:
        """Fetch and analyze DNSKEY records."""
        info: dict = {"keys": [], "algorithms": [], "key_sizes": []}
        try:
            answer = await resolver.resolve(domain, dns.rdatatype.DNSKEY)
        except dns.exception.DNSException:
            return info

        for rdata in answer:
            flags = rdata.flags
            algorithm = rdata.algorithm
            key_data = rdata.key

            is_ksk = bool(flags & _FLAG_SEP)
            is_zone = bool(flags & _FLAG_ZONE)
            role = "KSK" if is_ksk else ("ZSK" if is_zone else "other")

            key_tag = self._compute_key_tag(rdata)

            algo_name, algo_strength = _ALGORITHMS.get(
                algorithm, (f"Unknown({algorithm})", "unknown"),
            )

            key_bits = self._estimate_key_size(algorithm, key_data)

            info["keys"].append({
                "key_tag": key_tag,
                "algorithm": algo_name,
                "algorithm_id": algorithm,
                "strength": algo_strength,
                "role": role,
                "key_bits": key_bits,
            })
            if algo_name not in info["algorithms"]:
                info["algorithms"].append(algo_name)
            if key_bits and key_bits not in info["key_sizes"]:
                info["key_sizes"].append(key_bits)

            # Flag weak algorithms
            if algo_strength == "weak":
                findings.append(Finding.high(
                    f"Weak DNSSEC algorithm: {algo_name} ({role})",
                    description=(
                        f"DNSKEY tag {key_tag} uses {algo_name} "
                        f"(algorithm {algorithm}), which is "
                        "cryptographically weak"
                    ),
                    evidence=f"Algorithm: {algorithm}, flags: {flags}",
                    remediation=(
                        "Migrate to ECDSAP256SHA256 (alg 13) or "
                        "ED25519 (alg 15)"
                    ),
                    tags=["scanning", "dns", "dnssec", "weak-algorithm"],
                ))
            elif algo_strength == "acceptable":
                if key_bits and key_bits < 2048:
                    findings.append(Finding.high(
                        f"DNSSEC RSA key too short: {key_bits} bits ({role})",
                        description=(
                            f"DNSKEY tag {key_tag} uses {algo_name} "
                            f"with only {key_bits}-bit key"
                        ),
                        evidence=f"Key size: {key_bits} bits",
                        remediation=(
                            "Use RSA-2048 minimum, or migrate to ECDSA"
                        ),
                        tags=["scanning", "dns", "dnssec", "weak-key"],
                    ))
                else:
                    findings.append(Finding.info(
                        f"DNSKEY: {algo_name} "
                        f"{key_bits or '?'}-bit ({role}, tag {key_tag})",
                        tags=["scanning", "dns", "dnssec"],
                    ))
            elif algo_strength == "strong":
                findings.append(Finding.info(
                    f"DNSKEY: {algo_name} ({role}, tag {key_tag})",
                    tags=["scanning", "dns", "dnssec"],
                ))

        return info

    # ------------------------------------------------------------------
    # DS analysis
    # ------------------------------------------------------------------

    async def _analyze_ds(
        self,
        domain: str,
        resolver: dns.asyncresolver.Resolver,
        findings: list[Finding],
    ) -> dict:
        """Fetch and analyze DS records."""
        info: dict = {"records": [], "digest_types": []}
        try:
            answer = await resolver.resolve(domain, dns.rdatatype.DS)
        except dns.exception.DNSException:
            return info

        for rdata in answer:
            key_tag = rdata.key_tag
            algorithm = rdata.algorithm
            digest_type = rdata.digest_type
            digest_hex = rdata.digest.hex()

            digest_name, digest_strength = _DS_DIGESTS.get(
                digest_type, (f"Unknown({digest_type})", "unknown"),
            )

            info["records"].append({
                "key_tag": key_tag,
                "algorithm": algorithm,
                "digest_type": digest_name,
                "digest_strength": digest_strength,
                "digest": digest_hex[:32] + "...",
            })
            if digest_name not in info["digest_types"]:
                info["digest_types"].append(digest_name)

            if digest_strength == "weak":
                findings.append(Finding.medium(
                    f"DS record uses weak digest: {digest_name}",
                    description=(
                        f"DS for key tag {key_tag} uses {digest_name} "
                        f"(type {digest_type}), which is vulnerable "
                        "to collision attacks"
                    ),
                    evidence=f"DS digest type: {digest_type}",
                    remediation=(
                        "Add DS record with SHA-256 (type 2) or "
                        "SHA-384 (type 4)"
                    ),
                    tags=["scanning", "dns", "dnssec", "weak-digest"],
                ))

        return info

    # ------------------------------------------------------------------
    # RRSIG analysis
    # ------------------------------------------------------------------

    async def _analyze_rrsig(
        self,
        domain: str,
        resolver: dns.asyncresolver.Resolver,
        findings: list[Finding],
    ) -> dict:
        """Check RRSIG records for signature expiration."""
        info: dict = {}
        try:
            answer = await resolver.resolve(domain, dns.rdatatype.RRSIG)
        except dns.exception.DNSException:
            return info

        for rdata in answer:
            expiry_ts = rdata.expiration
            signer = str(rdata.signer).rstrip(".")
            algo = rdata.algorithm

            from datetime import UTC, datetime
            expiry_dt = datetime.fromtimestamp(expiry_ts, tz=UTC)
            now = datetime.now(tz=UTC)

            info["expiry"] = expiry_dt.isoformat()
            info["signer"] = signer

            if expiry_dt < now:
                findings.append(Finding.high(
                    "RRSIG signature has expired",
                    description=(
                        f"Expiration: {expiry_dt.isoformat()}, "
                        f"signer: {signer}. Expired signatures cause "
                        "DNSSEC validation failures."
                    ),
                    evidence=f"RRSIG expired at {expiry_dt.isoformat()}",
                    remediation="Re-sign the DNS zone immediately",
                    tags=["scanning", "dns", "dnssec", "rrsig-expired"],
                ))
            else:
                days_left = (expiry_dt - now).days
                if days_left < 7:
                    findings.append(Finding.medium(
                        f"RRSIG expires in {days_left} days",
                        description=(
                            f"Expiration: {expiry_dt.isoformat()}, "
                            f"signer: {signer}"
                        ),
                        remediation=(
                            "Ensure automatic zone re-signing is configured"
                        ),
                        tags=[
                            "scanning", "dns", "dnssec", "rrsig-expiring",
                        ],
                    ))
                else:
                    findings.append(Finding.info(
                        f"RRSIG valid (expires in {days_left} days)",
                        description=(
                            f"Signer: {signer}, algorithm {algo}"
                        ),
                        tags=["scanning", "dns", "dnssec"],
                    ))
            # Only analyze first RRSIG to avoid noise
            break

        return info

    # ------------------------------------------------------------------
    # NSEC / NSEC3 detection
    # ------------------------------------------------------------------

    async def _detect_nsec(
        self,
        domain: str,
        resolver: dns.asyncresolver.Resolver,
        findings: list[Finding],
    ) -> dict:
        """Detect NSEC or NSEC3 zone enumeration protection."""
        info: dict = {"has_nsec": False, "has_nsec3": False}

        # Check NSEC3PARAM to detect NSEC3 usage
        try:
            answer = await resolver.resolve(
                domain, dns.rdatatype.NSEC3PARAM,
            )
            if answer:
                info["has_nsec3"] = True
                for rdata in answer:
                    info["nsec3_iterations"] = rdata.iterations
                    # High iteration count is a DoS vector (RFC 9276)
                    if rdata.iterations > 100:
                        findings.append(Finding.low(
                            f"NSEC3 high iterations: {rdata.iterations}",
                            description=(
                                "NSEC3 iterations > 100 increases CPU load "
                                "on resolvers. RFC 9276 recommends 0."
                            ),
                            remediation="Set NSEC3 iterations to 0 (RFC 9276)",
                            tags=["scanning", "dns", "dnssec", "nsec3"],
                        ))
                    findings.append(Finding.info(
                        "NSEC3 zone enumeration protection enabled",
                        description=(
                            f"Algorithm: {rdata.algorithm}, "
                            f"iterations: {rdata.iterations}, "
                            f"salt length: {len(rdata.salt)}"
                        ),
                        tags=["scanning", "dns", "dnssec", "nsec3"],
                    ))
                    break
                return info
        except dns.exception.DNSException:
            pass

        # If no NSEC3, probe for NSEC via NXDOMAIN response
        try:
            nxname = f"_dnssec_probe_nx.{domain}"
            await resolver.resolve(nxname, dns.rdatatype.A)
        except dns.asyncresolver.NXDOMAIN:
            # The domain likely uses NSEC if DNSSEC is enabled but no NSEC3
            info["has_nsec"] = True
            findings.append(Finding.medium(
                "NSEC used (zone walking possible)",
                description=(
                    "The zone uses NSEC rather than NSEC3. NSEC records "
                    "allow enumerating all names in the zone via "
                    "zone walking."
                ),
                evidence="No NSEC3PARAM found; NXDOMAIN for probe query",
                remediation="Switch to NSEC3 to prevent zone enumeration",
                tags=["scanning", "dns", "dnssec", "nsec"],
            ))
        except dns.exception.DNSException:
            pass

        return info

    # ------------------------------------------------------------------
    # Chain validation: DS matches DNSKEY
    # ------------------------------------------------------------------

    async def _validate_chain(
        self,
        domain: str,
        resolver: dns.asyncresolver.Resolver,
        dnskey_info: dict,
        ds_info: dict,
        findings: list[Finding],
    ) -> bool:
        """Validate that DS record digests match DNSKEY records."""
        if not ds_info["records"] or not dnskey_info["keys"]:
            return False

        try:
            dnskey_answer = await resolver.resolve(
                domain, dns.rdatatype.DNSKEY,
            )
        except dns.exception.DNSException:
            return False

        try:
            ds_answer = await resolver.resolve(domain, dns.rdatatype.DS)
            ds_records = list(ds_answer)
        except dns.exception.DNSException:
            return False

        chain_valid = False
        domain_name = dns.name.from_text(domain)

        for ds_rdata in ds_records:
            for dnskey_rdata in dnskey_answer:
                # Only KSK (SEP flag) should match DS
                if not (dnskey_rdata.flags & _FLAG_SEP):
                    continue
                key_tag = self._compute_key_tag(dnskey_rdata)
                if key_tag != ds_rdata.key_tag:
                    continue
                if dnskey_rdata.algorithm != ds_rdata.algorithm:
                    continue

                computed = self._compute_ds_digest(
                    domain_name, dnskey_rdata, ds_rdata.digest_type,
                )
                if computed and computed == ds_rdata.digest:
                    chain_valid = True
                    break
            if chain_valid:
                break

        if chain_valid:
            findings.append(Finding.info(
                "DNSSEC chain validated (DS matches DNSKEY)",
                tags=["scanning", "dns", "dnssec", "chain-valid"],
            ))
        else:
            findings.append(Finding.high(
                "DNSSEC chain broken: DS does not match any DNSKEY",
                description=(
                    "The DS record at the parent zone does not match "
                    "any KSK in the child zone. This causes DNSSEC "
                    "validation failures for resolvers."
                ),
                remediation=(
                    "Update the DS record at your registrar to match "
                    "the current KSK"
                ),
                tags=["scanning", "dns", "dnssec", "chain-broken"],
            ))

        return chain_valid

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_key_tag(dnskey_rdata) -> int:
        """Compute DNSKEY key tag per RFC 4034 Appendix B."""
        wire = (
            struct.pack(
                "!HBB",
                dnskey_rdata.flags,
                dnskey_rdata.protocol,
                dnskey_rdata.algorithm,
            )
            + dnskey_rdata.key
        )
        ac = 0
        for i, byte in enumerate(wire):
            if i & 1:
                ac += byte
            else:
                ac += byte << 8
        ac += (ac >> 16) & 0xFFFF
        return ac & 0xFFFF

    @staticmethod
    def _compute_ds_digest(
        name: dns.name.Name,
        dnskey_rdata,
        digest_type: int,
    ) -> bytes | None:
        """Compute DS digest for a DNSKEY record."""
        wire_name = name.to_wire()
        wire_key = (
            struct.pack(
                "!HBB",
                dnskey_rdata.flags,
                dnskey_rdata.protocol,
                dnskey_rdata.algorithm,
            )
            + dnskey_rdata.key
        )
        data = wire_name + wire_key

        if digest_type == 1:
            return hashlib.sha1(data).digest()  # noqa: S324
        if digest_type == 2:
            return hashlib.sha256(data).digest()
        if digest_type == 4:
            return hashlib.sha384(data).digest()
        return None

    @staticmethod
    def _estimate_key_size(algorithm: int, key_data: bytes) -> int | None:
        """Estimate key size in bits from algorithm and key data."""
        # RSA: key data = exponent_length + exponent + modulus
        if algorithm in (1, 5, 7, 8, 10):
            if not key_data:
                return None
            exp_len_byte = key_data[0]
            if exp_len_byte == 0:
                if len(key_data) < 3:
                    return None
                exp_len = struct.unpack("!H", key_data[1:3])[0]
                modulus_start = 3 + exp_len
            else:
                exp_len = exp_len_byte
                modulus_start = 1 + exp_len
            modulus = key_data[modulus_start:]
            return len(modulus) * 8
        if algorithm == 13:
            return 256
        if algorithm == 14:
            return 384
        if algorithm == 15:
            return 256
        if algorithm == 16:
            return 448
        return None
