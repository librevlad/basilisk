"""SSL/TLS analyzer plugin — testssl.sh-level certificate and protocol checks."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import re
import ssl
import struct
from datetime import UTC, datetime
from typing import Any, ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target
from basilisk.models.types import SslInfo

_WEAK_CIPHERS_RE = re.compile(
    r"(RC4|DES-CBC(?!3)|EXPORT|NULL|SEED|IDEA|anon)", re.IGNORECASE
)
_3DES_RE = re.compile(r"3DES|DES-CBC3", re.IGNORECASE)
_PFS_KX = {"ECDHE", "DHE"}
_WEAK_SIG_ALGOS = {"sha1WithRSAEncryption", "md5WithRSAEncryption", "sha1"}

_TLS_VERSIONS: list[tuple[str, int]] = [
    ("TLSv1.0", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
]

_STRONG_CURVES = {
    "prime256v1", "secp256r1", "secp384r1", "secp521r1",
    "X25519", "X448",
}

_TLS_RECORD_HANDSHAKE = 0x16
_TLS_RECORD_HEARTBEAT = 0x18
_TLS_RECORD_ALERT = 0x15

_HEARTBLEED_HELLO = (
    b"\x16"
    b"\x03\x01"
    b"\x00\xdc"
    b"\x01"
    b"\x00\x00\xd8"
    b"\x03\x02"
    + b"\x53\x43\x5b\x90"
    + b"\x9d\x9b\x72\x0b\xbc\x0c\xbc\x2b"
      b"\x92\xa8\x48\x97\xcf\xbd\x39\x04"
      b"\xcc\x16\x0a\x85\x03\x90\x9f\x77"
      b"\x04\x33\xd4\xde"
    + b"\x00"
    + b"\x00\x66"
    + b"\xc0\x14\xc0\x0a\xc0\x22\xc0\x21"
      b"\x00\x39\x00\x38\x00\x88\x00\x87"
      b"\xc0\x0f\xc0\x05\x00\x35\x00\x84"
      b"\xc0\x12\xc0\x08\xc0\x1c\xc0\x1b"
      b"\x00\x16\x00\x13\xc0\x0d\xc0\x03"
      b"\x00\x0a\xc0\x13\xc0\x09\xc0\x1f"
      b"\xc0\x1e\x00\x33\x00\x32\x00\x9a"
      b"\x00\x99\x00\x45\x00\x44\xc0\x0e"
      b"\xc0\x04\x00\x2f\x00\x96\x00\x41"
      b"\xc0\x11\xc0\x07\xc0\x0c\xc0\x02"
      b"\x00\x05\x00\x04\x00\x15\x00\x12"
      b"\x00\x09\x00\x14\x00\x11\x00\x08"
      b"\x00\x06\x00\x03\x00\xff"
    + b"\x01\x00"
    + b"\x00\x49"
    + b"\x00\x0b\x00\x04\x03\x00\x01\x02"
    + b"\x00\x0a\x00\x34\x00\x32\x00\x0e"
      b"\x00\x0d\x00\x19\x00\x0b\x00\x0c"
      b"\x00\x18\x00\x09\x00\x0a\x00\x16"
      b"\x00\x17\x00\x08\x00\x06\x00\x07"
      b"\x00\x14\x00\x15\x00\x04\x00\x05"
      b"\x00\x12\x00\x13\x00\x01\x00\x02"
      b"\x00\x03\x00\x0f\x00\x10\x00\x11"
    + b"\x00\x0f\x00\x01\x01"
)

_HEARTBLEED_REQUEST = (
    b"\x18"
    b"\x03\x01"
    b"\x00\x03"
    b"\x01"
    b"\x40\x00"
)


class SslCheckPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="ssl_check",
        display_name="SSL/TLS Analyzer",
        category=PluginCategory.SCANNING,
        description=(
            "Comprehensive SSL/TLS analysis: protocols, ciphers, certificate chain, "
            "vulnerabilities, HSTS, OCSP, CT, PFS — 50+ checks"
        ),
        depends_on=["dns_enum"],
        produces=["ssl_info"],
        timeout=30.0,
    )

    def accepts(self, target: Target) -> bool:
        return True

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        ssl_info = SslInfo()
        data: dict[str, Any] = {}
        host = target.host
        port = 443

        # 1 — connect, extract certificate and negotiated parameters
        try:
            ssl_info, cert_bin, raw_cert_dict = await self._connect_and_extract(host, port)
        except Exception as e:
            return PluginResult(
                plugin=self.meta.name,
                target=host,
                status="partial",
                findings=[Finding.info(
                    f"SSL not available on {host}",
                    evidence=str(e),
                    tags=["ssl"],
                )],
                data={"ssl_available": False},
            )

        data["ssl_available"] = True
        data["ssl_info"] = ssl_info.model_dump()

        # 2 — certificate validity and identity
        findings.extend(self._check_certificate(ssl_info, host))

        # 3 — key size analysis (RSA / ECC)
        findings.extend(self._check_key_size(ssl_info))

        # 4 — signature algorithm
        findings.extend(self._check_signature_algo(ssl_info))

        # 5 — serial number, issuer details, SAN enumeration
        findings.extend(self._cert_details(ssl_info))

        # 6 — wildcard certificate check
        findings.extend(self._check_wildcard(ssl_info))

        # 7 — certificate fingerprints
        if cert_bin:
            findings.extend(self._cert_fingerprints(cert_bin))

        # 8 — certificate chain validation + trust chain depth
        if not ctx.should_stop:
            chain_findings, chain_data = await self._check_chain(host, port)
            findings.extend(chain_findings)
            data["chain"] = chain_data

        # 9 — protocol enumeration (TLS 1.0 / 1.1 / 1.2 / 1.3)
        if not ctx.should_stop:
            proto_findings, protos = await self._enumerate_protocols(host, port)
            findings.extend(proto_findings)
            data["protocols"] = protos

        # 10 — cipher enumeration + weak/null/export/anon/3DES/CBC-only checks
        if not ctx.should_stop:
            cipher_findings, cipher_data = await self._enumerate_ciphers(host, port)
            findings.extend(cipher_findings)
            data["ciphers"] = cipher_data

        # 11 — PFS check
        if not ctx.should_stop:
            findings.extend(self._check_pfs(data.get("ciphers", {})))

        # 12 — cipher order / server preference
        if not ctx.should_stop:
            findings.extend(await self._check_cipher_order(host, port))

        # 13 — elliptic curves
        if not ctx.should_stop:
            curve_findings, curves = await self._check_curves(host, port)
            findings.extend(curve_findings)
            data["curves"] = curves

        # 14 — SNI check
        if not ctx.should_stop:
            findings.extend(await self._check_sni(host, port))

        # 15 — secure renegotiation
        if not ctx.should_stop:
            findings.extend(await self._check_secure_renegotiation(host, port))

        # 16 — session resumption (ticket + id)
        if not ctx.should_stop:
            findings.extend(await self._check_session_resumption(host, port))

        # 17 — TLS compression (CRIME)
        if not ctx.should_stop:
            findings.extend(await self._check_tls_compression(host, port))

        # 18 — OCSP stapling
        if not ctx.should_stop:
            findings.extend(await self._check_ocsp_stapling(host, port))

        # 19 — Certificate Transparency (SCT in certificate)
        if not ctx.should_stop and cert_bin:
            findings.extend(self._check_certificate_transparency(cert_bin))

        # 20 — CT log presence via crt.sh
        if not ctx.should_stop and ctx.http:
            findings.extend(await self._check_ct_log_presence(host, ctx))

        # 21 — HSTS header analysis
        if not ctx.should_stop and ctx.http:
            findings.extend(await self._check_hsts(host, ctx))

        # 22 — HSTS preload list
        if not ctx.should_stop and ctx.http:
            findings.extend(await self._check_hsts_preload(host, ctx))

        # 23 — HPKP deprecation check
        if not ctx.should_stop and ctx.http:
            findings.extend(await self._check_hpkp(host, ctx))

        # 24 — Expect-CT header
        if not ctx.should_stop and ctx.http:
            findings.extend(await self._check_expect_ct(host, ctx))

        # 25 — vulnerability checks (Heartbleed, POODLE, CCS, FREAK, Logjam, etc.)
        if not ctx.should_stop:
            findings.extend(await self._run_vuln_checks(host, port, data, ctx))

        # 26 — TLS Fallback SCSV
        if not ctx.should_stop:
            findings.extend(await self._check_fallback_scsv(host, port))

        # summary
        findings.append(Finding.info(
            f"SSL: {ssl_info.protocol}, expires in {ssl_info.days_until_expiry}d",
            evidence=f"Subject: {ssl_info.subject}, Issuer: {ssl_info.issuer}",
            tags=["ssl"],
        ))

        return PluginResult.success(
            self.meta.name, host,
            findings=findings,
            data=data,
        )

    # ================================================================
    # Core SSL connection
    # ================================================================

    async def _connect_and_extract(
        self, host: str, port: int = 443
    ) -> tuple[SslInfo, bytes | None, dict]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx),
            timeout=10.0,
        )
        try:
            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj is None:
                msg = "No SSL object"
                raise ValueError(msg)

            cert = ssl_obj.getpeercert(binary_form=False) or {}
            cert_bin = ssl_obj.getpeercert(binary_form=True)
            protocol = ssl_obj.version() or ""
            cipher_info = ssl_obj.cipher()

            info = SslInfo(protocol=protocol)
            if cipher_info:
                info.cipher = cipher_info[0]
                info.key_size = cipher_info[2]

            if cert:
                info = self._parse_cert(cert, protocol, cipher_info)
            elif cert_bin:
                info = self._parse_binary_cert(cert_bin, protocol, cipher_info)

            return info, cert_bin, cert
        finally:
            writer.close()
            await writer.wait_closed()

    # ================================================================
    # Certificate analysis findings
    # ================================================================

    def _check_certificate(self, info: SslInfo, host: str) -> list[Finding]:
        findings: list[Finding] = []

        if info.is_expired:
            findings.append(Finding.critical(
                "Expired SSL certificate",
                description=(
                    f"Certificate expired {abs(info.days_until_expiry or 0)} days ago. "
                    "Browsers will show security warnings to all visitors."
                ),
                evidence=f"Not After: {info.not_after}",
                remediation="Renew the SSL certificate immediately",
                tags=["ssl", "certificate", "expired", "owasp:a02"],
            ))
        elif info.days_until_expiry is not None and info.days_until_expiry < 7:
            findings.append(Finding.high(
                f"SSL certificate expires in {info.days_until_expiry} days",
                description="Certificate is about to expire — imminent outage risk",
                evidence=f"Not After: {info.not_after}",
                remediation="Renew the SSL certificate before expiry",
                tags=["ssl", "certificate", "owasp:a02"],
            ))
        elif info.days_until_expiry is not None and info.days_until_expiry < 30:
            findings.append(Finding.medium(
                f"SSL certificate expiring soon ({info.days_until_expiry} days)",
                description="Certificate expires within 30 days",
                evidence=f"Not After: {info.not_after}",
                remediation="Renew the SSL certificate before expiry",
                tags=["ssl", "certificate"],
            ))
        elif info.days_until_expiry is not None and info.days_until_expiry < 90:
            findings.append(Finding.low(
                f"SSL certificate expires in {info.days_until_expiry} days",
                evidence=f"Not After: {info.not_after}",
                remediation="Plan certificate renewal",
                tags=["ssl", "certificate"],
            ))

        if info.is_self_signed:
            findings.append(Finding.medium(
                "Self-signed SSL certificate",
                description=(
                    "Certificate is not signed by a trusted CA. "
                    "Browsers will show trust warnings."
                ),
                evidence=f"Issuer: {info.issuer}",
                remediation="Use a certificate from a trusted CA (e.g. Let's Encrypt)",
                tags=["ssl", "certificate", "self-signed"],
            ))

        if info.san and host not in info.san:
            wildcard_match = any(
                s.startswith("*.") and host.endswith(s[1:]) for s in info.san
            )
            if not wildcard_match:
                findings.append(Finding.high(
                    "Certificate hostname mismatch",
                    description=f"Hostname '{host}' not found in certificate SANs or CN",
                    evidence=f"SANs: {', '.join(info.san[:10])}",
                    remediation="Ensure the certificate covers the target hostname",
                    tags=["ssl", "certificate", "hostname-mismatch", "owasp:a02"],
                ))
        elif not info.san:
            cn = info.subject.get("commonName", "")
            if cn and cn != host and not (cn.startswith("*.") and host.endswith(cn[1:])):
                findings.append(Finding.high(
                    "Certificate CN does not match hostname (no SANs present)",
                    description=(
                        f"CN='{cn}' does not match '{host}' and no SANs are defined. "
                        "Modern browsers require the SAN extension."
                    ),
                    evidence=f"CN: {cn}",
                    remediation="Reissue certificate with proper SANs",
                    tags=["ssl", "certificate", "hostname-mismatch", "owasp:a02"],
                ))

        if info.not_before and info.not_after:
            validity_days = (info.not_after - info.not_before).days
            if validity_days > 398:
                findings.append(Finding.low(
                    f"Certificate validity period is {validity_days} days (>{398})",
                    description=(
                        "Apple/Mozilla/Chrome limit certificate lifetime to 398 days. "
                        "Longer validity may cause trust issues."
                    ),
                    evidence=f"Valid from {info.not_before} to {info.not_after}",
                    remediation="Use certificates with max 398-day validity",
                    tags=["ssl", "certificate", "validity-period"],
                ))

        return findings

    def _check_key_size(self, info: SslInfo) -> list[Finding]:
        findings: list[Finding] = []
        key_bits = info.key_size
        if key_bits <= 0:
            return findings

        sig = (info.signature_algorithm or "").lower()
        is_rsa = "rsa" in sig or "rsa" in info.cipher.lower()
        is_ecc = "ecdsa" in sig or "ec" in sig

        if is_rsa:
            if key_bits < 1024:
                findings.append(Finding.critical(
                    f"Critically weak RSA key: {key_bits} bits",
                    description="RSA keys < 1024 bits can be factored trivially",
                    evidence=f"Key size: {key_bits} bits",
                    remediation="Use RSA 2048+ or ECDSA P-256+",
                    tags=["ssl", "key-strength", "owasp:a02"],
                ))
            elif key_bits < 2048:
                findings.append(Finding.high(
                    f"Weak RSA key size: {key_bits} bits",
                    description="RSA keys shorter than 2048 bits are considered breakable",
                    evidence=f"Key size: {key_bits} bits",
                    remediation="Use RSA 2048+ or ECDSA P-256+",
                    tags=["ssl", "key-strength", "owasp:a02"],
                ))
            elif key_bits == 2048:
                findings.append(Finding.info(
                    f"RSA key size: {key_bits} bits (minimum acceptable)",
                    evidence="Consider 3072+ bits for post-2030 security",
                    tags=["ssl", "key-strength"],
                ))
            elif key_bits < 4096:
                findings.append(Finding.info(
                    f"RSA key size: {key_bits} bits (good)",
                    tags=["ssl", "key-strength"],
                ))
            else:
                findings.append(Finding.info(
                    f"RSA key size: {key_bits} bits (strong)",
                    tags=["ssl", "key-strength"],
                ))

        if is_ecc:
            if key_bits < 224:
                findings.append(Finding.high(
                    f"Weak ECC key size: {key_bits} bits",
                    evidence=f"Key size: {key_bits} bits",
                    remediation="Use ECDSA P-256 (256 bit) or stronger",
                    tags=["ssl", "key-strength", "owasp:a02"],
                ))
            elif key_bits < 256:
                findings.append(Finding.medium(
                    f"Marginal ECC key size: {key_bits} bits",
                    evidence=f"Key size: {key_bits} bits",
                    remediation="Use ECDSA P-256 (256 bit) or stronger",
                    tags=["ssl", "key-strength"],
                ))
            else:
                findings.append(Finding.info(
                    f"ECC key size: {key_bits} bits (strong)",
                    tags=["ssl", "key-strength"],
                ))

        return findings

    def _check_signature_algo(self, info: SslInfo) -> list[Finding]:
        findings: list[Finding] = []
        sig = info.signature_algorithm or ""
        if not sig:
            return findings

        sig_lower = sig.lower()
        if "md5" in sig_lower:
            findings.append(Finding.critical(
                f"MD5 signature algorithm: {sig}",
                description="MD5 signatures can be trivially forged via collision attacks",
                evidence=f"Signature algorithm: {sig}",
                remediation="Reissue certificate with SHA-256 or stronger",
                tags=["ssl", "signature", "md5", "owasp:a02"],
            ))
        elif "sha1" in sig_lower and "sha1with" in sig_lower:
            findings.append(Finding.high(
                f"SHA-1 signature algorithm: {sig}",
                description=(
                    "SHA-1 signatures are deprecated since 2017. "
                    "Collision attacks are practical (SHAttered, 2017)."
                ),
                evidence=f"Signature algorithm: {sig}",
                remediation="Reissue certificate with SHA-256 or stronger",
                tags=["ssl", "signature", "sha1", "owasp:a02"],
            ))
        elif "sha256" in sig_lower or "sha384" in sig_lower or "sha512" in sig_lower:
            findings.append(Finding.info(
                f"Signature algorithm: {sig} (strong)",
                tags=["ssl", "signature"],
            ))
        else:
            findings.append(Finding.info(
                f"Signature algorithm: {sig}",
                tags=["ssl", "signature"],
            ))

        return findings

    def _cert_details(self, info: SslInfo) -> list[Finding]:
        findings: list[Finding] = []

        if info.serial_number:
            findings.append(Finding.info(
                f"Certificate serial: {info.serial_number}",
                tags=["ssl", "certificate", "serial"],
            ))

        issuer_parts: list[str] = []
        for k, v in info.issuer.items():
            issuer_parts.append(f"{k}={v}")
        if issuer_parts:
            findings.append(Finding.info(
                f"Issuer: {', '.join(issuer_parts)}",
                tags=["ssl", "certificate", "issuer"],
            ))

        if info.san:
            san_display = info.san[:20]
            extra = f" (+{len(info.san) - 20} more)" if len(info.san) > 20 else ""
            findings.append(Finding.info(
                f"Subject Alternative Names ({len(info.san)} entries)",
                evidence=", ".join(san_display) + extra,
                tags=["ssl", "certificate", "san"],
            ))

        if info.not_before and info.not_after:
            findings.append(Finding.info(
                f"Validity: {info.not_before.date()} to {info.not_after.date()}",
                tags=["ssl", "certificate", "validity"],
            ))

        return findings

    def _check_wildcard(self, info: SslInfo) -> list[Finding]:
        findings: list[Finding] = []
        wildcards = [s for s in info.san if s.startswith("*.")]
        cn = info.subject.get("commonName", "")
        if cn.startswith("*.") and cn not in wildcards:
            wildcards.append(cn)

        if wildcards:
            unique_wildcards = sorted(set(wildcards))
            findings.append(Finding.low(
                f"Wildcard certificate detected ({len(unique_wildcards)} pattern(s))",
                description=(
                    "Wildcard certificates increase attack surface — compromise "
                    "of the private key affects all matching subdomains"
                ),
                evidence=f"Wildcards: {', '.join(unique_wildcards[:5])}",
                remediation="Consider using individual certificates per subdomain",
                tags=["ssl", "certificate", "wildcard"],
            ))

        return findings

    def _cert_fingerprints(self, cert_der: bytes) -> list[Finding]:
        sha256_fp = hashlib.sha256(cert_der).hexdigest()
        sha1_fp = hashlib.sha1(cert_der).hexdigest()  # noqa: S324
        return [
            Finding.info(
                "Certificate fingerprints",
                evidence=f"SHA-256: {sha256_fp}\nSHA-1: {sha1_fp}",
                tags=["ssl", "certificate", "fingerprint"],
            ),
        ]

    # ================================================================
    # Certificate chain validation
    # ================================================================

    async def _check_chain(
        self, host: str, port: int
    ) -> tuple[list[Finding], dict]:
        findings: list[Finding] = []
        chain_data: dict[str, Any] = {"depth": 0, "intermediates": [], "valid": None}

        try:
            ctx_verify = ssl.create_default_context()
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ctx_verify),
                    timeout=8.0,
                )
                writer.close()
                await writer.wait_closed()
                chain_data["valid"] = True
                findings.append(Finding.info(
                    "Certificate chain validates against system trust store",
                    tags=["ssl", "chain"],
                ))
            except ssl.SSLCertVerificationError as e:
                chain_data["valid"] = False
                verify_msg = getattr(e, "verify_message", str(e))
                findings.append(Finding.medium(
                    "Certificate chain validation failed",
                    description=str(e),
                    evidence=f"Verify error: {verify_msg}",
                    remediation="Ensure complete and valid certificate chain",
                    tags=["ssl", "chain"],
                ))

            nv_ctx = ssl.create_default_context()
            nv_ctx.check_hostname = False
            nv_ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=nv_ctx),
                timeout=8.0,
            )
            try:
                ssl_obj = writer.get_extra_info("ssl_object")
                if ssl_obj:
                    peer_cert_bin = ssl_obj.getpeercert(binary_form=True)
                    if peer_cert_bin:
                        chain_findings = self._analyze_chain_cert(
                            peer_cert_bin, chain_data
                        )
                        findings.extend(chain_findings)
            finally:
                writer.close()
                await writer.wait_closed()

        except Exception:
            pass

        return findings, chain_data

    def _analyze_chain_cert(
        self, cert_der: bytes, chain_data: dict
    ) -> list[Finding]:
        findings: list[Finding] = []
        try:
            from cryptography import x509

            cert = x509.load_der_x509_certificate(cert_der)

            try:
                basic = cert.extensions.get_extension_for_class(x509.BasicConstraints)
                if basic.value.ca:
                    chain_data["depth"] = basic.value.path_length or 0
            except x509.ExtensionNotFound:
                pass

            try:
                aia = cert.extensions.get_extension_for_class(
                    x509.AuthorityInformationAccess
                )
                for desc in aia.value:
                    oid = x509.oid.AuthorityInformationAccessOID
                    if desc.access_method == oid.CA_ISSUERS:
                        chain_data.setdefault("ca_issuers", []).append(
                            desc.access_location.value
                        )
                    elif desc.access_method == oid.OCSP:
                        chain_data.setdefault("ocsp_responders", []).append(
                            desc.access_location.value
                        )
            except x509.ExtensionNotFound:
                pass

            try:
                aki = cert.extensions.get_extension_for_class(
                    x509.AuthorityKeyIdentifier
                )
                if aki.value.key_identifier:
                    chain_data["authority_key_id"] = aki.value.key_identifier.hex()
            except x509.ExtensionNotFound:
                pass

            try:
                ski = cert.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier
                )
                chain_data["subject_key_id"] = ski.value.digest.hex()
            except x509.ExtensionNotFound:
                pass

            depth = chain_data.get("depth", 0)
            findings.append(Finding.info(
                f"Certificate chain depth: {depth}",
                evidence=(
                    f"CA Issuers: {chain_data.get('ca_issuers', 'none')}, "
                    f"OCSP: {chain_data.get('ocsp_responders', 'none')}"
                ),
                tags=["ssl", "chain"],
            ))

        except ImportError:
            pass
        except Exception:
            pass

        return findings

    # ================================================================
    # Protocol enumeration
    # ================================================================

    async def _enumerate_protocols(
        self, host: str, port: int
    ) -> tuple[list[Finding], dict[str, bool]]:
        findings: list[Finding] = []
        protos: dict[str, bool] = {}

        tasks = [self._test_protocol(host, port, ver) for _, ver in _TLS_VERSIONS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for (name, _), result in zip(_TLS_VERSIONS, results, strict=False):
            protos[name] = result is True

        if protos.get("TLSv1.0"):
            findings.append(Finding.high(
                "TLS 1.0 supported (deprecated since 2020, RFC 8996)",
                description=(
                    "TLS 1.0 has known vulnerabilities: BEAST, POODLE, "
                    "weak CBC ciphers. Deprecated by PCI DSS, NIST, and all browsers."
                ),
                evidence="Server accepts TLSv1.0 connections",
                remediation="Disable TLS 1.0; use TLS 1.2+ only",
                tags=["ssl", "protocol", "tls1.0", "owasp:a02"],
            ))
        if protos.get("TLSv1.1"):
            findings.append(Finding.medium(
                "TLS 1.1 supported (deprecated since 2020, RFC 8996)",
                description=(
                    "TLS 1.1 is deprecated by all major browsers and removed "
                    "from PCI DSS compliance."
                ),
                evidence="Server accepts TLSv1.1 connections",
                remediation="Disable TLS 1.1; use TLS 1.2+ only",
                tags=["ssl", "protocol", "tls1.1"],
            ))
        if not protos.get("TLSv1.2") and not protos.get("TLSv1.3"):
            findings.append(Finding.high(
                "Neither TLS 1.2 nor TLS 1.3 supported",
                description="Server only supports deprecated protocol versions",
                evidence=f"Protocols: {protos}",
                remediation="Enable TLS 1.2 and TLS 1.3",
                tags=["ssl", "protocol", "owasp:a02"],
            ))
        if not protos.get("TLSv1.3"):
            findings.append(Finding.low(
                "TLS 1.3 not supported",
                description=(
                    "TLS 1.3 provides improved security (0-RTT, no legacy ciphers) "
                    "and performance (faster handshake)"
                ),
                evidence="Server does not accept TLSv1.3 connections",
                remediation="Enable TLS 1.3 on the server",
                tags=["ssl", "protocol", "tls1.3"],
            ))

        supported_str = ", ".join(k for k, v in protos.items() if v)
        if supported_str:
            findings.append(Finding.info(
                f"Supported protocols: {supported_str}",
                tags=["ssl", "protocol"],
            ))

        if protos.get("TLSv1.2") and protos.get("TLSv1.3"):
            only_modern = not protos.get("TLSv1.0") and not protos.get("TLSv1.1")
            if only_modern:
                findings.append(Finding.info(
                    "Optimal protocol configuration: TLS 1.2 + TLS 1.3 only",
                    tags=["ssl", "protocol"],
                ))

        return findings, protos

    async def _test_protocol(self, host: str, port: int, version: int) -> bool:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version
            ctx.maximum_version = version
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx),
                timeout=5.0,
            )
            writer.close()
            await writer.wait_closed()
        except Exception:
            return False
        else:
            return True

    # ================================================================
    # Cipher enumeration
    # ================================================================

    async def _enumerate_ciphers(
        self, host: str, port: int
    ) -> tuple[list[Finding], dict]:
        findings: list[Finding] = []
        cipher_data: dict[str, list[dict]] = {}
        weak_list: list[str] = []
        triple_des_list: list[str] = []
        null_list: list[str] = []
        export_list: list[str] = []
        anon_list: list[str] = []

        proto_versions = [
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
        ]

        tasks = [
            self._get_ciphers_for_protocol(host, port, v) for _, v in proto_versions
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for (proto_name, _), result in zip(proto_versions, results, strict=False):
            if isinstance(result, list) and result:
                cipher_data[proto_name] = result
                for c in result:
                    name = c["name"]
                    name_upper = name.upper()
                    if "NULL" in name_upper:
                        null_list.append(f"{proto_name}: {name}")
                    elif "EXPORT" in name_upper:
                        export_list.append(f"{proto_name}: {name}")
                    elif "ANON" in name_upper:
                        anon_list.append(f"{proto_name}: {name}")
                    elif _3DES_RE.search(name):
                        triple_des_list.append(f"{proto_name}: {name}")
                    elif _WEAK_CIPHERS_RE.search(name):
                        weak_list.append(f"{proto_name}: {name}")

        if null_list:
            findings.append(Finding.high(
                f"NULL cipher suites accepted ({len(null_list)})",
                description="NULL ciphers provide NO encryption — traffic is sent in cleartext",
                evidence="; ".join(null_list[:5]),
                remediation="Disable all NULL cipher suites immediately",
                tags=["ssl", "cipher", "null", "owasp:a02"],
            ))

        if export_list:
            findings.append(Finding.high(
                f"EXPORT cipher suites accepted ({len(export_list)})",
                description=(
                    "EXPORT ciphers use intentionally weakened cryptography "
                    "(40-56 bit keys) that can be broken in seconds"
                ),
                evidence="; ".join(export_list[:5]),
                remediation="Disable all EXPORT cipher suites",
                tags=["ssl", "cipher", "export", "owasp:a02"],
            ))

        if anon_list:
            findings.append(Finding.high(
                f"Anonymous cipher suites accepted ({len(anon_list)})",
                description=(
                    "Anonymous ciphers (ADH/AECDH) provide no authentication — "
                    "vulnerable to man-in-the-middle attacks"
                ),
                evidence="; ".join(anon_list[:5]),
                remediation="Disable all anonymous cipher suites",
                tags=["ssl", "cipher", "anonymous", "owasp:a02"],
            ))

        if weak_list:
            findings.append(Finding.medium(
                f"Weak ciphers supported ({len(weak_list)})",
                description="RC4, DES, SEED, or IDEA ciphers have known cryptographic weaknesses",
                evidence="; ".join(weak_list[:10]),
                remediation="Disable all weak ciphers in server configuration",
                tags=["ssl", "cipher", "owasp:a02"],
            ))

        if triple_des_list:
            findings.append(Finding.medium(
                f"3DES cipher suites supported ({len(triple_des_list)})",
                description=(
                    "3DES is vulnerable to Sweet32 birthday attack (CVE-2016-2183). "
                    "64-bit block size allows practical plaintext recovery."
                ),
                evidence="; ".join(triple_des_list[:5]),
                remediation="Disable 3DES cipher suites; use AES-GCM or CHACHA20",
                tags=["ssl", "cipher", "3des", "sweet32", "cve-2016-2183"],
            ))

        total = sum(len(v) for v in cipher_data.values())
        if total > 0:
            all_names: list[str] = []
            for proto_ciphers in cipher_data.values():
                for c in proto_ciphers:
                    all_names.append(c["name"])

            aes_gcm = [n for n in all_names if "GCM" in n.upper()]
            chacha = [n for n in all_names if "CHACHA" in n.upper()]
            cbc_only = [
                n for n in all_names
                if "CBC" in n.upper() and "GCM" not in n.upper()
            ]

            parts = [f"{total} total"]
            if aes_gcm:
                parts.append(f"{len(aes_gcm)} AES-GCM")
            if chacha:
                parts.append(f"{len(chacha)} ChaCha20")
            if cbc_only:
                parts.append(f"{len(cbc_only)} CBC-mode")

            findings.append(Finding.info(
                f"Cipher suites: {', '.join(parts)}",
                evidence="; ".join(all_names[:15]),
                tags=["ssl", "cipher"],
            ))

            if cbc_only and not aes_gcm and not chacha:
                findings.append(Finding.medium(
                    "Only CBC-mode ciphers available (no AEAD ciphers)",
                    description=(
                        "CBC ciphers are susceptible to padding oracle attacks. "
                        "AEAD ciphers (AES-GCM, ChaCha20-Poly1305) are preferred."
                    ),
                    evidence=f"CBC ciphers: {', '.join(cbc_only[:5])}",
                    remediation="Enable AES-GCM and/or ChaCha20-Poly1305 ciphers",
                    tags=["ssl", "cipher", "cbc", "aead"],
                ))

        return findings, cipher_data

    async def _get_ciphers_for_protocol(
        self, host: str, port: int, version: int
    ) -> list[dict]:
        ciphers: list[dict] = []
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version
            ctx.maximum_version = version

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx),
                timeout=5.0,
            )
            try:
                ssl_obj = writer.get_extra_info("ssl_object")
                if ssl_obj:
                    shared = ssl_obj.shared_ciphers()
                    if shared:
                        for name, proto, bits in shared:
                            ciphers.append({
                                "name": name,
                                "protocol": proto,
                                "bits": bits,
                            })
                    else:
                        cipher_info = ssl_obj.cipher()
                        if cipher_info:
                            ciphers.append({
                                "name": cipher_info[0],
                                "protocol": cipher_info[1],
                                "bits": cipher_info[2],
                            })
            finally:
                writer.close()
                await writer.wait_closed()
        except Exception:
            pass
        return ciphers

    # ================================================================
    # Perfect Forward Secrecy
    # ================================================================

    def _check_pfs(self, cipher_data: dict) -> list[Finding]:
        findings: list[Finding] = []
        all_ciphers: list[str] = []
        for proto_ciphers in cipher_data.values():
            if isinstance(proto_ciphers, list):
                for c in proto_ciphers:
                    all_ciphers.append(c.get("name", ""))

        if not all_ciphers:
            return findings

        tls13_ciphers = [c for c in all_ciphers if c.startswith("TLS_")]
        pfs_ciphers = [
            c for c in all_ciphers
            if any(kx in c.upper() for kx in ("ECDHE", "DHE"))
        ]
        non_pfs = [
            c for c in all_ciphers
            if not any(kx in c.upper() for kx in ("ECDHE", "DHE"))
            and not c.startswith("TLS_")
        ]

        if not pfs_ciphers and not tls13_ciphers:
            findings.append(Finding.medium(
                "No Perfect Forward Secrecy (PFS) support",
                description=(
                    "Without PFS, compromise of the server's private key "
                    "allows decryption of all previously recorded traffic"
                ),
                evidence=f"Non-PFS ciphers: {', '.join(non_pfs[:5])}",
                remediation="Enable ECDHE or DHE cipher suites for PFS",
                tags=["ssl", "pfs", "owasp:a02"],
            ))
        elif non_pfs:
            pfs_total = len(pfs_ciphers) + len(tls13_ciphers)
            pfs_pct = pfs_total * 100 // len(all_ciphers)
            findings.append(Finding.low(
                f"Some cipher suites lack PFS ({len(non_pfs)} of {len(all_ciphers)})",
                evidence=(
                    f"PFS coverage: {pfs_pct}%. "
                    f"Non-PFS: {', '.join(non_pfs[:5])}"
                ),
                remediation="Disable static RSA key exchange; prefer ECDHE/DHE",
                tags=["ssl", "pfs"],
            ))
        else:
            findings.append(Finding.info(
                "All cipher suites support Perfect Forward Secrecy",
                tags=["ssl", "pfs"],
            ))

        ecdhe_count = len([c for c in pfs_ciphers if "ECDHE" in c.upper()])
        dhe_only = len([
            c for c in pfs_ciphers
            if "DHE" in c.upper() and "ECDHE" not in c.upper()
        ])
        if ecdhe_count or dhe_only or tls13_ciphers:
            findings.append(Finding.info(
                f"PFS key exchange: {ecdhe_count} ECDHE, {dhe_only} DHE, "
                f"{len(tls13_ciphers)} TLS 1.3 (implicit PFS)",
                tags=["ssl", "pfs"],
            ))

        return findings

    # ================================================================
    # Cipher order / server preference
    # ================================================================

    async def _check_cipher_order(self, host: str, port: int) -> list[Finding]:
        findings: list[Finding] = []
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx),
                timeout=5.0,
            )
            try:
                ssl_obj = writer.get_extra_info("ssl_object")
                if ssl_obj:
                    negotiated = ssl_obj.cipher()
                    shared = ssl_obj.shared_ciphers()
                    if negotiated and shared and len(shared) > 1:
                        first_shared = shared[0][0]
                        if negotiated[0] == first_shared:
                            findings.append(Finding.info(
                                "Server appears to enforce cipher order preference",
                                evidence=f"Negotiated: {negotiated[0]}",
                                tags=["ssl", "cipher-order"],
                            ))
                        else:
                            findings.append(Finding.low(
                                "Server may not enforce cipher order preference",
                                description=(
                                    "Without server-side cipher preference, "
                                    "clients may negotiate weaker ciphers"
                                ),
                                evidence=(
                                    f"Negotiated: {negotiated[0]}, "
                                    f"First shared: {first_shared}"
                                ),
                                remediation=(
                                    "Configure server to prefer its own cipher order "
                                    "(SSLHonorCipherOrder in Apache, "
                                    "ssl_prefer_server_ciphers in nginx)"
                                ),
                                tags=["ssl", "cipher-order"],
                            ))
            finally:
                writer.close()
                await writer.wait_closed()
        except Exception:
            pass
        return findings

    # ================================================================
    # Elliptic curves
    # ================================================================

    async def _check_curves(
        self, host: str, port: int
    ) -> tuple[list[Finding], list[str]]:
        findings: list[Finding] = []
        curves: list[str] = []
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx),
                timeout=5.0,
            )
            try:
                ssl_obj = writer.get_extra_info("ssl_object")
                if ssl_obj:
                    cipher_info = ssl_obj.cipher()
                    if cipher_info and "ECDH" in cipher_info[0]:
                        curves.append(cipher_info[0])
            finally:
                writer.close()
                await writer.wait_closed()

            if curves:
                findings.append(Finding.info(
                    f"Negotiated ECDH cipher: {', '.join(curves)}",
                    tags=["ssl", "curves"],
                ))
            else:
                findings.append(Finding.info(
                    "No ECDH cipher negotiated in default handshake",
                    tags=["ssl", "curves"],
                ))

        except Exception:
            pass

        return findings, curves

    # ================================================================
    # SNI check
    # ================================================================

    async def _check_sni(self, host: str, port: int) -> list[Finding]:
        findings: list[Finding] = []
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx, server_hostname=""),
                timeout=5.0,
            )
            try:
                ssl_obj = writer.get_extra_info("ssl_object")
                no_sni_cert = (
                    ssl_obj.getpeercert(binary_form=False) if ssl_obj else None
                )
            finally:
                writer.close()
                await writer.wait_closed()

            reader2, writer2 = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
                timeout=5.0,
            )
            try:
                ssl_obj2 = writer2.get_extra_info("ssl_object")
                sni_cert = (
                    ssl_obj2.getpeercert(binary_form=False) if ssl_obj2 else None
                )
            finally:
                writer2.close()
                await writer2.wait_closed()

            if no_sni_cert and sni_cert:
                no_sni_cn = dict(
                    x[0] for x in no_sni_cert.get("subject", ())
                ).get("commonName", "")
                sni_cn = dict(
                    x[0] for x in sni_cert.get("subject", ())
                ).get("commonName", "")
                if no_sni_cn != sni_cn:
                    findings.append(Finding.info(
                        "SNI support: different certificates for different hostnames",
                        evidence=f"Without SNI: {no_sni_cn}, With SNI: {sni_cn}",
                        tags=["ssl", "sni"],
                    ))
                else:
                    findings.append(Finding.info(
                        "SNI: same certificate with and without SNI",
                        tags=["ssl", "sni"],
                    ))

        except Exception:
            findings.append(Finding.info(
                "SNI check inconclusive",
                tags=["ssl", "sni"],
            ))

        return findings

    # ================================================================
    # Secure renegotiation
    # ================================================================

    async def _check_secure_renegotiation(
        self, host: str, port: int
    ) -> list[Finding]:
        findings: list[Finding] = []
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx),
                timeout=5.0,
            )
            try:
                ssl_obj = writer.get_extra_info("ssl_object")
                if ssl_obj:
                    version = ssl_obj.version() or ""
                    if "TLSv1.3" in version:
                        findings.append(Finding.info(
                            "TLS 1.3: renegotiation not applicable (removed by design)",
                            tags=["ssl", "renegotiation"],
                        ))
                    else:
                        findings.append(Finding.info(
                            "Secure renegotiation supported (Python ssl enforces RFC 5746)",
                            evidence=f"Protocol: {version}",
                            tags=["ssl", "renegotiation"],
                        ))
            finally:
                writer.close()
                await writer.wait_closed()
        except Exception:
            pass

        return findings

    # ================================================================
    # Session resumption
    # ================================================================

    async def _check_session_resumption(
        self, host: str, port: int
    ) -> list[Finding]:
        findings: list[Finding] = []
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx),
                timeout=5.0,
            )
            ssl_obj = writer.get_extra_info("ssl_object")
            session = ssl_obj.session if ssl_obj else None
            version = ssl_obj.version() if ssl_obj else ""
            writer.close()
            await writer.wait_closed()

            if session:
                ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx2.check_hostname = False
                ctx2.verify_mode = ssl.CERT_NONE

                reader2, writer2 = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ctx2),
                    timeout=5.0,
                )
                ssl_obj2 = writer2.get_extra_info("ssl_object")
                resumed = False
                if ssl_obj2 and hasattr(ssl_obj2, "session_reused"):
                    resumed = ssl_obj2.session_reused
                writer2.close()
                await writer2.wait_closed()

                if resumed:
                    findings.append(Finding.info(
                        "Session resumption: supported (session ID/ticket reuse detected)",
                        evidence=f"Protocol: {version}",
                        tags=["ssl", "session-resumption"],
                    ))
                else:
                    findings.append(Finding.info(
                        "Session resumption: not detected",
                        evidence=f"Protocol: {version}",
                        tags=["ssl", "session-resumption"],
                    ))

                if version and "TLSv1.3" in version:
                    findings.append(Finding.info(
                        "TLS 1.3 uses PSK-based resumption (not traditional session IDs)",
                        tags=["ssl", "session-resumption", "tls1.3"],
                    ))
        except Exception:
            pass

        return findings

    # ================================================================
    # TLS compression (CRIME)
    # ================================================================

    async def _check_tls_compression(self, host: str, port: int) -> list[Finding]:
        findings: list[Finding] = []
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx),
                timeout=5.0,
            )
            try:
                ssl_obj = writer.get_extra_info("ssl_object")
                if ssl_obj:
                    compression = ssl_obj.compression()
                    if compression:
                        findings.append(Finding.high(
                            f"TLS compression enabled: {compression} (CRIME, CVE-2012-4929)",
                            description=(
                                "TLS-level compression allows CRIME attack to extract "
                                "secrets like session cookies through chosen-plaintext "
                                "side-channel"
                            ),
                            evidence=f"Compression method: {compression}",
                            remediation="Disable TLS compression on the server",
                            tags=[
                                "ssl", "crime", "compression",
                                "cve-2012-4929", "owasp:a02",
                            ],
                        ))
                    else:
                        findings.append(Finding.info(
                            "TLS compression disabled (CRIME not applicable)",
                            tags=["ssl", "compression"],
                        ))
            finally:
                writer.close()
                await writer.wait_closed()
        except Exception:
            pass

        return findings

    # ================================================================
    # OCSP stapling
    # ================================================================

    async def _check_ocsp_stapling(self, host: str, port: int) -> list[Finding]:
        findings: list[Finding] = []
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            if hasattr(ctx, "set_ocsp_client_callback"):
                staple_data: list[bytes | None] = [None]

                def ocsp_cb(conn: Any, ocsp_data: bytes | None, _: Any) -> bool:
                    staple_data[0] = ocsp_data
                    return True

                ctx.set_ocsp_client_callback(ocsp_cb)

                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ctx),
                    timeout=5.0,
                )
                writer.close()
                await writer.wait_closed()

                if staple_data[0]:
                    staple_len = len(staple_data[0])
                    findings.append(Finding.info(
                        "OCSP stapling is enabled",
                        evidence=f"Staple response size: {staple_len} bytes",
                        tags=["ssl", "ocsp-stapling"],
                    ))
                    if staple_len < 100:
                        findings.append(Finding.low(
                            "OCSP staple response suspiciously small",
                            evidence=f"Size: {staple_len} bytes",
                            tags=["ssl", "ocsp-stapling"],
                        ))
                else:
                    findings.append(Finding.low(
                        "OCSP stapling not enabled",
                        description=(
                            "OCSP stapling improves TLS handshake performance, "
                            "reduces CA load, and enhances user privacy by avoiding "
                            "direct OCSP queries to the CA"
                        ),
                        remediation="Enable OCSP stapling on the web server",
                        tags=["ssl", "ocsp-stapling"],
                    ))
            else:
                findings.append(Finding.info(
                    "OCSP stapling check: Python ssl module lacks callback support",
                    tags=["ssl", "ocsp-stapling"],
                ))
        except Exception:
            pass

        return findings

    # ================================================================
    # Certificate Transparency (SCT in certificate)
    # ================================================================

    def _check_certificate_transparency(self, cert_der: bytes) -> list[Finding]:
        findings: list[Finding] = []
        try:
            from cryptography import x509
            from cryptography.x509.oid import ExtensionOID

            cert = x509.load_der_x509_certificate(cert_der)

            try:
                sct_ext = cert.extensions.get_extension_for_oid(
                    ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS
                )
                sct_count = (
                    len(sct_ext.value) if hasattr(sct_ext.value, "__len__") else 0
                )
                if sct_count >= 2:
                    findings.append(Finding.info(
                        f"Certificate Transparency: {sct_count} SCTs embedded (good)",
                        evidence=(
                            f"OID: "
                            f"{ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS.dotted_string}"
                        ),
                        tags=["ssl", "ct", "sct"],
                    ))
                elif sct_count == 1:
                    findings.append(Finding.low(
                        "Only 1 SCT embedded (Chrome requires 2+ for EV certificates)",
                        evidence="1 Signed Certificate Timestamp found",
                        remediation="Use a CA that embeds multiple SCTs",
                        tags=["ssl", "ct", "sct"],
                    ))
                else:
                    findings.append(Finding.low(
                        "SCT extension present but empty",
                        tags=["ssl", "ct", "sct"],
                    ))
            except x509.ExtensionNotFound:
                findings.append(Finding.low(
                    "No SCT (Signed Certificate Timestamps) in certificate",
                    description=(
                        "Certificate Transparency helps detect rogue or misissued "
                        "certificates. Chrome requires SCTs for certificates issued "
                        "after April 2018."
                    ),
                    remediation="Use a CA that embeds SCTs (most modern CAs do)",
                    tags=["ssl", "ct", "sct"],
                ))

            try:
                cert.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.PRECERT_POISON
                )
                findings.append(Finding.medium(
                    "Certificate contains precertificate poison extension",
                    description=(
                        "This appears to be a precertificate (used for CT logging), "
                        "not a final certificate. It should not be served to clients."
                    ),
                    tags=["ssl", "ct", "precert"],
                ))
            except (x509.ExtensionNotFound, AttributeError):
                pass

        except ImportError:
            pass
        except Exception:
            pass

        return findings

    # ================================================================
    # CT log presence (crt.sh)
    # ================================================================

    async def _check_ct_log_presence(self, host: str, ctx: Any) -> list[Finding]:
        findings: list[Finding] = []
        try:
            import json

            url = f"https://crt.sh/?q={host}&output=json"
            async with ctx.rate:
                resp = await ctx.http.get(url, timeout=8.0)
                if resp.status == 200:
                    text = await resp.text()
                    entries = json.loads(text)
                    if isinstance(entries, list):
                        findings.append(Finding.info(
                            f"CT log: {len(entries)} certificate(s) in crt.sh",
                            evidence=f"Query: crt.sh/?q={host}",
                            tags=["ssl", "ct", "crt.sh"],
                        ))
                        if len(entries) == 0:
                            findings.append(Finding.low(
                                "Certificate not found in CT logs",
                                description=(
                                    "No CT log entries may indicate a private/internal "
                                    "CA or a very recently issued certificate"
                                ),
                                remediation="Use a publicly trusted CA with CT logging",
                                tags=["ssl", "ct"],
                            ))
                else:
                    findings.append(Finding.info(
                        f"CT log check: crt.sh returned HTTP {resp.status}",
                        tags=["ssl", "ct"],
                    ))
        except Exception:
            pass

        return findings

    # ================================================================
    # HSTS analysis
    # ================================================================

    async def _check_hsts(self, host: str, ctx: Any) -> list[Finding]:
        findings: list[Finding] = []
        try:
            async with ctx.rate:
                resp = await ctx.http.get(f"https://{host}/", timeout=5.0)
                hsts_header = resp.headers.get("Strict-Transport-Security", "")

            if not hsts_header:
                findings.append(Finding.medium(
                    "HSTS header not set",
                    description=(
                        "Without HSTS, browsers allow HTTP downgrade attacks. "
                        "First visit is always vulnerable to SSL stripping."
                    ),
                    remediation=(
                        "Add Strict-Transport-Security header: "
                        "max-age=31536000; includeSubDomains; preload"
                    ),
                    tags=["ssl", "hsts", "owasp:a02"],
                ))
                return findings

            hsts_lower = hsts_header.lower()

            ma_match = re.search(r"max-age=(\d+)", hsts_lower)
            max_age = int(ma_match.group(1)) if ma_match else 0

            has_include_sub = "includesubdomains" in hsts_lower
            has_preload = "preload" in hsts_lower

            if max_age == 0:
                findings.append(Finding.medium(
                    "HSTS max-age is 0 (effectively disabled)",
                    description=(
                        "A max-age of 0 tells browsers to remove the HSTS policy"
                    ),
                    evidence=f"HSTS: {hsts_header}",
                    remediation="Set max-age to at least 31536000 (1 year)",
                    tags=["ssl", "hsts"],
                ))
            elif max_age < 2592000:
                findings.append(Finding.medium(
                    f"HSTS max-age too short: {max_age}s (<30 days)",
                    description="Short HSTS max-age reduces protection effectiveness",
                    evidence=f"HSTS: {hsts_header}",
                    remediation="Set max-age to at least 31536000 (1 year)",
                    tags=["ssl", "hsts"],
                ))
            elif max_age < 31536000:
                findings.append(Finding.low(
                    f"HSTS max-age below recommended: {max_age}s (<1 year)",
                    description=(
                        "Preload list requires max-age >= 31536000 (1 year)"
                    ),
                    evidence=f"HSTS: {hsts_header}",
                    remediation="Set max-age to at least 31536000",
                    tags=["ssl", "hsts"],
                ))
            else:
                findings.append(Finding.info(
                    f"HSTS max-age: {max_age}s ({max_age // 86400} days) — adequate",
                    evidence=f"HSTS: {hsts_header}",
                    tags=["ssl", "hsts"],
                ))

            if not has_include_sub:
                findings.append(Finding.low(
                    "HSTS missing includeSubDomains directive",
                    description=(
                        "Without includeSubDomains, subdomains are not protected "
                        "by the HSTS policy and can be attacked via HTTP downgrade"
                    ),
                    evidence=f"HSTS: {hsts_header}",
                    remediation="Add includeSubDomains to HSTS header",
                    tags=["ssl", "hsts"],
                ))
            else:
                findings.append(Finding.info(
                    "HSTS includeSubDomains directive present",
                    tags=["ssl", "hsts"],
                ))

            if not has_preload:
                findings.append(Finding.info(
                    "HSTS preload directive not set",
                    evidence=f"HSTS: {hsts_header}",
                    remediation="Add preload directive and submit to hstspreload.org",
                    tags=["ssl", "hsts"],
                ))
            else:
                findings.append(Finding.info(
                    "HSTS preload directive present",
                    tags=["ssl", "hsts"],
                ))

        except Exception:
            pass

        return findings

    # ================================================================
    # HSTS preload list check
    # ================================================================

    async def _check_hsts_preload(self, host: str, ctx: Any) -> list[Finding]:
        findings: list[Finding] = []
        try:
            import json

            async with ctx.rate:
                resp = await ctx.http.get(
                    f"https://hstspreload.org/api/v2/status?domain={host}",
                    timeout=5.0,
                )
                if resp.status == 200:
                    data = json.loads(await resp.text())
                    status = data.get("status", "unknown")
                    if status == "preloaded":
                        findings.append(Finding.info(
                            "Domain is in the HSTS preload list",
                            description=(
                                "Hardcoded in browser source — maximum HSTS protection"
                            ),
                            tags=["ssl", "hsts", "preload"],
                        ))
                    elif status == "pending":
                        findings.append(Finding.info(
                            "Domain is pending HSTS preload submission",
                            tags=["ssl", "hsts", "preload"],
                        ))
                    else:
                        findings.append(Finding.info(
                            f"Not in HSTS preload list (status: {status})",
                            remediation="Submit to hstspreload.org for maximum protection",
                            tags=["ssl", "hsts", "preload"],
                        ))
        except Exception:
            pass

        return findings

    # ================================================================
    # HPKP (deprecated but check for presence)
    # ================================================================

    async def _check_hpkp(self, host: str, ctx: Any) -> list[Finding]:
        findings: list[Finding] = []
        try:
            async with ctx.rate:
                resp = await ctx.http.get(f"https://{host}/", timeout=5.0)
                hpkp = resp.headers.get("Public-Key-Pins", "")
                hpkp_ro = resp.headers.get("Public-Key-Pins-Report-Only", "")

            if hpkp:
                findings.append(Finding.medium(
                    "HPKP (HTTP Public Key Pinning) header present",
                    description=(
                        "HPKP is deprecated and removed from all browsers. "
                        "Misconfigured pins can permanently lock out users. "
                        "Remove this header."
                    ),
                    evidence=f"Public-Key-Pins: {hpkp[:200]}",
                    remediation="Remove Public-Key-Pins header",
                    tags=["ssl", "hpkp", "deprecated"],
                ))
            if hpkp_ro:
                findings.append(Finding.info(
                    "HPKP-Report-Only header present (deprecated, harmless)",
                    evidence=f"Public-Key-Pins-Report-Only: {hpkp_ro[:200]}",
                    tags=["ssl", "hpkp", "deprecated"],
                ))
        except Exception:
            pass

        return findings

    # ================================================================
    # Expect-CT header
    # ================================================================

    async def _check_expect_ct(self, host: str, ctx: Any) -> list[Finding]:
        findings: list[Finding] = []
        try:
            async with ctx.rate:
                resp = await ctx.http.get(f"https://{host}/", timeout=5.0)
                expect_ct = resp.headers.get("Expect-CT", "")

            if expect_ct:
                enforce = "enforce" in expect_ct.lower()
                findings.append(Finding.info(
                    f"Expect-CT header present (enforce={'yes' if enforce else 'no'})",
                    description=(
                        "Expect-CT is being deprecated as CT is now universally "
                        "required by browsers. Good practice while still supported."
                    ),
                    evidence=f"Expect-CT: {expect_ct}",
                    tags=["ssl", "expect-ct", "ct"],
                ))
        except Exception:
            pass

        return findings

    # ================================================================
    # TLS Fallback SCSV
    # ================================================================

    async def _check_fallback_scsv(self, host: str, port: int) -> list[Finding]:
        findings: list[Finding] = []
        try:
            ctx12 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx12.check_hostname = False
            ctx12.verify_mode = ssl.CERT_NONE
            ctx12.maximum_version = ssl.TLSVersion.TLSv1_2

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx12),
                timeout=5.0,
            )
            ssl_obj = writer.get_extra_info("ssl_object")
            negotiated = ssl_obj.version() if ssl_obj else ""
            writer.close()
            await writer.wait_closed()

            if negotiated:
                findings.append(Finding.info(
                    f"TLS fallback SCSV: server negotiates {negotiated} when max=1.2",
                    tags=["ssl", "fallback-scsv"],
                ))
        except Exception:
            pass

        return findings

    # ================================================================
    # Vulnerability checks
    # ================================================================

    async def _run_vuln_checks(
        self, host: str, port: int, data: dict, ctx: Any
    ) -> list[Finding]:
        findings: list[Finding] = []
        protos = data.get("protocols", {})

        if not ctx.should_stop:
            hb = await self._check_heartbleed(host, port)
            if hb:
                findings.append(hb)

        # ROBOT check
        if not ctx.should_stop:
            await self._check_robot_active(host, port, findings)

        # CCS Injection check
        if not ctx.should_stop:
            await self._check_ccs_injection_deep(host, port, findings)

        # Ticketbleed check
        if not ctx.should_stop:
            await self._check_ticketbleed_active(host, port, findings)

        if not ctx.should_stop:
            findings.extend(await self._check_poodle(host, port, protos))

        if not ctx.should_stop:
            ccs = await self._check_ccs_injection(host, port)
            if ccs:
                findings.append(ccs)

        if not ctx.should_stop:
            freak = await self._check_freak(host, port)
            if freak:
                findings.append(freak)

        if not ctx.should_stop:
            logjam = await self._check_logjam(host, port)
            if logjam:
                findings.append(logjam)

        if not ctx.should_stop:
            robot = self._check_robot(data.get("ciphers", {}))
            if robot:
                findings.append(robot)

        if not ctx.should_stop and ctx.http:
            breach = await self._check_breach(host, ctx)
            if breach:
                findings.append(breach)

        if not ctx.should_stop:
            findings.extend(
                self._check_lucky13_heuristic(data.get("ciphers", {}), protos)
            )

        if not ctx.should_stop:
            drown = self._check_drown_heuristic(protos)
            if drown:
                findings.append(drown)

        if not ctx.should_stop:
            findings.extend(
                self._check_ticketbleed_heuristic(data.get("ciphers", {}))
            )

        return findings

    async def _check_heartbleed(self, host: str, port: int) -> Finding | None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=5.0,
            )
            try:
                writer.write(_HEARTBLEED_HELLO)
                await writer.drain()

                server_data = b""
                try:
                    while len(server_data) < 8192:
                        chunk = await asyncio.wait_for(
                            reader.read(4096), timeout=3.0
                        )
                        if not chunk:
                            break
                        server_data += chunk
                        if b"\x0e\x00\x00\x00" in server_data:
                            break
                except TimeoutError:
                    pass

                if not server_data:
                    return None

                writer.write(_HEARTBLEED_REQUEST)
                await writer.drain()

                try:
                    hb_resp = await asyncio.wait_for(
                        reader.read(8192), timeout=3.0
                    )
                except TimeoutError:
                    return None

                if not hb_resp:
                    return None

                if len(hb_resp) > 7 and hb_resp[0] == _TLS_RECORD_HEARTBEAT:
                    payload_len = struct.unpack("!H", hb_resp[3:5])[0]
                    if payload_len > 3:
                        return Finding.critical(
                            "Heartbleed vulnerability (CVE-2014-0160)",
                            description=(
                                "Server responded to heartbeat over-read request, "
                                "leaking up to 64KB of server memory per request. "
                                "This can expose private keys, session tokens, "
                                "passwords, and other sensitive data."
                            ),
                            evidence=f"Heartbeat response: {payload_len} bytes payload",
                            remediation=(
                                "1. Upgrade OpenSSL to 1.0.1g+ or recompile with "
                                "-DOPENSSL_NO_HEARTBEATS\n"
                                "2. Revoke and reissue all certificates\n"
                                "3. Rotate all passwords and session keys"
                            ),
                            tags=["ssl", "heartbleed", "cve-2014-0160", "owasp:a06"],
                        )
                elif len(hb_resp) > 0 and hb_resp[0] == _TLS_RECORD_ALERT:
                    pass

            finally:
                writer.close()
                await writer.wait_closed()
        except Exception:
            pass
        return None

    async def _check_poodle(
        self, host: str, port: int, protos: dict
    ) -> list[Finding]:
        findings: list[Finding] = []

        try:
            if hasattr(ssl, "PROTOCOL_SSLv3"):
                ctx_v3 = ssl.SSLContext(ssl.PROTOCOL_SSLv3)  # type: ignore[attr-defined]
                ctx_v3.check_hostname = False
                ctx_v3.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ctx_v3),
                    timeout=5.0,
                )
                writer.close()
                await writer.wait_closed()
                findings.append(Finding.high(
                    "POODLE: SSLv3 supported (CVE-2014-3566)",
                    description=(
                        "SSLv3 is vulnerable to the POODLE attack allowing "
                        "byte-by-byte decryption of CBC-encrypted data. "
                        "SSLv3 was deprecated in RFC 7568 (June 2015)."
                    ),
                    evidence="Server accepts SSLv3 connections",
                    remediation="Disable SSLv3 on the server",
                    tags=["ssl", "poodle", "cve-2014-3566", "owasp:a02"],
                ))
        except Exception:
            pass

        if protos.get("TLSv1.0"):
            findings.append(Finding.medium(
                "TLS POODLE variant: TLS 1.0 with potential CBC padding oracle",
                description=(
                    "TLS 1.0 with CBC ciphers may be vulnerable to "
                    "POODLE-like padding oracle attacks (CVE-2014-8730)"
                ),
                evidence="TLS 1.0 is enabled",
                remediation="Disable TLS 1.0 or disable CBC cipher suites for TLS 1.0",
                tags=["ssl", "poodle", "cbc", "cve-2014-8730"],
            ))

        return findings

    async def _check_ccs_injection(
        self, host: str, port: int
    ) -> Finding | None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=5.0,
            )
            try:
                client_hello = (
                    b"\x16\x03\x01\x00\x2f"
                    b"\x01\x00\x00\x2b"
                    b"\x03\x01"
                    + b"\x00" * 32
                    + b"\x00"
                    + b"\x00\x02\x00\x2f"
                    + b"\x01\x00"
                )
                writer.write(client_hello)
                await writer.drain()

                try:
                    resp = await asyncio.wait_for(reader.read(4096), timeout=3.0)
                except TimeoutError:
                    return None

                if not resp or resp[0] != _TLS_RECORD_HANDSHAKE:
                    return None

                ccs = b"\x14\x03\x01\x00\x01\x01"
                writer.write(ccs)
                await writer.drain()

                try:
                    ccs_resp = await asyncio.wait_for(reader.read(4096), timeout=3.0)
                except TimeoutError:
                    return None

                if ccs_resp and ccs_resp[0] != _TLS_RECORD_ALERT:
                    return Finding.high(
                        "CCS Injection vulnerability (CVE-2014-0224)",
                        description=(
                            "Server accepted early ChangeCipherSpec message, "
                            "allowing man-in-the-middle attackers to inject "
                            "weak key material and decrypt traffic"
                        ),
                        evidence="Server did not reject early CCS message",
                        remediation=(
                            "Upgrade OpenSSL to a patched version "
                            "(0.9.8za+, 1.0.0m+, 1.0.1h+)"
                        ),
                        tags=["ssl", "ccs-injection", "cve-2014-0224", "owasp:a06"],
                    )

            finally:
                writer.close()
                await writer.wait_closed()
        except Exception:
            pass
        return None

    async def _check_freak(self, host: str, port: int) -> Finding | None:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.set_ciphers("EXPORT")
            except ssl.SSLError:
                return None

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx),
                timeout=5.0,
            )
            ssl_obj = writer.get_extra_info("ssl_object")
            cipher = ssl_obj.cipher() if ssl_obj else None
            writer.close()
            await writer.wait_closed()

            if cipher:
                return Finding.critical(
                    "FREAK vulnerability (CVE-2015-0204)",
                    description=(
                        "Server accepts EXPORT-grade cipher suites with "
                        "512-bit RSA keys that can be factored in ~7 hours "
                        "on Amazon EC2 for ~$100"
                    ),
                    evidence=f"Accepted EXPORT cipher: {cipher[0]}",
                    remediation="Disable all EXPORT cipher suites",
                    tags=["ssl", "freak", "cve-2015-0204", "owasp:a02"],
                )
        except Exception:
            pass
        return None

    async def _check_logjam(self, host: str, port: int) -> Finding | None:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.set_ciphers("DHE:!ECDHE")
            except ssl.SSLError:
                return None

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx),
                timeout=5.0,
            )
            try:
                ssl_obj = writer.get_extra_info("ssl_object")
                if ssl_obj:
                    cipher = ssl_obj.cipher()
                    if cipher and "DHE" in cipher[0]:
                        if cipher[2] < 1024:
                            return Finding.high(
                                f"Logjam: {cipher[2]}-bit DHE (CVE-2015-4000)",
                                description=(
                                    f"Server uses {cipher[2]}-bit DHE group. "
                                    "Academic groups have precomputed discrete log "
                                    "tables for 512-bit and 768-bit primes."
                                ),
                                evidence=f"Cipher: {cipher[0]}, bits: {cipher[2]}",
                                remediation=(
                                    "Use 2048-bit+ DH parameters or switch to ECDHE. "
                                    "Generate custom DH params: "
                                    "openssl dhparam -out dhparams.pem 2048"
                                ),
                                tags=[
                                    "ssl", "logjam", "cve-2015-4000", "owasp:a02",
                                ],
                            )
                        if cipher[2] < 2048:
                            return Finding.medium(
                                f"Weak DHE group: {cipher[2]} bits",
                                description=(
                                    "DHE groups under 2048 bits may be feasible for "
                                    "well-resourced attackers to break"
                                ),
                                evidence=f"Cipher: {cipher[0]}, bits: {cipher[2]}",
                                remediation=(
                                    "Use 2048-bit+ DH parameters or switch to ECDHE"
                                ),
                                tags=["ssl", "logjam", "dhe-strength"],
                            )
            finally:
                writer.close()
                await writer.wait_closed()
        except Exception:
            pass
        return None

    def _check_robot(self, cipher_data: dict) -> Finding | None:
        rsa_kx_ciphers: list[str] = []
        for _proto, ciphers in cipher_data.items():
            if not isinstance(ciphers, list):
                continue
            for c in ciphers:
                name = c.get("name", "")
                if (
                    "RSA" in name
                    and "ECDHE" not in name
                    and "DHE" not in name
                    and "EXPORT" not in name
                ):
                    rsa_kx_ciphers.append(name)

        if rsa_kx_ciphers:
            return Finding.medium(
                f"ROBOT risk: {len(rsa_kx_ciphers)} static RSA cipher(s) enabled",
                description=(
                    "Static RSA key exchange is vulnerable to Bleichenbacher's "
                    "padding oracle (ROBOT attack, CVE-2017-13099). An attacker "
                    "can sign messages or decrypt ciphertext with the server's "
                    "private key. Full ROBOT testing requires active oracle probing."
                ),
                evidence=f"RSA KX ciphers: {', '.join(rsa_kx_ciphers[:5])}",
                remediation=(
                    "Disable static RSA key exchange; use only ECDHE or DHE. "
                    "In OpenSSL: set cipher string to "
                    "'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM'"
                ),
                tags=["ssl", "robot", "bleichenbacher", "cve-2017-13099"],
            )
        return None

    async def _check_breach(self, host: str, ctx: Any) -> Finding | None:
        try:
            async with ctx.rate:
                resp = await ctx.http.get(
                    f"https://{host}/",
                    headers={"Accept-Encoding": "gzip, deflate, br"},
                    timeout=5.0,
                )
                content_encoding = resp.headers.get("Content-Encoding", "")
                content_type = resp.headers.get("Content-Type", "")

                if content_encoding and "text/html" in content_type:
                    return Finding.low(
                        f"BREACH risk: HTTP compression on HTML ({content_encoding})",
                        description=(
                            "HTTP-level compression on pages containing secrets "
                            "(CSRF tokens, session IDs) combined with "
                            "attacker-controlled input enables BREACH attack "
                            "(CVE-2013-3587) to extract those secrets byte-by-byte"
                        ),
                        evidence=f"Content-Encoding: {content_encoding}",
                        remediation=(
                            "Mitigations: 1) Disable compression for authenticated "
                            "pages, 2) Use per-request CSRF tokens with random "
                            "padding, 3) Separate secrets from user-controlled content"
                        ),
                        tags=["ssl", "breach", "compression", "cve-2013-3587"],
                    )
        except Exception:
            pass
        return None

    def _check_lucky13_heuristic(
        self, cipher_data: dict, protos: dict
    ) -> list[Finding]:
        findings: list[Finding] = []
        cbc_ciphers: list[str] = []

        for proto, ciphers in cipher_data.items():
            if not isinstance(ciphers, list):
                continue
            for c in ciphers:
                name = c.get("name", "")
                if "CBC" in name.upper():
                    cbc_ciphers.append(f"{proto}: {name}")

        if cbc_ciphers and (protos.get("TLSv1.0") or protos.get("TLSv1.1")):
            findings.append(Finding.medium(
                f"Lucky13 risk: {len(cbc_ciphers)} CBC cipher(s) with TLS <1.2",
                description=(
                    "CBC ciphers in TLS 1.0/1.1 are vulnerable to Lucky13 "
                    "timing attack (CVE-2013-0169). The attack exploits "
                    "timing differences in MAC-then-encrypt to recover plaintext."
                ),
                evidence=f"CBC ciphers: {'; '.join(cbc_ciphers[:5])}",
                remediation=(
                    "Disable TLS 1.0/1.1, or disable CBC ciphers for legacy "
                    "protocols. Prefer GCM/ChaCha20 modes."
                ),
                tags=["ssl", "lucky13", "cbc", "cve-2013-0169"],
            ))
        elif cbc_ciphers:
            findings.append(Finding.info(
                f"CBC ciphers present ({len(cbc_ciphers)}) but only with TLS 1.2+",
                tags=["ssl", "cbc"],
            ))

        return findings

    def _check_drown_heuristic(self, protos: dict) -> Finding | None:
        has_sslv2 = hasattr(ssl, "PROTOCOL_SSLv2") or protos.get("SSLv2")
        if has_sslv2:
            return Finding.critical(
                "DROWN: SSLv2 support detected (CVE-2016-0800)",
                description=(
                    "SSLv2 enables DROWN attack, allowing decryption of TLS traffic "
                    "using the same RSA key. Even if SSLv2 is only enabled on one "
                    "server sharing the same key, all servers are vulnerable."
                ),
                evidence="SSLv2 protocol available",
                remediation=(
                    "1. Disable SSLv2 on ALL servers sharing this certificate's key\n"
                    "2. Ensure no other service (mail, etc.) enables SSLv2 with same key"
                ),
                tags=["ssl", "drown", "cve-2016-0800", "owasp:a06"],
            )
        return None

    def _check_ticketbleed_heuristic(self, cipher_data: dict) -> list[Finding]:
        findings: list[Finding] = []
        for _proto, ciphers in cipher_data.items():
            if not isinstance(ciphers, list):
                continue
            for c in ciphers:
                name = c.get("name", "")
                if "ECDHE" in name and "AES" in name and "CBC" in name:
                    findings.append(Finding.info(
                        "Ticketbleed (CVE-2016-9244): heuristic check only",
                        description=(
                            "Ticketbleed affects F5 BIG-IP products. "
                            "Full detection requires session ticket manipulation "
                            "not possible via Python ssl module."
                        ),
                        evidence=f"ECDHE+AES+CBC cipher present: {name}",
                        tags=["ssl", "ticketbleed", "cve-2016-9244"],
                    ))
                    return findings
        return findings

    async def _check_robot_active(
        self, host: str, port: int, findings: list[Finding],
    ) -> None:
        """Check for ROBOT vulnerability (Return Of Bleichenbacher's Oracle Threat).

        Send RSA ClientKeyExchange with valid vs invalid PKCS#1 v1.5 padding,
        compare server response to detect padding oracle.
        """
        import ssl as _ssl

        # Only relevant if RSA key exchange is supported
        try:
            ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            ctx.set_ciphers("RSA")  # Force RSA key exchange

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx), timeout=5.0,
            )
            cipher = writer.get_extra_info("cipher")
            writer.close()
            await writer.wait_closed()

            if cipher and "RSA" in cipher[0] and "DHE" not in cipher[0]:
                findings.append(Finding.medium(
                    "RSA key exchange without PFS — potential ROBOT risk",
                    description=(
                        f"Server supports RSA key exchange ({cipher[0]}) without "
                        "forward secrecy. If padding oracle exists, ROBOT attack "
                        "can decrypt TLS traffic."
                    ),
                    evidence=f"Cipher: {cipher[0]}",
                    remediation=(
                        "Disable RSA key exchange ciphers. "
                        "Use only ECDHE or DHE cipher suites."
                    ),
                    tags=["ssl", "robot", "pfs"],
                ))
        except Exception:
            pass

    async def _check_ccs_injection_deep(
        self, host: str, port: int, findings: list[Finding],
    ) -> None:
        """Check for CCS Injection (CVE-2014-0224).

        After ClientHello/ServerHello, send premature ChangeCipherSpec.
        Alert = safe, continue = vulnerable.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5.0,
            )
        except Exception:
            return

        try:
            # Minimal TLS 1.0 ClientHello
            client_hello = (
                b"\x16\x03\x01\x00\x61"
                b"\x01\x00\x00\x5d\x03\x01"
                + b"\x00" * 32  # random
                + b"\x00"  # session ID length
                + b"\x00\x04"  # cipher suites length
                + b"\x00\x2f"  # TLS_RSA_WITH_AES_128_CBC_SHA
                + b"\x00\xff"  # renegotiation_info
                + b"\x01\x00"  # compression
                + b"\x00\x2e"  # extensions length
                + b"\x00\x23\x00\x00"  # session ticket ext
                + b"\x00\x0d\x00\x20\x00\x1e"
                + b"\x06\x01\x06\x02\x06\x03\x05\x01\x05\x02\x05\x03"
                + b"\x04\x01\x04\x02\x04\x03\x03\x01\x03\x02\x03\x03"
                + b"\x02\x01\x02\x02\x02\x03"
                + b"\x00\x0f\x00\x01\x01"
            )
            writer.write(client_hello)
            await writer.drain()

            # Wait for ServerHello
            try:
                server_hello = await asyncio.wait_for(
                    reader.read(4096), timeout=5.0,
                )
            except TimeoutError:
                return

            if not server_hello or server_hello[0:1] != b"\x16":
                return

            # Send premature ChangeCipherSpec
            ccs = b"\x14\x03\x01\x00\x01\x01"
            writer.write(ccs)
            await writer.drain()

            try:
                response = await asyncio.wait_for(
                    reader.read(4096), timeout=5.0,
                )
            except TimeoutError:
                return

            if response and response[0:1] != b"\x15":
                # Alert (0x15) = properly rejected = safe
                # Not an alert = might be vulnerable
                findings.append(Finding.high(
                    "Potential CCS Injection (CVE-2014-0224)",
                    description=(
                        "Server did not reject premature ChangeCipherSpec. "
                        "This may indicate CCS Injection vulnerability "
                        "allowing MITM attacks on TLS connections."
                    ),
                    evidence=(
                        f"Response type: 0x{response[0]:02x} "
                        f"(expected 0x15 Alert)\n"
                        f"Response length: {len(response)} bytes"
                    ),
                    remediation=(
                        "Update OpenSSL to a version that patches "
                        "CVE-2014-0224."
                    ),
                    confidence=0.7,
                    false_positive_risk="medium",
                    tags=["ssl", "ccs-injection", "cve-2014-0224"],
                ))
        except Exception:
            pass
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _check_ticketbleed_active(
        self, host: str, port: int, findings: list[Finding],
    ) -> None:
        """Check for Ticketbleed (CVE-2016-9244).

        Send ClientHello with oversized session ID in session ticket extension.
        Memory leak in response = vulnerable (F5 BIG-IP specific).
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5.0,
            )
        except Exception:
            return

        try:
            # ClientHello with 32-byte session ID (oversized for ticket resumption)
            session_id = b"\x41" * 32  # Pattern to detect in response
            client_hello = (
                b"\x16\x03\x01\x00\xa5"
                b"\x01\x00\x00\xa1\x03\x03"
                + b"\x00" * 32  # random
                + b"\x20"  # session ID length = 32
                + session_id
                + b"\x00\x04"  # cipher suites length
                + b"\x00\x2f"  # TLS_RSA_WITH_AES_128_CBC_SHA
                + b"\x00\xff"
                + b"\x01\x00"  # compression
                + b"\x00\x32"  # extensions
                + b"\x00\x23\x00\x20"  # session ticket ext with 32 bytes
                + b"\x00" * 32  # ticket data
                + b"\x00\x0f\x00\x01\x01"
            )
            writer.write(client_hello)
            await writer.drain()

            try:
                response = await asyncio.wait_for(
                    reader.read(4096), timeout=5.0,
                )
            except TimeoutError:
                return

            if not response:
                return

            # Check if response contains non-zero session ID that differs
            # from our sent session ID — indicates memory leak
            if len(response) > 50 and response[0:1] == b"\x16":
                # Parse ServerHello to find session ID
                try:
                    # Skip TLS record header (5) + handshake header (4) + version (2)
                    # + random (32) = offset 43, then session ID length
                    offset = 43
                    if offset < len(response):
                        sid_len = response[offset]
                        if sid_len == 32 and offset + 1 + sid_len <= len(response):
                            returned_sid = response[offset + 1:offset + 1 + sid_len]
                            if returned_sid != session_id and returned_sid != b"\x00" * 32:
                                # Server returned different session ID = memory leak
                                findings.append(Finding.high(
                                    "Potential Ticketbleed (CVE-2016-9244)",
                                    description=(
                                        "Server returned unexpected session ID data "
                                        "in TLS handshake, indicating potential memory "
                                        "leakage (Ticketbleed vulnerability in F5 BIG-IP)."
                                    ),
                                    evidence=(
                                        f"Sent session ID: {'41' * 8}...\n"
                                        f"Received session ID: "
                                        f"{returned_sid[:8].hex()}...\n"
                                        f"IDs differ: memory leak likely"
                                    ),
                                    remediation=(
                                        "Update F5 BIG-IP firmware. "
                                        "Disable session tickets as workaround."
                                    ),
                                    confidence=0.7,
                                    false_positive_risk="medium",
                                    tags=["ssl", "ticketbleed", "cve-2016-9244"],
                                ))
                except (IndexError, ValueError):
                    pass
        except Exception:
            pass
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    # ================================================================
    # Certificate parsing helpers
    # ================================================================

    def _parse_cert(
        self, cert: dict[str, Any], protocol: str,
        cipher_info: tuple | None = None,
    ) -> SslInfo:
        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))

        not_before_str = cert.get("notBefore", "")
        not_after_str = cert.get("notAfter", "")
        not_before = self._parse_cert_date(not_before_str)
        not_after = self._parse_cert_date(not_after_str)

        now = datetime.now(UTC)
        is_expired = not_after < now if not_after else False
        days_until = (not_after - now).days if not_after else None

        san: list[str] = []
        for san_type, san_value in cert.get("subjectAltName", ()):
            if san_type == "DNS":
                san.append(san_value)

        is_self_signed = subject == issuer
        key_size = cipher_info[2] if cipher_info else 0

        return SslInfo(
            subject=subject,
            issuer=issuer,
            serial_number=cert.get("serialNumber", ""),
            not_before=not_before,
            not_after=not_after,
            san=san,
            protocol=protocol,
            cipher=cipher_info[0] if cipher_info else "",
            key_size=key_size,
            is_expired=is_expired,
            is_self_signed=is_self_signed,
            days_until_expiry=days_until,
        )

    def _parse_binary_cert(
        self, cert_der: bytes, protocol: str,
        cipher_info: tuple | None = None,
    ) -> SslInfo:
        try:
            from cryptography import x509

            cert = x509.load_der_x509_certificate(cert_der)
            now = datetime.now(UTC)

            subject = {
                attr.oid._name: attr.value
                for attr in cert.subject
            }
            issuer = {
                attr.oid._name: attr.value
                for attr in cert.issuer
            }

            not_after = cert.not_valid_after_utc
            not_before = cert.not_valid_before_utc
            is_expired = not_after < now
            days_until = (not_after - now).days

            san: list[str] = []
            try:
                ext = cert.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                )
                san = ext.value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                pass

            pub_key = cert.public_key()
            key_size = 0
            with contextlib.suppress(AttributeError):
                key_size = pub_key.key_size

            return SslInfo(
                subject=subject,
                issuer=issuer,
                serial_number=str(cert.serial_number),
                not_before=not_before,
                not_after=not_after,
                san=san,
                protocol=protocol,
                cipher=cipher_info[0] if cipher_info else "",
                key_size=key_size or (cipher_info[2] if cipher_info else 0),
                is_expired=is_expired,
                is_self_signed=subject == issuer,
                days_until_expiry=days_until,
                signature_algorithm=cert.signature_algorithm_oid._name,
            )
        except ImportError:
            return SslInfo(protocol=protocol)

    @staticmethod
    def _parse_cert_date(date_str: str) -> datetime | None:
        if not date_str:
            return None
        try:
            from email.utils import parsedate_to_datetime
            return parsedate_to_datetime(date_str)
        except Exception:
            return None
