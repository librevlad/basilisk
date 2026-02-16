"""SSL/TLS certificate analyzer plugin.

Performs certificate analysis (expiry, key strength, signature algorithm,
chain validation, wildcard detection, fingerprints). Stores connection data
in ctx.state for sub-plugins (ssl_protocols, ssl_vulns, ssl_compliance).
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import ssl
from typing import Any, ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target
from basilisk.models.types import SslInfo
from basilisk.utils.ssl_helpers import ssl_connect

logger = logging.getLogger(__name__)


class SslCheckPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="ssl_check",
        display_name="SSL/TLS Analyzer",
        category=PluginCategory.SCANNING,
        description=(
            "Certificate analysis: expiry, key strength, signature algorithm, "
            "chain validation, wildcard detection, fingerprints"
        ),
        depends_on=["dns_enum"],
        produces=["ssl_info"],
        timeout=30.0,
    )

    def accepts(self, target: Target) -> bool:
        return True

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        data: dict[str, Any] = {}
        host = target.host
        port = 443

        # 1 — connect, extract certificate and negotiated parameters
        try:
            ssl_info, cert_bin, raw_cert_dict = await ssl_connect(host, port)
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

        # Store connection data for sub-plugins (ssl_protocols, ssl_vulns, ssl_compliance)
        ctx.state[f"ssl_conn:{host}"] = {
            "ssl_info": ssl_info,
            "cert_bin": cert_bin,
            "cert_dict": raw_cert_dict,
            "port": port,
        }

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

        except Exception as e:
            logger.debug("ssl_check: chain validation for %s failed: %s", host, e)

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
            logger.debug("ssl_check: cryptography library not available for chain analysis")
        except Exception as e:
            logger.debug("ssl_check: chain cert analysis failed: %s", e)

        return findings
