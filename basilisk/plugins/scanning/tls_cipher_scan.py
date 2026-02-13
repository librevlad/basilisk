"""TLS cipher and protocol version scanner."""

from __future__ import annotations

import asyncio
import ssl
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

# Short names / substrings matched against the negotiated cipher name.
# Any cipher whose upper-cased name contains one of these tokens is weak.
WEAK_CIPHER_TOKENS = {
    "RC4", "RC2", "DES", "3DES", "MD5", "NULL",
    "EXPORT", "anon", "IDEA", "SEED", "CAMELLIA",
    "AECDH", "ADH", "EXP",
}

# Explicit IANA / OpenSSL cipher suite names considered weak or insecure.
WEAK_CIPHERS = {
    # NULL ciphers — no encryption at all
    "TLS_RSA_WITH_NULL_MD5",
    "TLS_RSA_WITH_NULL_SHA",
    "TLS_RSA_WITH_NULL_SHA256",
    "SSL_RSA_WITH_NULL_MD5",
    "SSL_RSA_WITH_NULL_SHA",
    # EXPORT-grade ciphers — artificially weakened key sizes
    "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
    "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
    "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
    "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
    "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
    "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
    "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
    # RC4 ciphers — biased keystream
    "TLS_RSA_WITH_RC4_128_MD5",
    "TLS_RSA_WITH_RC4_128_SHA",
    "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    "TLS_ECDH_RSA_WITH_RC4_128_SHA",
    "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
    "SSL_RSA_WITH_RC4_128_MD5",
    "SSL_RSA_WITH_RC4_128_SHA",
    # DES ciphers — 56-bit key
    "TLS_RSA_WITH_DES_CBC_SHA",
    "TLS_DHE_RSA_WITH_DES_CBC_SHA",
    "TLS_DHE_DSS_WITH_DES_CBC_SHA",
    "SSL_RSA_WITH_DES_CBC_SHA",
    # 3DES / Triple-DES — Sweet32 attack (CVE-2016-2183)
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
    "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
    # Anonymous key exchange — no authentication
    "TLS_DH_anon_WITH_AES_128_CBC_SHA",
    "TLS_DH_anon_WITH_AES_256_CBC_SHA",
    "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
    "TLS_DH_anon_WITH_AES_256_CBC_SHA256",
    "TLS_DH_anon_WITH_RC4_128_MD5",
    "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
    "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
    "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDH_anon_WITH_RC4_128_SHA",
    # Obsolete ciphers — SEED, IDEA
    "TLS_RSA_WITH_SEED_CBC_SHA",
    "TLS_RSA_WITH_IDEA_CBC_SHA",
    "TLS_DHE_DSS_WITH_SEED_CBC_SHA",
    "TLS_DHE_RSA_WITH_SEED_CBC_SHA",
    # CBC mode with RSA key exchange (no forward secrecy)
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA256",
}

# Deprecated TLS/SSL protocol versions
WEAK_PROTOCOLS = {
    "SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1",
}


class TlsCipherScanPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="tls_cipher_scan",
        display_name="TLS Cipher Scanner",
        category=PluginCategory.SCANNING,
        description="Enumerates supported TLS versions and cipher suites",
        depends_on=["port_scan"],
        produces=["tls_info"],
        timeout=30.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        cipher_info: dict = {"protocol": "", "cipher": "", "bits": 0}

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    target.host, 443, ssl=context, server_hostname=target.host,
                ),
                timeout=10.0,
            )

            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj:
                cipher_info["protocol"] = ssl_obj.version() or ""
                cipher_tuple = ssl_obj.cipher()
                if cipher_tuple:
                    cipher_info["cipher"] = cipher_tuple[0]
                    cipher_info["bits"] = cipher_tuple[2]

            writer.close()
            await writer.wait_closed()
        except Exception:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info("Could not establish TLS connection")],
                data=cipher_info,
            )

        protocol = cipher_info["protocol"]
        cipher_name = cipher_info["cipher"]
        bits = cipher_info["bits"]

        # Check for weak protocols
        if protocol in ("SSLv2", "SSLv3"):
            findings.append(Finding.critical(
                f"Insecure protocol: {protocol}",
                description=(
                    f"{protocol} is fundamentally broken "
                    "(POODLE, DROWN)"
                ),
                evidence=f"Protocol: {protocol}",
                remediation="Disable SSLv2/SSLv3; use TLS 1.2+",
                tags=["scanning", "tls"],
            ))
        elif protocol in ("TLSv1", "TLSv1.0"):
            findings.append(Finding.high(
                f"Outdated TLS version: {protocol}",
                description=(
                    "TLS 1.0 is deprecated and has known "
                    "vulnerabilities"
                ),
                evidence=f"Protocol: {protocol}",
                remediation="Upgrade to TLS 1.2 or TLS 1.3",
                tags=["scanning", "tls"],
            ))
        elif protocol == "TLSv1.1":
            findings.append(Finding.medium(
                f"Deprecated TLS version: {protocol}",
                description="TLS 1.1 is deprecated",
                evidence=f"Protocol: {protocol}",
                remediation="Upgrade to TLS 1.2 or TLS 1.3",
                tags=["scanning", "tls"],
            ))

        # Check for weak ciphers (token substring + exact name match)
        upper_name = cipher_name.upper()
        is_weak = (
            any(tok in upper_name for tok in WEAK_CIPHER_TOKENS)
            or cipher_name in WEAK_CIPHERS
        )
        if is_weak:
            findings.append(Finding.high(
                f"Weak cipher suite: {cipher_name}",
                evidence=f"Cipher: {cipher_name} ({bits} bits)",
                remediation="Disable weak cipher suites",
                tags=["scanning", "tls", "cipher"],
            ))

        # Check key size
        if bits and bits < 128:
            findings.append(Finding.high(
                f"Weak key size: {bits} bits",
                evidence=f"Cipher: {cipher_name} ({bits} bits)",
                remediation="Use cipher suites with at least 128-bit keys",
                tags=["scanning", "tls"],
            ))

        if not findings:
            findings.append(Finding.info(
                f"TLS: {protocol}, {cipher_name} ({bits} bits)",
                tags=["scanning", "tls"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data=cipher_info,
        )
