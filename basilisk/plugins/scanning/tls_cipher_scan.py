"""TLS cipher and protocol version scanner."""

from __future__ import annotations

import asyncio
import ssl
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon",
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
        if protocol in ("TLSv1", "TLSv1.0"):
            findings.append(Finding.high(
                f"Outdated TLS version: {protocol}",
                description="TLS 1.0 is deprecated and has known vulnerabilities",
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

        # Check for weak ciphers
        if any(weak in cipher_name.upper() for weak in WEAK_CIPHERS):
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
