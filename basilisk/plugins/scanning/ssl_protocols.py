"""SSL/TLS protocol and cipher suite scanner.

Enumerates supported TLS protocol versions, cipher suites, PFS support,
elliptic curves, cipher order preference, and TLS Fallback SCSV.
"""

from __future__ import annotations

import asyncio
import ssl
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target
from basilisk.utils.ssl_helpers import (
    _3DES_RE,
    _TLS_VERSIONS,
    _WEAK_CIPHERS_RE,
    get_ciphers_for_protocol,
    test_protocol,
)


class SslProtocolsPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="ssl_protocols",
        display_name="SSL Protocol & Cipher Scanner",
        category=PluginCategory.SCANNING,
        description=(
            "Enumerates TLS protocol versions, cipher suites, PFS support, "
            "elliptic curves, cipher order, and Fallback SCSV"
        ),
        depends_on=["ssl_check"],
        produces=["ssl_protocols"],
        timeout=25.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        data: dict = {}
        host = target.host
        port = 443

        # Read port from ssl_check's stored state if available
        conn_state = ctx.state.get(f"ssl_conn:{host}")
        if conn_state:
            port = conn_state.get("port", 443)

        # 1 — protocol enumeration (TLS 1.0 / 1.1 / 1.2 / 1.3)
        if not ctx.should_stop:
            proto_findings, protos = await self._enumerate_protocols(host, port)
            findings.extend(proto_findings)
            data["protocols"] = protos

        # 2 — cipher enumeration + weak/null/export/anon/3DES/CBC-only checks
        if not ctx.should_stop:
            cipher_findings, cipher_data = await self._enumerate_ciphers(host, port)
            findings.extend(cipher_findings)
            data["ciphers"] = cipher_data

        # 3 — PFS check
        if not ctx.should_stop:
            findings.extend(self._check_pfs(data.get("ciphers", {})))

        # 4 — cipher order / server preference
        if not ctx.should_stop:
            findings.extend(await self._check_cipher_order(host, port))

        # 5 — elliptic curves
        if not ctx.should_stop:
            curve_findings, curves = await self._check_curves(host, port)
            findings.extend(curve_findings)
            data["curves"] = curves

        # 6 — TLS Fallback SCSV
        if not ctx.should_stop:
            findings.extend(await self._check_fallback_scsv(host, port))

        return PluginResult.success(
            self.meta.name, host,
            findings=findings,
            data=data,
        )

    # ================================================================
    # Protocol enumeration
    # ================================================================

    async def _enumerate_protocols(
        self, host: str, port: int
    ) -> tuple[list[Finding], dict[str, bool]]:
        findings: list[Finding] = []
        protos: dict[str, bool] = {}

        tasks = [test_protocol(host, port, ver) for _, ver in _TLS_VERSIONS]
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
            get_ciphers_for_protocol(host, port, v) for _, v in proto_versions
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
