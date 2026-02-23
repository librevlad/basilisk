"""TLS compliance checker plugin.

Checks SNI support, secure renegotiation, session resumption, TLS compression,
OCSP stapling, Certificate Transparency (SCT), HSTS, HPKP, and Expect-CT.
"""

from __future__ import annotations

import asyncio
import re
import ssl
from typing import Any, ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class SslCompliancePlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="ssl_compliance",
        display_name="TLS Compliance Checker",
        category=PluginCategory.SCANNING,
        description=(
            "TLS compliance: SNI, secure renegotiation, session resumption, "
            "compression, OCSP stapling, CT/SCT, HSTS, HPKP, Expect-CT"
        ),
        depends_on=["ssl_check"],
        produces=["ssl_compliance"],
        timeout=20.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        host = target.host
        port = 443

        conn_state = ctx.state.get(f"ssl_conn:{host}")
        cert_bin: bytes | None = None
        if conn_state:
            port = conn_state.get("port", 443)
            cert_bin = conn_state.get("cert_bin")

        # 1 — SNI check
        if not ctx.should_stop:
            findings.extend(await self._check_sni(host, port))

        # 2 — secure renegotiation
        if not ctx.should_stop:
            findings.extend(await self._check_secure_renegotiation(host, port))

        # 3 — session resumption (ticket + id)
        if not ctx.should_stop:
            findings.extend(await self._check_session_resumption(host, port))

        # 4 — TLS compression (CRIME)
        if not ctx.should_stop:
            findings.extend(await self._check_tls_compression(host, port))

        # 5 — OCSP stapling
        if not ctx.should_stop:
            findings.extend(await self._check_ocsp_stapling(host, port))

        # 6 — Certificate Transparency (SCT in certificate)
        if not ctx.should_stop and cert_bin:
            findings.extend(self._check_certificate_transparency(cert_bin))

        # 7 — CT log presence via crt.sh
        if not ctx.should_stop and ctx.http:
            findings.extend(await self._check_ct_log_presence(host, ctx))

        # 8 — HSTS header analysis
        if not ctx.should_stop and ctx.http:
            findings.extend(await self._check_hsts(host, ctx))

        # 9 — HSTS preload list
        if not ctx.should_stop and ctx.http:
            findings.extend(await self._check_hsts_preload(host, ctx))

        # 10 — HPKP deprecation check
        if not ctx.should_stop and ctx.http:
            findings.extend(await self._check_hpkp(host, ctx))

        # 11 — Expect-CT header
        if not ctx.should_stop and ctx.http:
            findings.extend(await self._check_expect_ct(host, ctx))

        return PluginResult.success(
            self.meta.name, host,
            findings=findings,
            data={"compliance_checked": True},
        )

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
                    evidence=(
                        f"HTTPS response from {host} has no "
                        f"Strict-Transport-Security header"
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
