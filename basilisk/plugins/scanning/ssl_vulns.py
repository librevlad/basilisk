"""SSL/TLS vulnerability scanner.

Active checks: Heartbleed, POODLE, CCS Injection, FREAK, Logjam, ROBOT, Ticketbleed.
Passive/heuristic checks: ROBOT, BREACH, Lucky13, DROWN, Ticketbleed.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
import struct
from typing import Any, ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

# ---------------------------------------------------------------------------
# TLS record type constants
# ---------------------------------------------------------------------------
_TLS_RECORD_HANDSHAKE = 0x16
_TLS_RECORD_HEARTBEAT = 0x18
_TLS_RECORD_ALERT = 0x15

# ---------------------------------------------------------------------------
# Heartbleed probe payloads
# ---------------------------------------------------------------------------
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


class SslVulnsPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="ssl_vulns",
        display_name="SSL Vulnerability Scanner",
        category=PluginCategory.SCANNING,
        description=(
            "Active and passive TLS vulnerability checks: Heartbleed, POODLE, "
            "CCS Injection, FREAK, Logjam, ROBOT, BREACH, Lucky13, DROWN, Ticketbleed"
        ),
        depends_on=["ssl_check", "ssl_protocols"],
        produces=["ssl_vulns"],
        timeout=30.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        host = target.host
        port = 443

        conn_state = ctx.state.get(f"ssl_conn:{host}")
        if conn_state:
            port = conn_state.get("port", 443)

        # Read protocol/cipher data from ssl_protocols pipeline result
        protos: dict = {}
        cipher_data: dict = {}
        proto_key = f"ssl_protocols:{host}"
        if proto_key in ctx.pipeline:
            proto_result = ctx.pipeline[proto_key]
            if proto_result.data:
                protos = proto_result.data.get("protocols", {})
                cipher_data = proto_result.data.get("ciphers", {})

        findings.extend(await self._run_vuln_checks(host, port, protos, cipher_data, ctx))

        return PluginResult.success(
            self.meta.name, host,
            findings=findings,
            data={"vulnerabilities_checked": True},
        )

    # ================================================================
    # Vulnerability checks orchestrator
    # ================================================================

    async def _run_vuln_checks(
        self, host: str, port: int, protos: dict,
        cipher_data: dict, ctx: Any,
    ) -> list[Finding]:
        findings: list[Finding] = []

        if not ctx.should_stop:
            hb = await self._check_heartbleed(host, port)
            if hb:
                findings.append(hb)

        # ROBOT active check
        if not ctx.should_stop:
            await self._check_robot_active(host, port, findings)

        # CCS Injection deep check
        if not ctx.should_stop:
            await self._check_ccs_injection_deep(host, port, findings)

        # Ticketbleed active check
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
            robot = self._check_robot(cipher_data)
            if robot:
                findings.append(robot)

        if not ctx.should_stop and ctx.http:
            breach = await self._check_breach(host, ctx)
            if breach:
                findings.append(breach)

        if not ctx.should_stop:
            findings.extend(
                self._check_lucky13_heuristic(cipher_data, protos)
            )

        if not ctx.should_stop:
            drown = self._check_drown_heuristic(protos)
            if drown:
                findings.append(drown)

        if not ctx.should_stop:
            findings.extend(
                self._check_ticketbleed_heuristic(cipher_data)
            )

        return findings

    # ================================================================
    # Active checks
    # ================================================================

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

    async def _check_robot_active(
        self, host: str, port: int, findings: list[Finding],
    ) -> None:
        """Check for ROBOT vulnerability (Return Of Bleichenbacher's Oracle Threat)."""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_ciphers("RSA")

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
        """Deep CCS Injection check (CVE-2014-0224)."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5.0,
            )
        except Exception:
            return

        try:
            client_hello = (
                b"\x16\x03\x01\x00\x61"
                b"\x01\x00\x00\x5d\x03\x01"
                + b"\x00" * 32
                + b"\x00"
                + b"\x00\x04"
                + b"\x00\x2f"
                + b"\x00\xff"
                + b"\x01\x00"
                + b"\x00\x2e"
                + b"\x00\x23\x00\x00"
                + b"\x00\x0d\x00\x20\x00\x1e"
                + b"\x06\x01\x06\x02\x06\x03\x05\x01\x05\x02\x05\x03"
                + b"\x04\x01\x04\x02\x04\x03\x03\x01\x03\x02\x03\x03"
                + b"\x02\x01\x02\x02\x02\x03"
                + b"\x00\x0f\x00\x01\x01"
            )
            writer.write(client_hello)
            await writer.drain()

            try:
                server_hello = await asyncio.wait_for(
                    reader.read(4096), timeout=5.0,
                )
            except TimeoutError:
                return

            if not server_hello or server_hello[0:1] != b"\x16":
                return

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
        """Check for Ticketbleed (CVE-2016-9244)."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5.0,
            )
        except Exception:
            return

        try:
            session_id = b"\x41" * 32
            client_hello = (
                b"\x16\x03\x01\x00\xa5"
                b"\x01\x00\x00\xa1\x03\x03"
                + b"\x00" * 32
                + b"\x20"
                + session_id
                + b"\x00\x04"
                + b"\x00\x2f"
                + b"\x00\xff"
                + b"\x01\x00"
                + b"\x00\x32"
                + b"\x00\x23\x00\x20"
                + b"\x00" * 32
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

            if len(response) > 50 and response[0:1] == b"\x16":
                try:
                    offset = 43
                    if offset < len(response):
                        sid_len = response[offset]
                        if sid_len == 32 and offset + 1 + sid_len <= len(response):
                            returned_sid = response[offset + 1:offset + 1 + sid_len]
                            if returned_sid != session_id and returned_sid != b"\x00" * 32:
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
    # Passive / heuristic checks
    # ================================================================

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
