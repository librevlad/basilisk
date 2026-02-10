"""SSL/TLS analyzer plugin — certificate validation, protocol checks."""

from __future__ import annotations

import asyncio
import ssl
from datetime import UTC, datetime
from typing import Any, ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target
from basilisk.models.types import SslInfo


class SslCheckPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="ssl_check",
        display_name="SSL/TLS Analyzer",
        category=PluginCategory.SCANNING,
        description="Checks SSL certificates, protocols, and cipher suites",
        depends_on=["dns_enum"],
        produces=["ssl_info"],
        timeout=15.0,
    )

    def accepts(self, target: Target) -> bool:
        return True  # Will check if 443 is reachable

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        ssl_info = SslInfo()

        try:
            ssl_info = await self._check_ssl(target.host)
        except Exception as e:
            return PluginResult(
                plugin=self.meta.name,
                target=target.host,
                status="partial",
                findings=[Finding.info(
                    f"SSL not available on {target.host}",
                    evidence=str(e),
                )],
                data={"ssl_available": False},
            )

        # Check certificate expiry
        if ssl_info.is_expired:
            findings.append(Finding.high(
                "Expired SSL certificate",
                description=f"Certificate expired {abs(ssl_info.days_until_expiry or 0)} days ago",
                evidence=f"Not After: {ssl_info.not_after}",
                remediation="Renew the SSL certificate immediately",
                tags=["ssl", "owasp:a02"],
            ))
        elif ssl_info.days_until_expiry is not None and ssl_info.days_until_expiry < 30:
            findings.append(Finding.medium(
                "SSL certificate expiring soon",
                description=f"Certificate expires in {ssl_info.days_until_expiry} days",
                evidence=f"Not After: {ssl_info.not_after}",
                remediation="Renew the SSL certificate before expiry",
                tags=["ssl"],
            ))

        # Check self-signed
        if ssl_info.is_self_signed:
            findings.append(Finding.medium(
                "Self-signed SSL certificate",
                description="Certificate is not signed by a trusted CA",
                evidence=f"Issuer: {ssl_info.issuer}",
                remediation="Use a certificate from a trusted CA",
                tags=["ssl"],
            ))

        # Check protocol
        if ssl_info.protocol and "TLSv1.0" in ssl_info.protocol:
            findings.append(Finding.high(
                "TLS 1.0 in use (deprecated)",
                evidence=f"Protocol: {ssl_info.protocol}",
                remediation="Upgrade to TLS 1.2 or TLS 1.3",
                tags=["ssl", "owasp:a02"],
            ))
        elif ssl_info.protocol and "TLSv1.1" in ssl_info.protocol:
            findings.append(Finding.medium(
                "TLS 1.1 in use (deprecated)",
                evidence=f"Protocol: {ssl_info.protocol}",
                remediation="Upgrade to TLS 1.2 or TLS 1.3",
                tags=["ssl"],
            ))

        findings.append(Finding.info(
            f"SSL: {ssl_info.protocol}, expires in {ssl_info.days_until_expiry}d",
            evidence=f"Subject: {ssl_info.subject}, Issuer: {ssl_info.issuer}",
            tags=["ssl"],
        ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"ssl_info": ssl_info.model_dump()},
        )

    async def _check_ssl(self, host: str, port: int = 443) -> SslInfo:
        """Connect and extract SSL certificate info."""
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

            cert = ssl_obj.getpeercert(binary_form=False)
            cert_bin = ssl_obj.getpeercert(binary_form=True)
            protocol = ssl_obj.version() or ""

            info = SslInfo(protocol=protocol)

            if cert:
                info = self._parse_cert(cert, protocol)
            elif cert_bin:
                info = self._parse_binary_cert(cert_bin, protocol)

            return info
        finally:
            writer.close()
            await writer.wait_closed()

    def _parse_cert(self, cert: dict[str, Any], protocol: str) -> SslInfo:
        """Parse a decoded certificate dictionary."""
        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))

        not_before_str = cert.get("notBefore", "")
        not_after_str = cert.get("notAfter", "")
        not_before = self._parse_cert_date(not_before_str)
        not_after = self._parse_cert_date(not_after_str)

        now = datetime.now(UTC)
        is_expired = not_after < now if not_after else False
        days_until = (not_after - now).days if not_after else None

        san = []
        for san_type, san_value in cert.get("subjectAltName", ()):
            if san_type == "DNS":
                san.append(san_value)

        is_self_signed = subject == issuer

        return SslInfo(
            subject=subject,
            issuer=issuer,
            serial_number=cert.get("serialNumber", ""),
            not_before=not_before,
            not_after=not_after,
            san=san,
            protocol=protocol,
            is_expired=is_expired,
            is_self_signed=is_self_signed,
            days_until_expiry=days_until,
        )

    def _parse_binary_cert(self, cert_der: bytes, protocol: str) -> SslInfo:
        """Parse a DER-encoded certificate using cryptography library."""
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
            is_expired = not_after < now
            days_until = (not_after - now).days

            san: list[str] = []
            try:
                ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                san = ext.value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                pass

            return SslInfo(
                subject=subject,
                issuer=issuer,
                serial_number=str(cert.serial_number),
                not_before=cert.not_valid_before_utc,
                not_after=not_after,
                san=san,
                protocol=protocol,
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
