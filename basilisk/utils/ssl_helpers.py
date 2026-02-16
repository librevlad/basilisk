"""Shared SSL/TLS connection helpers and certificate parsing utilities.

Used by ssl_check, ssl_protocols, ssl_vulns, and ssl_compliance plugins.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import ssl
from datetime import UTC, datetime
from typing import Any

from basilisk.models.types import SslInfo

# ---------------------------------------------------------------------------
# Constants shared across SSL plugins
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# SSL connection helper
# ---------------------------------------------------------------------------
async def ssl_connect(
    host: str, port: int = 443, *, timeout: float = 10.0,
) -> tuple[SslInfo, bytes | None, dict]:
    """Connect to *host:port* via TLS, return (SslInfo, cert_der, cert_dict).

    The connection is closed before returning.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ctx),
        timeout=timeout,
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
            info = parse_cert(cert, protocol, cipher_info)
        elif cert_bin:
            info = parse_binary_cert(cert_bin, protocol, cipher_info)

        return info, cert_bin, cert
    finally:
        writer.close()
        await writer.wait_closed()


# ---------------------------------------------------------------------------
# Protocol / cipher probing
# ---------------------------------------------------------------------------
async def test_protocol(host: str, port: int, version: int) -> bool:
    """Test whether *host:port* accepts a specific TLS protocol version."""
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


async def get_ciphers_for_protocol(
    host: str, port: int, version: int,
) -> list[dict]:
    """Return the list of shared cipher suites for a given TLS version."""
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


# ---------------------------------------------------------------------------
# Certificate parsing
# ---------------------------------------------------------------------------
def parse_cert(
    cert: dict[str, Any], protocol: str,
    cipher_info: tuple | None = None,
) -> SslInfo:
    """Parse a Python ssl peercert dict into an SslInfo model."""
    subject = dict(x[0] for x in cert.get("subject", ()))
    issuer = dict(x[0] for x in cert.get("issuer", ()))

    not_before_str = cert.get("notBefore", "")
    not_after_str = cert.get("notAfter", "")
    not_before = parse_cert_date(not_before_str)
    not_after = parse_cert_date(not_after_str)

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


def parse_binary_cert(
    cert_der: bytes, protocol: str,
    cipher_info: tuple | None = None,
) -> SslInfo:
    """Parse a DER-encoded certificate into an SslInfo model."""
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


def parse_cert_date(date_str: str) -> datetime | None:
    """Parse an SSL certificate date string."""
    if not date_str:
        return None
    try:
        from email.utils import parsedate_to_datetime
        return parsedate_to_datetime(date_str)
    except Exception:
        return None
