"""Tests for domain-specific types."""

from datetime import UTC, datetime

from basilisk.models.types import (
    DnsRecord,
    DnsRecordType,
    HttpInfo,
    PortInfo,
    PortState,
    SslInfo,
    WhoisInfo,
)


class TestDnsRecord:
    def test_a_record(self):
        r = DnsRecord(type=DnsRecordType.A, name="example.com", value="1.2.3.4", ttl=300)
        assert r.type == DnsRecordType.A
        assert r.value == "1.2.3.4"

    def test_mx_record(self):
        r = DnsRecord(
            type=DnsRecordType.MX, name="example.com",
            value="mail.example.com", priority=10,
        )
        assert r.priority == 10


class TestSslInfo:
    def test_expired_cert(self):
        info = SslInfo(
            subject={"CN": "example.com"},
            is_expired=True,
            days_until_expiry=-30,
        )
        assert info.is_expired
        assert info.days_until_expiry == -30

    def test_defaults(self):
        info = SslInfo()
        assert info.san == []
        assert not info.is_expired
        assert not info.is_self_signed


class TestPortInfo:
    def test_open_port(self):
        p = PortInfo(port=443, state=PortState.OPEN, service="https")
        assert p.state == PortState.OPEN
        assert p.service == "https"

    def test_default_state(self):
        p = PortInfo(port=80)
        assert p.state == PortState.CLOSED


class TestHttpInfo:
    def test_with_headers(self):
        info = HttpInfo(
            url="https://example.com",
            status_code=200,
            headers={"Server": "nginx", "Content-Type": "text/html"},
            title="Example",
            server="nginx",
        )
        assert info.status_code == 200
        assert info.server == "nginx"

    def test_security_headers(self):
        info = HttpInfo(
            security_headers={
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": None,
            }
        )
        assert info.security_headers["Strict-Transport-Security"] is not None
        assert info.security_headers["Content-Security-Policy"] is None


class TestWhoisInfo:
    def test_basic(self):
        info = WhoisInfo(
            domain="example.com",
            registrar="Example Registrar",
            creation_date=datetime(2020, 1, 1, tzinfo=UTC),
        )
        assert info.registrar == "Example Registrar"
