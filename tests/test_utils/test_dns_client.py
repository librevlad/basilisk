"""Tests for DnsClient — async DNS resolver."""

from unittest.mock import AsyncMock, MagicMock, patch

import dns.exception
import dns.rdatatype

from basilisk.models.types import DnsRecordType
from basilisk.utils.dns import DnsClient


class TestDnsClientInit:
    def test_default_init(self):
        client = DnsClient()
        assert client.resolver.lifetime == 5.0

    def test_custom_nameservers(self):
        client = DnsClient(nameservers=["1.1.1.1"])
        assert client.resolver.nameservers == ["1.1.1.1"]

    def test_custom_timeout(self):
        client = DnsClient(timeout=10.0)
        assert client.resolver.lifetime == 10.0

    def test_retries_zero(self):
        client = DnsClient(retries=0)
        assert client.resolver.retry_servfail is False


class TestDnsClientResolve:
    async def test_resolve_a_record(self):
        client = DnsClient()
        mock_rdata = MagicMock()
        mock_rdata.__str__ = lambda _: "1.2.3.4"
        mock_answer = MagicMock()
        mock_answer.__iter__ = lambda _: iter([mock_rdata])
        mock_answer.ttl = 300

        with patch.object(client.resolver, "resolve", new_callable=AsyncMock) as m:
            m.return_value = mock_answer
            records = await client.resolve("example.com", "A")

        assert len(records) == 1
        assert records[0].type == DnsRecordType.A
        assert records[0].value == "1.2.3.4"
        assert records[0].ttl == 300
        assert records[0].name == "example.com"

    async def test_resolve_mx_record(self):
        client = DnsClient()
        mock_rdata = MagicMock()
        mock_rdata.__str__ = lambda _: "10 mail.example.com."
        mock_rdata.preference = 10
        mock_rdata.exchange = MagicMock()
        mock_rdata.exchange.__str__ = lambda _: "mail.example.com."
        mock_answer = MagicMock()
        mock_answer.__iter__ = lambda _: iter([mock_rdata])
        mock_answer.ttl = 600

        with patch.object(client.resolver, "resolve", new_callable=AsyncMock) as m:
            m.return_value = mock_answer
            records = await client.resolve("example.com", "MX")

        assert len(records) == 1
        assert records[0].type == DnsRecordType.MX
        assert records[0].priority == 10
        assert records[0].value == "mail.example.com"

    async def test_resolve_cname_strips_dot(self):
        client = DnsClient()
        mock_rdata = MagicMock()
        mock_rdata.__str__ = lambda _: "www.example.com."
        mock_answer = MagicMock()
        mock_answer.__iter__ = lambda _: iter([mock_rdata])
        mock_answer.ttl = 100

        with patch.object(client.resolver, "resolve", new_callable=AsyncMock) as m:
            m.return_value = mock_answer
            records = await client.resolve("example.com", "CNAME")

        assert records[0].value == "www.example.com"

    async def test_resolve_unknown_type(self):
        client = DnsClient()
        records = await client.resolve("example.com", "INVALID")
        assert records == []

    async def test_resolve_dns_error(self):
        client = DnsClient()
        with patch.object(client.resolver, "resolve", new_callable=AsyncMock) as m:
            m.side_effect = dns.exception.DNSException("NXDOMAIN")
            records = await client.resolve("nonexistent.example.com", "A")
        assert records == []


class TestDnsClientBulk:
    async def test_resolve_all(self):
        client = DnsClient()
        with patch.object(client, "resolve", new_callable=AsyncMock) as m:
            m.return_value = []
            await client.resolve_all("example.com")
            # Default: A, AAAA, MX, NS, TXT, CNAME, SOA = 7 calls
            assert m.call_count == 7

    async def test_resolve_all_custom_types(self):
        client = DnsClient()
        with patch.object(client, "resolve", new_callable=AsyncMock) as m:
            m.return_value = []
            await client.resolve_all("example.com", record_types=["A", "MX"])
            assert m.call_count == 2

    async def test_get_ips(self):
        client = DnsClient()
        from basilisk.models.types import DnsRecord
        mock_records = [
            DnsRecord(type=DnsRecordType.A, name="example.com", value="1.2.3.4", ttl=300),
        ]
        with patch.object(client, "resolve", new_callable=AsyncMock) as m:
            m.side_effect = [mock_records, []]  # A returns 1, AAAA returns 0
            ips = await client.get_ips("example.com")
        assert ips == ["1.2.3.4"]

    async def test_reverse_lookup(self):
        client = DnsClient()
        from basilisk.models.types import DnsRecord
        mock_records = [
            DnsRecord(type=DnsRecordType.PTR, name="4.3.2.1.in-addr.arpa",
                      value="host.example.com", ttl=300),
        ]
        with patch.object(client, "resolve", new_callable=AsyncMock) as m:
            m.return_value = mock_records
            hosts = await client.reverse_lookup("1.2.3.4")
        assert hosts == ["host.example.com"]

    async def test_reverse_lookup_error(self):
        client = DnsClient()
        with patch.object(client, "resolve", new_callable=AsyncMock) as m:
            m.side_effect = Exception("fail")
            hosts = await client.reverse_lookup("1.2.3.4")
        assert hosts == []
