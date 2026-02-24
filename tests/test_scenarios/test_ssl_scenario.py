"""Tests for SSL/TLS scenario."""

from __future__ import annotations

from unittest.mock import patch

from basilisk.actor.recording import RecordingActor
from basilisk.domain.target import LiveTarget
from basilisk.scenarios.scanning.ssl_scenario import SslScenario


class TestSslScenario:
    def test_meta(self):
        s = SslScenario()
        assert s.meta.name == "ssl_scenario"
        assert s.meta.category == "scanning"
        assert "dns_scenario" in s.meta.depends_on

    async def test_ssl_not_available(self):
        actor = RecordingActor()
        target = LiveTarget.domain("no-ssl.local")
        with patch(
            "basilisk.scenarios.scanning.ssl_scenario._get_cert_info",
            side_effect=ConnectionRefusedError("refused"),
        ):
            result = await SslScenario().run(target, actor, [], {})
        assert result.ok
        assert result.data["ssl_available"] is False

    async def test_ssl_expired(self):
        actor = RecordingActor()
        target = LiveTarget.domain("expired.local")
        cert_info = {
            "subject": "CN=expired.local",
            "issuer": "CN=TestCA",
            "not_after": "Jan 01 00:00:00 2020 GMT",
            "san": [],
        }
        with patch(
            "basilisk.scenarios.scanning.ssl_scenario._get_cert_info",
            return_value=cert_info,
        ):
            result = await SslScenario().run(target, actor, [], {})
        assert result.ok
        expired = [f for f in result.findings if "expired" in f.title.lower()]
        assert len(expired) >= 1

    async def test_self_signed(self):
        actor = RecordingActor()
        target = LiveTarget.domain("self-signed.local")
        cert_info = {
            "subject": "CN=self-signed.local",
            "issuer": "CN=self-signed.local",
            "not_after": "Dec 31 23:59:59 2030 GMT",
            "san": ["self-signed.local"],
        }
        with patch(
            "basilisk.scenarios.scanning.ssl_scenario._get_cert_info",
            return_value=cert_info,
        ):
            result = await SslScenario().run(target, actor, [], {})
        self_signed = [f for f in result.findings if "self-signed" in f.title.lower()]
        assert len(self_signed) >= 1

    async def test_valid_cert(self):
        actor = RecordingActor()
        target = LiveTarget.domain("good.local")
        cert_info = {
            "subject": "CN=good.local",
            "issuer": "CN=Let's Encrypt Authority",
            "not_after": "Dec 31 23:59:59 2027 GMT",
            "san": ["good.local", "www.good.local"],
        }
        with patch(
            "basilisk.scenarios.scanning.ssl_scenario._get_cert_info",
            return_value=cert_info,
        ):
            result = await SslScenario().run(target, actor, [], {})
        assert result.ok
        assert result.data["ssl_available"] is True
        # Should have SAN info finding
        info_findings = [f for f in result.findings if "name(s)" in f.title]
        assert len(info_findings) >= 1

    async def test_produces_ssl_info(self):
        actor = RecordingActor()
        target = LiveTarget.domain("test.local")
        cert_info = {
            "subject": "CN=test.local",
            "issuer": "CN=CA",
            "not_after": "Dec 31 23:59:59 2027 GMT",
            "san": [],
        }
        with patch(
            "basilisk.scenarios.scanning.ssl_scenario._get_cert_info",
            return_value=cert_info,
        ):
            result = await SslScenario().run(target, actor, [], {})
        assert "ssl_info" in result.data
