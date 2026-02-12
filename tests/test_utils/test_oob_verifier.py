"""Tests for OOB verifier utility."""

from __future__ import annotations

import time
from dataclasses import dataclass
from unittest.mock import MagicMock

import pytest

from basilisk.utils.oob_verifier import (
    NoopOobVerifier,
    OobVerifier,
    OobVulnType,
)


@dataclass(frozen=True)
class FakeCallbackHit:
    token: str
    protocol: str
    source_ip: str
    timestamp: float
    data: dict


_token_counter = 0


def _make_callback_mock(*, has_hits: bool = False) -> MagicMock:
    """Create a mock CallbackServer."""
    global _token_counter  # noqa: PLW0603

    def _unique_token(**kwargs):
        global _token_counter  # noqa: PLW0603
        _token_counter += 1
        return f"bsk_test_token_{_token_counter}"

    mock = MagicMock()
    mock.generate_token = MagicMock(side_effect=_unique_token)
    mock.build_payload_url = MagicMock(
        side_effect=lambda token: f"http://callback:8880/{token}",
    )
    mock.build_dns_payload = MagicMock(
        side_effect=lambda token: f"{token}.callback.local",
    )
    if has_hits:
        def _get_hits(token):
            return [FakeCallbackHit(
                token=token,
                protocol="http",
                source_ip="10.0.0.1",
                timestamp=time.time(),
                data={"method": "GET"},
            )]
        mock.get_hits = MagicMock(side_effect=_get_hits)
    else:
        mock.get_hits = MagicMock(return_value=[])
    return mock


class TestOobVerifierCreateProbe:
    def test_rce_probe(self):
        mock_cb = _make_callback_mock()
        verifier = OobVerifier(mock_cb)
        probe = verifier.create_probe("rce", "example.com", "cmd")
        assert probe.vuln_type == OobVulnType.RCE
        assert probe.target == "example.com"
        assert probe.param == "cmd"
        assert len(probe.payloads) >= 5
        assert any("curl" in p.value for p in probe.payloads)
        assert any("nslookup" in p.value for p in probe.payloads)

    def test_ssrf_probe(self):
        mock_cb = _make_callback_mock()
        verifier = OobVerifier(mock_cb)
        probe = verifier.create_probe(OobVulnType.SSRF, "example.com")
        assert probe.vuln_type == OobVulnType.SSRF
        assert len(probe.payloads) >= 2
        assert any("http://" in p.value for p in probe.payloads)

    def test_xxe_probe(self):
        mock_cb = _make_callback_mock()
        verifier = OobVerifier(mock_cb)
        probe = verifier.create_probe("xxe", "example.com")
        assert any("DOCTYPE" in p.value for p in probe.payloads)
        assert any("ENTITY" in p.value for p in probe.payloads)

    def test_sqli_probe(self):
        mock_cb = _make_callback_mock()
        verifier = OobVerifier(mock_cb)
        probe = verifier.create_probe("sqli", "example.com")
        assert any("xp_dirtree" in p.value for p in probe.payloads)

    def test_ssti_probe(self):
        mock_cb = _make_callback_mock()
        verifier = OobVerifier(mock_cb)
        probe = verifier.create_probe("ssti", "example.com")
        assert len(probe.payloads) >= 1

    def test_extra_payloads(self):
        mock_cb = _make_callback_mock()
        verifier = OobVerifier(mock_cb)
        probe = verifier.create_probe(
            "rce", "example.com",
            extra_payloads=[";custom {http_url}"],
        )
        assert any(p.technique == "custom" for p in probe.payloads)

    def test_available_with_callback(self):
        mock_cb = _make_callback_mock()
        verifier = OobVerifier(mock_cb)
        assert verifier.available is True

    def test_available_without_callback(self):
        verifier = OobVerifier(None)
        assert verifier.available is False


class TestOobVerifierVerify:
    @pytest.mark.asyncio
    async def test_verify_hit_received(self):
        mock_cb = _make_callback_mock(has_hits=True)
        verifier = OobVerifier(mock_cb)
        probe = verifier.create_probe("rce", "example.com")
        result = await verifier.verify(probe.token, timeout=2, poll_interval=0.1)
        assert result.confirmed is True
        assert result.protocol == "http"
        assert result.source_ip == "10.0.0.1"
        assert result.poll_attempts >= 1

    @pytest.mark.asyncio
    async def test_verify_timeout(self):
        mock_cb = _make_callback_mock(has_hits=False)
        verifier = OobVerifier(mock_cb)
        probe = verifier.create_probe("rce", "example.com")
        result = await verifier.verify(probe.token, timeout=0.5, poll_interval=0.1)
        assert result.confirmed is False
        assert result.timeout_reached is True
        assert result.poll_attempts >= 2

    @pytest.mark.asyncio
    async def test_verify_batch(self):
        mock_cb = _make_callback_mock(has_hits=True)
        verifier = OobVerifier(mock_cb)
        p1 = verifier.create_probe("rce", "host1")
        p2 = verifier.create_probe("ssrf", "host2")
        results = await verifier.verify_batch(
            [p1.token, p2.token], timeout=2,
        )
        assert len(results) == 2


class TestNoopOobVerifier:
    def test_not_available(self):
        noop = NoopOobVerifier()
        assert noop.available is False

    def test_create_probe_returns_empty(self):
        noop = NoopOobVerifier()
        probe = noop.create_probe("rce", "example.com")
        assert probe.token == ""
        assert len(probe.payloads) == 0

    @pytest.mark.asyncio
    async def test_verify_returns_unconfirmed(self):
        noop = NoopOobVerifier()
        result = await noop.verify("fake_token")
        assert result.confirmed is False
        assert result.timeout_reached is True

    @pytest.mark.asyncio
    async def test_verify_batch_returns_unconfirmed(self):
        noop = NoopOobVerifier()
        results = await noop.verify_batch(["t1", "t2"])
        assert len(results) == 2
        assert all(not r.confirmed for r in results.values())
