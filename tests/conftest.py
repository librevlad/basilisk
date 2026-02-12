"""Shared test fixtures."""

import logging
from unittest.mock import AsyncMock

import pytest

from basilisk.config import Settings
from basilisk.core.executor import PluginContext
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target, TargetScope


@pytest.fixture
def sample_target():
    return Target.domain("example.com")


@pytest.fixture
def sample_subdomain():
    return Target.subdomain("api.example.com", parent="example.com")


@pytest.fixture
def sample_scope():
    scope = TargetScope()
    scope.add(Target.domain("example.com"))
    scope.add(Target.subdomain("api.example.com", parent="example.com"))
    scope.add(Target.subdomain("mail.example.com", parent="example.com"))
    return scope


@pytest.fixture
def sample_finding():
    return Finding.high(
        "Expired SSL Certificate",
        description="Certificate expired 30 days ago",
        evidence="Not After: 2026-01-01",
        remediation="Renew the SSL certificate",
        tags=["ssl", "owasp:a02"],
    )


@pytest.fixture
def sample_result(sample_finding):
    return PluginResult.success(
        plugin="ssl_check",
        target="example.com",
        findings=[sample_finding],
        data={"protocol": "TLSv1.3"},
        duration=1.5,
    )


@pytest.fixture
def mock_ctx():
    """PluginContext with all dependencies mocked for plugin testing."""
    rate = AsyncMock()
    rate.__aenter__ = AsyncMock(return_value=rate)
    rate.__aexit__ = AsyncMock(return_value=False)

    http = AsyncMock()
    dns = AsyncMock()
    net = AsyncMock()
    wordlists = AsyncMock()

    ctx = PluginContext(
        config=Settings(),
        http=http,
        dns=dns,
        net=net,
        rate=rate,
        wordlists=wordlists,
        log=logging.getLogger("test"),
        pipeline={},
        state={"http_scheme": {"example.com": "https"}},
    )
    return ctx
