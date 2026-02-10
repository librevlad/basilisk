"""Shared test fixtures."""

import pytest

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
