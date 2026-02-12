"""Tests for deserialization_check plugin."""

from __future__ import annotations

from basilisk.core.plugin import PluginCategory
from basilisk.plugins.pentesting.deserialization_check import (
    DESER_ERROR_PATTERNS,
    SERIAL_SIGNATURES,
    DeserializationCheckPlugin,
)


class TestDeserializationMeta:
    def test_meta_name(self):
        assert DeserializationCheckPlugin.meta.name == "deserialization_check"

    def test_meta_category(self):
        assert DeserializationCheckPlugin.meta.category == PluginCategory.PENTESTING

    def test_produces(self):
        assert "deserialization_findings" in DeserializationCheckPlugin.meta.produces

    def test_timeout(self):
        assert DeserializationCheckPlugin.meta.timeout == 40.0


class TestDeserializationData:
    def test_serial_signatures_platforms(self):
        expected = {"Java", "PHP", "Python", ".NET", "Ruby"}
        assert expected.issubset(set(SERIAL_SIGNATURES.keys()))

    def test_serial_signatures_non_empty(self):
        for platform, sigs in SERIAL_SIGNATURES.items():
            assert len(sigs) > 0, f"No signatures for {platform}"

    def test_error_patterns_platforms(self):
        expected = {"Java", "PHP", "Python", ".NET", "Ruby"}
        assert expected.issubset(set(DESER_ERROR_PATTERNS.keys()))

    def test_error_patterns_non_empty(self):
        for platform, patterns in DESER_ERROR_PATTERNS.items():
            assert len(patterns) > 0, f"No error patterns for {platform}"

    def test_java_signatures(self):
        java_sigs = [sig for sig, _ in SERIAL_SIGNATURES["Java"]]
        assert "rO0AB" in java_sigs  # Base64 Java serialized
        assert "aced0005" in java_sigs  # Hex header

    def test_php_signatures(self):
        php_sigs = [sig for sig, _ in SERIAL_SIGNATURES["PHP"]]
        assert "O:" in php_sigs  # PHP object

    def test_viewstate_protection(self):
        plugin = DeserializationCheckPlugin()
        # Long ViewState is considered protected
        assert plugin._viewstate_is_protected("A" * 300, ".NET")
