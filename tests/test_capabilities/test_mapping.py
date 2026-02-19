"""Tests for capability mapping."""

from __future__ import annotations

from basilisk.capabilities.capability import Capability
from basilisk.capabilities.mapping import CAPABILITY_MAP, build_capabilities
from basilisk.core.registry import PluginRegistry


class TestCapabilityMap:
    def test_map_not_empty(self):
        assert len(CAPABILITY_MAP) > 100

    def test_all_entries_have_required_keys(self):
        for name, entry in CAPABILITY_MAP.items():
            assert "requires" in entry, f"{name} missing 'requires'"
            assert "produces" in entry, f"{name} missing 'produces'"
            assert "cost" in entry, f"{name} missing 'cost'"
            assert "noise" in entry, f"{name} missing 'noise'"

    def test_cost_in_range(self):
        for name, entry in CAPABILITY_MAP.items():
            assert 1 <= entry["cost"] <= 10, f"{name} cost out of range: {entry['cost']}"

    def test_noise_in_range(self):
        for name, entry in CAPABILITY_MAP.items():
            assert 1 <= entry["noise"] <= 10, f"{name} noise out of range: {entry['noise']}"


class TestBuildCapabilities:
    def test_builds_for_all_plugins(self):
        registry = PluginRegistry()
        registry.discover()
        caps = build_capabilities(registry)
        assert len(caps) == len(registry.all())

    def test_explicit_mapping_used(self):
        registry = PluginRegistry()
        registry.discover()
        caps = build_capabilities(registry)
        port_scan = caps.get("port_scan")
        assert port_scan is not None
        assert "Service" in port_scan.produces_knowledge
        assert port_scan.cost_score == 3

    def test_auto_inferred_has_defaults(self):
        registry = PluginRegistry()
        registry.discover()
        caps = build_capabilities(registry)
        # All caps should have valid fields
        for name, cap in caps.items():
            assert cap.plugin_name == name
            assert len(cap.requires_knowledge) > 0
            assert len(cap.produces_knowledge) > 0
            assert cap.cost_score > 0
            assert cap.noise_score > 0
            assert cap.execution_time_estimate > 0

    def test_capability_model_fields(self):
        cap = Capability(
            name="test",
            plugin_name="test",
            category="recon",
            requires_knowledge=["Host"],
            produces_knowledge=["Service"],
            cost_score=2.0,
            noise_score=3.0,
            execution_time_estimate=30.0,
        )
        assert cap.name == "test"
        assert cap.cost_score == 2.0
