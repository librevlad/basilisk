"""Tests for capability mapping."""

from __future__ import annotations

from basilisk.capabilities.capability import Capability
from basilisk.capabilities.mapping import (
    CAPABILITY_MAP,
    _infer_risk_domain,
    build_capabilities,
)
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


class TestXxeCheckMapping:
    def test_xxe_check_is_host_level(self):
        """xxe_check requires Host+Service:http, not Endpoint:params."""
        entry = CAPABILITY_MAP["xxe_check"]
        assert "Host" in entry["requires"]
        assert "Service:http" in entry["requires"]
        assert "Endpoint:params" not in entry["requires"]


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

    def test_new_fields_default_safe(self):
        """reduces_uncertainty and risk_domain have safe defaults."""
        registry = PluginRegistry()
        registry.discover()
        caps = build_capabilities(registry)
        for name, cap in caps.items():
            assert isinstance(cap.reduces_uncertainty, list)
            assert isinstance(cap.risk_domain, str)
            assert cap.risk_domain != ""

    def test_explicit_risk_domain_preserved(self):
        """Plugins with explicit risk_domain keep their value."""
        registry = PluginRegistry()
        registry.discover()
        caps = build_capabilities(registry)
        assert caps["dns_enum"].risk_domain == "recon"
        assert caps["port_scan"].risk_domain == "network"
        assert caps["sqli_basic"].risk_domain == "web"
        assert caps["ssh_brute"].risk_domain == "auth"
        assert caps["hash_crack"].risk_domain == "crypto"
        assert caps["log_analyze"].risk_domain == "forensics"

    def test_reduces_uncertainty_on_verify_plugins(self):
        """Verification plugins have non-empty reduces_uncertainty."""
        registry = PluginRegistry()
        registry.discover()
        caps = build_capabilities(registry)
        ssti = caps.get("ssti_verify")
        assert ssti is not None
        assert len(ssti.reduces_uncertainty) > 0
        assert "Finding:ssti" in ssti.reduces_uncertainty
        nosqli = caps.get("nosqli_verify")
        assert nosqli is not None
        assert "Finding:nosqli" in nosqli.reduces_uncertainty


class TestContainerCapabilities:
    def test_container_plugins_have_container_risk_domain(self):
        container_plugins = [
            "container_discovery", "container_enumeration", "image_fingerprint",
            "container_config_audit", "container_escape_probe", "registry_lookup",
            "container_verification",
        ]
        for name in container_plugins:
            assert name in CAPABILITY_MAP, f"{name} not in CAPABILITY_MAP"
            assert CAPABILITY_MAP[name].get("risk_domain") == "container", (
                f"{name} should have risk_domain='container'"
            )

    def test_container_verification_has_reduces_uncertainty(self):
        entry = CAPABILITY_MAP["container_verification"]
        assert "reduces_uncertainty" in entry
        assert len(entry["reduces_uncertainty"]) > 0

    def test_container_capabilities_build(self):
        registry = PluginRegistry()
        registry.discover()
        caps = build_capabilities(registry)
        assert "container_discovery" in caps
        assert caps["container_discovery"].risk_domain == "container"
        assert "container_enumeration" in caps
        assert "Container" in caps["container_enumeration"].produces_knowledge


class TestInferRiskDomain:
    def test_recon(self):
        assert _infer_risk_domain("recon") == "recon"

    def test_scanning(self):
        assert _infer_risk_domain("scanning") == "network"

    def test_pentesting(self):
        assert _infer_risk_domain("pentesting") == "web"

    def test_lateral(self):
        assert _infer_risk_domain("lateral") == "auth"

    def test_crypto(self):
        assert _infer_risk_domain("crypto") == "crypto"

    def test_unknown_defaults_to_general(self):
        assert _infer_risk_domain("unknown") == "general"
