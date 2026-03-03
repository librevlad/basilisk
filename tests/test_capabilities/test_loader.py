"""Tests for the YAML capability loader."""

from __future__ import annotations

from basilisk.capabilities.loader import _DATA_DIR, load_capability_map, reset_cache


class TestLoadCapabilityMap:
    def setup_method(self):
        reset_cache()

    def test_loads_all_entries(self):
        cap_map = load_capability_map()
        assert len(cap_map) > 100

    def test_all_entries_have_required_keys(self):
        cap_map = load_capability_map()
        for name, entry in cap_map.items():
            assert "requires" in entry, f"{name} missing 'requires'"
            assert "produces" in entry, f"{name} missing 'produces'"
            assert "cost" in entry, f"{name} missing 'cost'"
            assert "noise" in entry, f"{name} missing 'noise'"

    def test_cost_in_range(self):
        cap_map = load_capability_map()
        for name, entry in cap_map.items():
            assert 1 <= entry["cost"] <= 10, f"{name} cost out of range: {entry['cost']}"

    def test_noise_in_range(self):
        cap_map = load_capability_map()
        for name, entry in cap_map.items():
            assert 1 <= entry["noise"] <= 10, f"{name} noise out of range: {entry['noise']}"

    def test_caching(self):
        map1 = load_capability_map()
        map2 = load_capability_map()
        assert map1 is map2

    def test_reset_cache(self):
        map1 = load_capability_map()
        reset_cache()
        map2 = load_capability_map()
        assert map1 is not map2
        assert map1 == map2

    def test_data_dir_exists(self):
        assert _DATA_DIR.is_dir()

    def test_yaml_files_exist(self):
        yaml_files = list(_DATA_DIR.glob("*.yaml"))
        assert len(yaml_files) >= 10

    def test_known_entries_present(self):
        cap_map = load_capability_map()
        assert "dns_enum" in cap_map
        assert "port_scan" in cap_map
        assert "sqli_basic" in cap_map
        assert "container_discovery" in cap_map
        assert "hash_crack" in cap_map

    def test_dns_enum_values(self):
        cap_map = load_capability_map()
        entry = cap_map["dns_enum"]
        assert entry["requires"] == ["Host"]
        assert "Host:dns_data" in entry["produces"]
        assert entry["cost"] == 1
        assert entry["noise"] == 1

    def test_reduces_uncertainty_loaded(self):
        cap_map = load_capability_map()
        entry = cap_map.get("waf_bypass")
        assert entry is not None
        assert "reduces_uncertainty" in entry
        assert len(entry["reduces_uncertainty"]) > 0

    def test_detects_loaded(self):
        cap_map = load_capability_map()
        entry = cap_map.get("sqli_basic")
        assert entry is not None
        assert "detects" in entry
        assert "sqli" in entry["detects"]

    def test_risk_domain_loaded(self):
        cap_map = load_capability_map()
        entry = cap_map.get("port_scan")
        assert entry is not None
        assert entry.get("risk_domain") == "network"
