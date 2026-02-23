"""Tests for basilisk.data.loader — YAML data loading with caching."""

from __future__ import annotations

import pytest

from basilisk.data.loader import (
    load_payload_defaults,
    load_payloads,
    load_waf_profiles,
    load_yaml,
)


class TestLoadYaml:
    def test_load_existing_file(self):
        data = load_yaml("waf_profiles")
        assert isinstance(data, dict)
        assert "profiles" in data

    def test_load_nonexistent_file(self):
        with pytest.raises(FileNotFoundError):
            load_yaml("nonexistent_file_xyz")

    def test_load_subdirectory(self):
        data = load_yaml("payloads/sqli")
        assert isinstance(data, dict)
        assert "payloads" in data
        assert "defaults" in data


class TestLoadPayloads:
    def test_load_sqli(self):
        payloads = load_payloads("sqli")
        assert len(payloads) >= 40
        assert all(isinstance(p, dict) for p in payloads)
        assert all("value" in p for p in payloads)

    def test_load_xss(self):
        payloads = load_payloads("xss")
        assert len(payloads) >= 20
        assert any("script" in p["value"].lower() for p in payloads)

    def test_load_all_categories(self):
        categories = [
            "sqli", "xss", "ssti", "lfi", "rce", "ssrf", "xxe",
            "crlf", "nosqli", "redirect", "jwt", "pp", "header",
        ]
        for cat in categories:
            payloads = load_payloads(cat)
            assert len(payloads) > 0, f"Category {cat} has no payloads"

    def test_payload_has_description(self):
        payloads = load_payloads("sqli")
        for p in payloads:
            assert "description" in p, f"Payload missing description: {p['value']!r}"


class TestLoadPayloadDefaults:
    def test_sqli_defaults(self):
        defaults = load_payload_defaults("sqli")
        assert defaults["context"] == "query"
        assert defaults["dbms"] == "generic"
        assert defaults["waf_level"] == 0
        assert defaults["blind"] is False

    def test_xxe_defaults(self):
        defaults = load_payload_defaults("xxe")
        assert "context" in defaults


class TestLoadWafProfiles:
    def test_load_profiles(self):
        profiles = load_waf_profiles()
        assert len(profiles) >= 20
        assert "Cloudflare" in profiles
        assert "Unknown WAF" in profiles

    def test_profile_structure(self):
        profiles = load_waf_profiles()
        cf = profiles["Cloudflare"]
        assert "effective_encodings" in cf
        assert isinstance(cf["effective_encodings"], list)
        assert len(cf["effective_encodings"]) > 0

    def test_all_profiles_have_encodings(self):
        profiles = load_waf_profiles()
        for name, data in profiles.items():
            assert "effective_encodings" in data, f"WAF {name} has no effective_encodings"
            assert len(data["effective_encodings"]) > 0, f"WAF {name} has empty encodings"
