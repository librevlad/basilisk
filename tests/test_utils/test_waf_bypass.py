"""Tests for WAF adaptive bypass engine."""

from __future__ import annotations

from basilisk.utils.waf_bypass import (
    WAF_PROFILES,
    BypassResult,
    WafBypassEngine,
    _case_swap,
    _comment_split,
    _double_encode,
    _multiline,
    _null_byte,
    _unicode_normalize,
    _whitespace_variant,
)


class TestWafProfiles:
    def test_profiles_count(self):
        assert len(WAF_PROFILES) >= 20

    def test_cloudflare_profile(self):
        cf = WAF_PROFILES["Cloudflare"]
        assert cf.name == "Cloudflare"
        assert len(cf.effective_encodings) > 0

    def test_unknown_waf_profile(self):
        unknown = WAF_PROFILES["Unknown WAF"]
        # Unknown WAF should have all common techniques
        assert len(unknown.effective_encodings) >= 5

    def test_all_profiles_have_encodings(self):
        for name, profile in WAF_PROFILES.items():
            assert len(profile.effective_encodings) > 0, (
                f"WAF {name} has no effective_encodings"
            )


class TestEncodingFunctions:
    def test_double_encode(self):
        result = _double_encode("' OR 1=1--")
        assert "'" not in result
        assert "%2527" in result

    def test_case_swap(self):
        result = _case_swap("' OR 1=1--")
        assert result != "' OR 1=1--"
        # Should contain alternating case
        assert "oR" in result or "Or" in result or "or" not in result.lower()

    def test_comment_split(self):
        result = _comment_split("' OR 1=1--")
        assert "/**/" in result

    def test_whitespace_variant(self):
        result = _whitespace_variant("' OR 1=1--")
        assert "\t" in result
        assert " " not in result

    def test_null_byte(self):
        result = _null_byte("' OR 1=1--")
        assert "%00" in result

    def test_unicode_normalize(self):
        result = _unicode_normalize("' OR 1=1--")
        assert result != "' OR 1=1--"

    def test_multiline(self):
        result = _multiline("' OR 1=1--")
        assert "%0a" in result


class TestWafBypassEngine:
    def test_initial_state(self):
        engine = WafBypassEngine()
        assert not engine.waf_detected
        assert engine.waf_name == ""
        assert engine.profile is None

    def test_set_waf(self):
        engine = WafBypassEngine()
        engine.set_waf("Cloudflare")
        assert engine.waf_detected
        assert engine.waf_name == "Cloudflare"
        assert engine.profile is not None
        assert engine.profile.name == "Cloudflare"

    def test_set_unknown_waf(self):
        engine = WafBypassEngine()
        engine.set_waf("Unknown WAF")
        assert engine.waf_detected
        assert engine.profile is not None

    def test_encode_no_waf(self):
        engine = WafBypassEngine()
        result = engine.encode("' OR 1=1--")
        assert result == ["' OR 1=1--"]

    def test_encode_with_waf(self):
        engine = WafBypassEngine()
        engine.set_waf("Cloudflare")
        result = engine.encode("' OR 1=1--")
        assert len(result) > 1  # Original + variants
        assert result[0] == "' OR 1=1--"  # First is always original

    def test_encode_with_headers(self):
        engine = WafBypassEngine()
        engine.set_waf("AWS WAF")
        result = engine.encode_with_headers("' OR 1=1--")
        assert len(result) > 1
        # Should include header-based bypass
        has_headers = any(h for _, h in result if h)
        assert has_headers

    def test_record_success(self):
        engine = WafBypassEngine()
        engine.record_success("example.com", "double_encode")
        techniques = engine.get_working_techniques("example.com")
        assert "double_encode" in techniques

    def test_record_failure(self):
        engine = WafBypassEngine()
        engine.record_failure("example.com", "case_swap")
        # No crash, failure recorded internally

    def test_get_best_encoding(self):
        engine = WafBypassEngine()
        engine.set_waf("Cloudflare")
        engine.record_success("example.com", "double_encode")
        result = engine.get_best_encoding("example.com", "' OR 1=1--")
        # Should use double_encode since it was successful
        assert result != "' OR 1=1--"

    def test_get_best_encoding_no_history(self):
        engine = WafBypassEngine()
        engine.set_waf("ModSecurity")
        result = engine.get_best_encoding("new-host.com", "' OR 1=1--")
        # Should use first profile encoding
        assert result != "' OR 1=1--"

    def test_encode_uniqueness(self):
        engine = WafBypassEngine()
        engine.set_waf("Unknown WAF")
        result = engine.encode("' OR 1=1--")
        # All variants should be unique
        assert len(result) == len(set(result))

    def test_bypass_result_defaults(self):
        r = BypassResult(original="test", encoded="test", technique="none")
        assert not r.passed
        assert r.status == 0
        assert r.waf_name == ""
