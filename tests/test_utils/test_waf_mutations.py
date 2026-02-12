"""Tests for WAF mutation engine extensions."""

from __future__ import annotations

from basilisk.utils.waf_bypass import (
    WafBypassEngine,
    _chunked_randomized,
    _double_slash,
    _header_case_variation,
    _json_comment_injection,
    _json_duplicate_keys,
    _json_scientific_numbers,
    _json_unicode_keys,
    _matrix_params,
    _path_normalization,
    _trailing_dot,
)


class TestPathObfuscation:
    def test_matrix_params_basic(self):
        result = _matrix_params("/api/v1/users")
        assert ";bsk=1" in result
        assert result.endswith("/users")

    def test_matrix_params_single_segment(self):
        result = _matrix_params("/users")
        assert ";bsk=1" in result

    def test_matrix_params_no_slash(self):
        result = _matrix_params("payload")
        assert ";bsk=1" in result

    def test_path_normalization(self):
        result = _path_normalization("/api/v1/users")
        assert "/../" in result
        assert "v1" in result

    def test_path_normalization_short(self):
        result = _path_normalization("/a")
        assert result == "/a"

    def test_double_slash(self):
        assert _double_slash("/api/v1/users") == "//api//v1//users"

    def test_double_slash_empty(self):
        assert _double_slash("noslash") == "noslash"

    def test_trailing_dot(self):
        result = _trailing_dot("/api/v1/")
        assert "/./" in result


class TestJsonObfuscation:
    def test_json_unicode_keys(self):
        result = _json_unicode_keys('{"admin": true}')
        assert "\\u" in result
        assert "true" in result

    def test_json_unicode_keys_multiple(self):
        result = _json_unicode_keys('{"name": "test", "id": 1}')
        assert result.count("\\u") >= 2

    def test_json_scientific_numbers(self):
        result = _json_scientific_numbers('{"id": 1}')
        assert "1e0" in result

    def test_json_scientific_numbers_multiple(self):
        result = _json_scientific_numbers('{"id": 1, "count": 42}')
        assert "1e0" in result
        assert "42e0" in result

    def test_json_duplicate_keys(self):
        result = _json_duplicate_keys('{"admin": true}')
        assert result.count('"admin"') == 2
        assert "null" in result

    def test_json_comment_injection_object(self):
        result = _json_comment_injection('{"data": 1}')
        assert "/*bsk*/" in result
        assert result.startswith("{")

    def test_json_comment_injection_other(self):
        result = _json_comment_injection("payload")
        assert "/*bsk*/" in result


class TestProtocolMutations:
    def test_chunked_randomized_terminates(self):
        result = _chunked_randomized("test payload")
        assert result.endswith("0\r\n\r\n")

    def test_chunked_randomized_contains_data(self):
        payload = "hello"
        result = _chunked_randomized(payload)
        # All original chars should be present in chunks
        content = ""
        for line in result.split("\r\n"):
            try:
                int(line, 16)
            except ValueError:
                content += line
        assert "hello" in content or all(c in content for c in payload)

    def test_header_case_variation(self):
        result = _header_case_variation("Content-Type")
        assert result != "Content-Type"
        assert result.lower() == "content-type"


class TestEncodeForContext:
    def test_query_context(self):
        engine = WafBypassEngine()
        engine.set_waf("Unknown WAF")
        variants = engine.encode_for_context("' OR 1=1--", "query")
        assert len(variants) > 1
        assert variants[0] == "' OR 1=1--"

    def test_json_body_context(self):
        engine = WafBypassEngine()
        engine.set_waf("Unknown WAF")
        variants = engine.encode_for_context('{"admin": true}', "json_body")
        assert len(variants) > 1
        assert any("\\u" in v for v in variants)

    def test_path_context(self):
        engine = WafBypassEngine()
        engine.set_waf("Unknown WAF")
        variants = engine.encode_for_context("/api/users/1", "path")
        assert len(variants) > 1
        assert any("//" in v for v in variants)

    def test_xml_context(self):
        engine = WafBypassEngine()
        engine.set_waf("Unknown WAF")
        variants = engine.encode_for_context("<script>alert(1)</script>", "xml_body")
        assert len(variants) > 1

    def test_header_context(self):
        engine = WafBypassEngine()
        engine.set_waf("Unknown WAF")
        variants = engine.encode_for_context("malicious-value", "header")
        assert len(variants) >= 1

    def test_no_waf_returns_original(self):
        engine = WafBypassEngine()
        variants = engine.encode_for_context("test", "query")
        assert variants == ["test"]


class TestTeBypassHeaders:
    def test_returns_variants(self):
        engine = WafBypassEngine()
        headers = engine.get_te_bypass_headers()
        assert len(headers) >= 5
        assert all("Transfer-Encoding" in h or "Transfer-encoding" in h for h in headers)


class TestContentTypeBypasses:
    def test_json_bypasses(self):
        engine = WafBypassEngine()
        bypasses = engine.get_content_type_bypasses("application/json")
        assert len(bypasses) >= 3
        assert "application/csp-report" in bypasses

    def test_form_bypasses(self):
        engine = WafBypassEngine()
        bypasses = engine.get_content_type_bypasses("application/x-www-form-urlencoded")
        assert len(bypasses) >= 2

    def test_unknown_type(self):
        engine = WafBypassEngine()
        bypasses = engine.get_content_type_bypasses("text/plain")
        assert bypasses == ["text/plain"]
