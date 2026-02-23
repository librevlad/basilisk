"""Tests for adaptive payload engine."""

from __future__ import annotations

from basilisk.utils.payloads import (
    DbmsType,
    InjectionContext,
    MutationEngine,
    Payload,
    PayloadCategory,
    PayloadEngine,
)


class TestPayloadEngine:
    def test_categories_available(self):
        engine = PayloadEngine()
        cats = engine.categories
        assert PayloadCategory.SQLI in cats
        assert PayloadCategory.XSS in cats
        assert PayloadCategory.SSTI in cats
        assert PayloadCategory.LFI in cats
        assert PayloadCategory.RCE in cats
        assert PayloadCategory.SSRF in cats
        assert PayloadCategory.XXE in cats

    def test_total_payload_count(self):
        engine = PayloadEngine()
        total = engine.count()
        assert total >= 100  # should have 100+ payloads total

    def test_get_sqli_payloads(self):
        engine = PayloadEngine()
        payloads = engine.get(PayloadCategory.SQLI)
        assert len(payloads) > 20
        values = [p.value for p in payloads]
        assert "'" in values
        assert "' OR 1=1--" in values

    def test_get_xss_payloads(self):
        engine = PayloadEngine()
        payloads = engine.get(PayloadCategory.XSS)
        assert len(payloads) > 10
        # Should have script-based payloads
        assert any("script" in p.value.lower() for p in payloads)

    def test_filter_by_dbms(self):
        engine = PayloadEngine()
        mysql = engine.get(PayloadCategory.SQLI, dbms=DbmsType.MYSQL)
        postgres = engine.get(PayloadCategory.SQLI, dbms=DbmsType.POSTGRES)
        # MySQL payloads should include SLEEP
        assert any("SLEEP" in p.value.upper() for p in mysql)
        # Postgres payloads should include pg_sleep
        assert any("pg_sleep" in p.value for p in postgres)

    def test_filter_by_waf_level(self):
        engine = PayloadEngine()
        no_waf = engine.get(PayloadCategory.SQLI, max_waf=0)
        with_waf = engine.get(PayloadCategory.SQLI, max_waf=3)
        # WAF-level > 0 payloads excluded when max_waf=0
        assert len(with_waf) > len(no_waf)
        assert all(p.waf_level == 0 for p in no_waf)

    def test_filter_blind_only(self):
        engine = PayloadEngine()
        blind = engine.get(PayloadCategory.SQLI, blind_only=True)
        assert len(blind) > 0
        assert all(p.blind for p in blind)

    def test_limit(self):
        engine = PayloadEngine()
        limited = engine.get(PayloadCategory.SQLI, limit=5)
        assert len(limited) == 5

    def test_get_for_waf(self):
        engine = PayloadEngine()
        waf_payloads = engine.get_for_waf(PayloadCategory.SQLI, "Cloudflare")
        assert len(waf_payloads) > 0
        # WAF payloads should be sorted by waf_level descending
        if len(waf_payloads) > 1:
            assert waf_payloads[0].waf_level >= waf_payloads[-1].waf_level

    def test_get_with_mutations(self):
        engine = PayloadEngine()
        results = engine.get_with_mutations(PayloadCategory.SQLI, limit=3)
        assert len(results) == 3
        for payload, variants in results:
            assert isinstance(payload, Payload)
            assert isinstance(variants, list)

    def test_smart_select(self):
        engine = PayloadEngine()
        payloads = engine.smart_select(
            PayloadCategory.SQLI,
            detected_dbms=DbmsType.MYSQL,
            detected_waf="Cloudflare",
            limit=10,
        )
        assert len(payloads) <= 10
        assert len(payloads) > 0

    def test_smart_select_no_context(self):
        engine = PayloadEngine()
        payloads = engine.smart_select(PayloadCategory.XSS, limit=5)
        assert len(payloads) == 5

    def test_add_custom_payloads(self):
        engine = PayloadEngine()
        before = engine.count(PayloadCategory.SQLI)
        engine.add(PayloadCategory.SQLI, [
            Payload("CUSTOM_PAYLOAD", PayloadCategory.SQLI),
        ])
        after = engine.count(PayloadCategory.SQLI)
        assert after == before + 1

    def test_filter_by_context(self):
        engine = PayloadEngine()
        html_xss = engine.get(
            PayloadCategory.XSS, context=InjectionContext.HTML_TAG,
        )
        assert len(html_xss) > 0
        assert all(p.context == InjectionContext.HTML_TAG for p in html_xss)

    def test_ssti_payloads(self):
        engine = PayloadEngine()
        ssti = engine.get(PayloadCategory.SSTI)
        assert any("{{7*7}}" in p.value for p in ssti)

    def test_ssrf_payloads(self):
        engine = PayloadEngine()
        ssrf = engine.get(PayloadCategory.SSRF)
        assert any("169.254.169.254" in p.value for p in ssrf)


class TestMutationEngine:
    def test_case_swap(self):
        variants = MutationEngine.case_swap("' OR 1=1--")
        assert len(variants) > 0
        assert any("oR" in v or "Or" in v for v in variants)

    def test_comment_split(self):
        variants = MutationEngine.comment_split("' OR 1=1--")
        assert len(variants) > 0
        assert any("/**/" in v for v in variants)

    def test_url_encode(self):
        encoded = MutationEngine.url_encode("' OR 1=1--")
        assert "'" not in encoded
        assert "%27" in encoded

    def test_double_encode(self):
        encoded = MutationEngine.url_encode("' OR 1=1--", double=True)
        assert "%2527" in encoded

    def test_null_byte(self):
        variants = MutationEngine.null_byte_insert("' OR 1=1--")
        assert len(variants) > 0
        assert any("%00" in v for v in variants)

    def test_unicode_normalize(self):
        variants = MutationEngine.unicode_normalize("' OR 1=1--")
        assert len(variants) > 0
        assert all(v != "' OR 1=1--" for v in variants)

    def test_whitespace_variants(self):
        variants = MutationEngine.whitespace_variants("' OR 1=1--")
        assert len(variants) > 0
        assert any("\t" in v or "/**/" in v for v in variants)

    def test_mutate_combined(self):
        variants = MutationEngine.mutate("' OR 1=1--", max_variants=10)
        assert len(variants) <= 10
        assert all(v != "' OR 1=1--" for v in variants)

    def test_mutate_deduplication(self):
        variants = MutationEngine.mutate("' OR 1=1--")
        assert len(variants) == len(set(variants))

    def test_mutate_no_input_in_output(self):
        """Original payload should not appear in variants."""
        original = "' OR 1=1--"
        variants = MutationEngine.mutate(original)
        assert original not in variants
