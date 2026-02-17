"""HTML form analyzer — detects forms and their security properties."""

from __future__ import annotations

import logging
import re
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)


class FormAnalyzerPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="form_analyzer",
        display_name="Form Analyzer",
        category=PluginCategory.ANALYSIS,
        description="Analyzes HTML forms for security issues (CSRF, autocomplete, action)",
        produces=["forms"],
        timeout=10.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        findings: list[Finding] = []
        forms: list[dict] = []

        for scheme in ("https", "http"):
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(
                        f"{scheme}://{target.host}/", timeout=8.0,
                    )
                    body = await resp.text(encoding="utf-8", errors="replace")
                    forms = self._parse_forms(body)
                    break
            except Exception as e:
                logger.debug("form_analyzer: %s fetch failed: %s", scheme, e)
                continue

        for form in forms:
            # Check for missing CSRF token
            if form["method"].upper() == "POST" and not form["has_csrf"]:
                findings.append(Finding.medium(
                    f"POST form without CSRF token: {form['action'] or '/'}",
                    description="Form submits POST without anti-CSRF token",
                    evidence=f"POST {form['action'] or '/'} (no csrf/token hidden field)",
                    remediation="Add CSRF token to all POST forms",
                    tags=["analysis", "form", "csrf"],
                ))

            # Check for password field with autocomplete
            if form["has_password"] and form["autocomplete"] != "off":
                findings.append(Finding.low(
                    "Password field allows autocomplete",
                    evidence=f"Form action: {form['action']}",
                    remediation="Set autocomplete='off' on password fields",
                    tags=["analysis", "form"],
                ))

            # Check for HTTP action on HTTPS page
            if form["action"].startswith("http://"):
                findings.append(Finding.medium(
                    "Form submits to HTTP (insecure)",
                    evidence=f"Action: {form['action']}",
                    remediation="Use HTTPS for form actions",
                    tags=["analysis", "form", "ssl"],
                ))

        if not forms:
            findings.append(Finding.info("No forms found on main page"))
        elif not findings:
            findings.append(Finding.info(
                f"{len(forms)} forms analyzed, no issues found",
                tags=["analysis", "form"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"forms": forms},
        )

    @staticmethod
    def _parse_forms(html: str) -> list[dict]:
        forms = []
        for match in re.finditer(
            r'<form\s+([^>]*)>(.*?)</form>', html, re.IGNORECASE | re.DOTALL,
        ):
            attrs = match.group(1)
            content = match.group(2)
            action = ""
            action_m = re.search(r'action\s*=\s*["\']([^"\']*)', attrs, re.IGNORECASE)
            if action_m:
                action = action_m.group(1)
            method = "GET"
            method_m = re.search(r'method\s*=\s*["\']?(\w+)', attrs, re.IGNORECASE)
            if method_m:
                method = method_m.group(1)
            autocomplete = ""
            auto_m = re.search(r'autocomplete\s*=\s*["\']?([\w-]+)', attrs, re.IGNORECASE)
            if auto_m:
                autocomplete = auto_m.group(1)
            has_csrf = bool(re.search(
                r'(?:name\s*=\s*["\'](?:csrf|_token|csrfmiddlewaretoken|'
                r'authenticity_token|__RequestVerificationToken))',
                content, re.IGNORECASE,
            ))
            has_password = bool(re.search(
                r'type\s*=\s*["\']?password', content, re.IGNORECASE,
            ))
            forms.append({
                "action": action,
                "method": method,
                "autocomplete": autocomplete,
                "has_csrf": has_csrf,
                "has_password": has_password,
            })
        return forms
