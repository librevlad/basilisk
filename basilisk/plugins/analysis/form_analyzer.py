"""HTML form analyzer — detects forms and their security properties.

Crawls the main page AND all scan_paths pages to discover forms and extract
their input field names.  Stores ``discovered_forms`` in ``ctx.state`` so
pentesting plugins (via ``collect_injection_points``) get real form data
instead of relying on hardcoded parameter names.
"""

from __future__ import annotations

import logging
import re
from typing import ClassVar
from urllib.parse import urlparse

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target
from basilisk.utils.http_check import resolve_base_url

logger = logging.getLogger(__name__)

# Input types that are never injectable (buttons, hidden tokens, etc.)
_SKIP_INPUT_TYPES = frozenset({
    "submit", "button", "image", "reset", "hidden",
})
# Hidden inputs that ARE worth testing (they carry user-supplied data)
_TESTABLE_HIDDEN_NAMES = frozenset({
    "id", "user_id", "userid", "uid", "account", "item", "product",
    "page", "action", "url", "file", "path", "query", "search",
    "redirect", "return", "next", "callback", "ref", "target",
})


class FormAnalyzerPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="form_analyzer",
        display_name="Form Analyzer",
        category=PluginCategory.ANALYSIS,
        description="Analyzes HTML forms for security issues (CSRF, autocomplete, action)",
        produces=["forms"],
        timeout=30.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        base_url = await resolve_base_url(target.host, ctx)
        if not base_url:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info("Host not reachable via HTTP/HTTPS")],
                data={"forms": []},
            )

        findings: list[Finding] = []
        all_forms: list[dict] = []
        injectable_forms: list[dict] = []  # for ctx.state

        # Collect pages to fetch: main page + scan_paths
        pages: list[str] = ["/"]
        crawled = ctx.state.get("crawled_urls", {}).get(target.host, [])
        for curl in crawled:
            if isinstance(curl, str):
                parsed = urlparse(curl)
                path = parsed.path or "/"
                if path not in pages:
                    pages.append(path)
        pages = pages[:60]  # cap to avoid excessive requests

        fetched = 0
        for path in pages:
            if ctx.should_stop:
                break
            url = f"{base_url}{path}"
            body = await self._fetch(url, ctx)
            if body is None:
                continue
            fetched += 1
            page_forms = self._parse_forms(body, path)
            all_forms.extend(page_forms)

            for form in page_forms:
                # Build injectable form entry for pentesting plugins
                if form.get("inputs"):
                    action = form["action"] or path
                    # Resolve relative action
                    if action and not action.startswith(("http://", "https://", "/")):
                        # Relative to current path
                        parent = path.rsplit("/", 1)[0] if "/" in path else ""
                        action = f"{parent}/{action}"
                    injectable_forms.append({
                        "action": action,
                        "method": form["method"].upper(),
                        "inputs": form["inputs"],
                    })

                # Check for missing CSRF token
                if form["method"].upper() == "POST" and not form["has_csrf"]:
                    findings.append(Finding.medium(
                        f"POST form without CSRF token: {form['action'] or path}",
                        description="Form submits POST without anti-CSRF token",
                        evidence=(
                            f"POST {form['action'] or path} "
                            f"(inputs: {', '.join(form.get('inputs', {}).keys()) or 'none'})"
                        ),
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

        # Store discovered forms for pentesting plugins
        if injectable_forms:
            existing = ctx.state.get("discovered_forms", {})
            host_forms = existing.get(target.host, [])
            # Deduplicate by action+method
            seen = {(f["action"], f["method"]) for f in host_forms}
            for form in injectable_forms:
                key = (form["action"], form["method"])
                if key not in seen:
                    host_forms.append(form)
                    seen.add(key)
            existing[target.host] = host_forms
            ctx.state["discovered_forms"] = existing
            logger.info(
                "form_analyzer: stored %d injectable forms for %s",
                len(host_forms), target.host,
            )

        if not all_forms:
            findings.append(Finding.info(
                f"No forms found ({fetched} pages checked)",
            ))
        elif not findings:
            findings.append(Finding.info(
                f"{len(all_forms)} forms analyzed on {fetched} pages, no issues found",
                tags=["analysis", "form"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"forms": all_forms, "injectable_forms": injectable_forms},
        )

    @staticmethod
    def _parse_forms(html: str, page_path: str = "/") -> list[dict]:
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

            # Extract input field names and values
            inputs: dict[str, str] = {}
            for inp_m in re.finditer(
                r'<(?:input|select|textarea)\s+([^>]*?)/?>', content, re.IGNORECASE,
            ):
                inp_attrs = inp_m.group(1)
                name_m = re.search(r'name\s*=\s*["\']([^"\']+)', inp_attrs, re.IGNORECASE)
                if not name_m:
                    continue
                name = name_m.group(1)
                inp_type = ""
                type_m = re.search(r'type\s*=\s*["\']?(\w+)', inp_attrs, re.IGNORECASE)
                if type_m:
                    inp_type = type_m.group(1).lower()
                # Skip non-injectable types (but keep testable hidden fields)
                if inp_type in _SKIP_INPUT_TYPES:
                    if inp_type != "hidden" or name.lower() not in _TESTABLE_HIDDEN_NAMES:
                        continue
                value = ""
                val_m = re.search(r'value\s*=\s*["\']([^"\']*)', inp_attrs, re.IGNORECASE)
                if val_m:
                    value = val_m.group(1)
                inputs[name] = value

            forms.append({
                "action": action,
                "method": method,
                "autocomplete": autocomplete,
                "has_csrf": has_csrf,
                "has_password": has_password,
                "inputs": inputs,
            })
        return forms

    @staticmethod
    async def _fetch(url: str, ctx) -> str | None:
        try:
            async with ctx.rate:
                resp = await ctx.http.get(url, timeout=8.0)
                if resp.status >= 400:
                    return None
                return await resp.text(encoding="utf-8", errors="replace")
        except Exception as e:
            logger.debug("form_analyzer: fetch %s failed: %s", url, e)
            return None
