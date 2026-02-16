"""JavaScript secret scanner — finds API keys and tokens in JS files."""

from __future__ import annotations

import logging
import re
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target
from basilisk.utils.secrets import SECRET_REGISTRY

logger = logging.getLogger(__name__)


class JsSecretScanPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="js_secret_scan",
        display_name="JavaScript Secret Scanner",
        category=PluginCategory.ANALYSIS,
        description="Scans JavaScript files for exposed API keys, tokens, and secrets",
        produces=["js_secrets"],
        timeout=30.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        findings: list[Finding] = []
        secrets_found: list[dict] = []

        # Get main page and extract JS URLs
        js_urls: list[str] = []
        base_url = ""

        for scheme in ("https", "http"):
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(
                        f"{scheme}://{target.host}/", timeout=8.0,
                    )
                    base_url = f"{scheme}://{target.host}"
                    body = await resp.text(encoding="utf-8", errors="replace")

                    # Scan inline scripts
                    self._scan_content(body, f"{base_url}/", secrets_found)

                    # Extract JS file URLs
                    srcs = re.findall(
                        r'<script[^>]+src=["\']([^"\']+)["\']', body, re.IGNORECASE,
                    )
                    for src in srcs:
                        if src.startswith("//"):
                            js_urls.append(f"{scheme}:{src}")
                        elif src.startswith("/"):
                            js_urls.append(f"{base_url}{src}")
                        elif src.startswith("http"):
                            js_urls.append(src)
                    break
            except Exception as e:
                logger.debug("js_secret_scan: %s fetch failed: %s", scheme, e)
                continue

        # Scan external JS files (limit to 15)
        js_files_scanned = 0
        for js_url in js_urls[:15]:
            if ctx.should_stop:
                break
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(js_url, timeout=8.0)
                    if resp.status == 200:
                        js_files_scanned += 1
                        content = await resp.text(encoding="utf-8", errors="replace")
                        self._scan_content(content, js_url, secrets_found)
            except Exception as e:
                logger.debug("js_secret_scan: %s failed: %s", js_url, e)
                continue

        for secret in secrets_found:
            sev = "high" if secret["type"] in (
                "AWS Access Key", "Private Key", "Stripe Secret Key",
            ) else "medium"
            findings.append(getattr(Finding, sev)(
                f"Secret found: {secret['type']}",
                description=f"Exposed {secret['type']} in {secret['source']}",
                evidence=secret["match"][:100],
                remediation="Remove secrets from client-side code, use environment variables",
                tags=["analysis", "secret", "javascript"],
            ))

        if not findings:
            findings.append(Finding.info(
                f"No secrets found in {js_files_scanned + 1} JS sources",
                tags=["analysis", "secret"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"secrets": secrets_found, "js_files_scanned": js_files_scanned},
        )

    def _scan_content(
        self, content: str, source: str, results: list[dict],
    ) -> None:
        for sp in SECRET_REGISTRY:
            matches = sp.pattern.findall(content)
            for match in matches[:3]:
                results.append({
                    "type": sp.name,
                    "match": match if isinstance(match, str) else str(match),
                    "source": source,
                })
