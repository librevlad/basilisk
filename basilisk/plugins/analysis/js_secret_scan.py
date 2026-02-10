"""JavaScript secret scanner — finds API keys and tokens in JS files."""

from __future__ import annotations

import re
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

SECRET_PATTERNS = [
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
    ("AWS Secret Key", r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[\w/+=]{40}"),
    ("Google API Key", r"AIza[0-9A-Za-z_-]{35}"),
    ("Google OAuth", r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
    ("Stripe Secret Key", r"sk_live_[0-9a-zA-Z]{24,}"),
    ("Stripe Publishable Key", r"pk_live_[0-9a-zA-Z]{24,}"),
    ("Slack Token", r"xox[bpors]-[0-9a-zA-Z-]{10,}"),
    ("GitHub Token", r"gh[pousr]_[0-9a-zA-Z]{36,}"),
    ("Firebase", r"(?i)firebase[a-zA-Z]*\s*[:=]\s*['\"][A-Za-z0-9_-]+['\"]"),
    ("Private Key", r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    ("JWT Token", r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    ("Bearer Token", r"(?i)bearer\s+[a-zA-Z0-9_\-.~+/]+=*"),
    ("Basic Auth", r"(?i)basic\s+[a-zA-Z0-9+/]+=+"),
    ("Mailgun API Key", r"key-[0-9a-zA-Z]{32}"),
    ("Twilio API Key", r"SK[0-9a-fA-F]{32}"),
    ("SendGrid API Key", r"SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}"),
    ("Hardcoded Password", r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}['\"]"),
    ("API Key Generic", r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][a-zA-Z0-9]{16,}['\"]"),
]


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
            except Exception:
                continue

        # Scan external JS files (limit to 15)
        for js_url in js_urls[:15]:
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(js_url, timeout=8.0)
                    if resp.status == 200:
                        content = await resp.text(encoding="utf-8", errors="replace")
                        self._scan_content(content, js_url, secrets_found)
            except Exception:
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
                f"No secrets found in {len(js_urls) + 1} JS sources",
                tags=["analysis", "secret"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"secrets": secrets_found, "js_files_scanned": len(js_urls)},
        )

    def _scan_content(
        self, content: str, source: str, results: list[dict],
    ) -> None:
        for name, pattern in SECRET_PATTERNS:
            matches = re.findall(pattern, content)
            for match in matches[:3]:
                results.append({
                    "type": name,
                    "match": match if isinstance(match, str) else str(match),
                    "source": source,
                })
