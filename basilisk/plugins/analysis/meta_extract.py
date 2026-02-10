"""HTML meta tag extractor — discovers site metadata and generator info."""

from __future__ import annotations

import re
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class MetaExtractPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="meta_extract",
        display_name="Meta Tag Extractor",
        category=PluginCategory.ANALYSIS,
        description="Extracts HTML meta tags for site metadata and version info",
        produces=["meta_tags"],
        timeout=10.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        findings: list[Finding] = []
        meta_tags: dict[str, str] = {}

        for scheme in ("https", "http"):
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(
                        f"{scheme}://{target.host}/", timeout=8.0,
                    )
                    body = await resp.text(encoding="utf-8", errors="replace")
                    meta_tags = self._parse_meta(body)
                    break
            except Exception:
                continue

        if not meta_tags:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info("No meta tags found")],
                data={"meta_tags": {}},
            )

        # Check for generator (version disclosure)
        generator = meta_tags.get("generator", "")
        if generator:
            findings.append(Finding.low(
                f"Generator meta tag: {generator}",
                description="Meta generator reveals CMS/framework and version",
                evidence=f"<meta name=\"generator\" content=\"{generator}\">",
                remediation="Remove generator meta tag to reduce fingerprinting",
                tags=["analysis", "meta", "info-disclosure"],
            ))

        # Check for author disclosure
        author = meta_tags.get("author", "")
        if author:
            findings.append(Finding.info(
                f"Author: {author}",
                tags=["analysis", "meta"],
            ))

        # Check for robots noindex
        robots = meta_tags.get("robots", "")
        if "noindex" in robots.lower():
            findings.append(Finding.info(
                "Page set to noindex",
                evidence=f"robots: {robots}",
                tags=["analysis", "meta"],
            ))

        if not findings:
            findings.append(Finding.info(
                f"Extracted {len(meta_tags)} meta tags",
                evidence=", ".join(f"{k}={v[:30]}" for k, v in list(meta_tags.items())[:10]),
                tags=["analysis", "meta"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"meta_tags": meta_tags},
        )

    @staticmethod
    def _parse_meta(html: str) -> dict[str, str]:
        tags: dict[str, str] = {}
        for match in re.finditer(
            r'<meta\s+([^>]+?)/?>', html, re.IGNORECASE | re.DOTALL,
        ):
            attrs = match.group(1)
            name = ""
            content = ""
            name_match = re.search(r'(?:name|property)\s*=\s*["\']([^"\']+)', attrs, re.IGNORECASE)
            content_match = re.search(r'content\s*=\s*["\']([^"\']*)', attrs, re.IGNORECASE)
            if name_match:
                name = name_match.group(1).lower()
            if content_match:
                content = content_match.group(1)
            if name and content:
                tags[name] = content
        return tags
