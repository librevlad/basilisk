"""External link extractor — discovers third-party integrations."""

from __future__ import annotations

import re
from typing import ClassVar
from urllib.parse import urlparse

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class LinkExtractorPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="link_extractor",
        display_name="External Link Extractor",
        category=PluginCategory.ANALYSIS,
        description="Extracts external links and third-party resource references",
        produces=["external_links"],
        timeout=10.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        findings: list[Finding] = []
        external_domains: set[str] = set()
        all_links: list[str] = []

        for scheme in ("https", "http"):
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(
                        f"{scheme}://{target.host}/", timeout=8.0,
                    )
                    body = await resp.text(encoding="utf-8", errors="replace")

                    urls = re.findall(
                        r'(?:href|src|action)\s*=\s*["\']?(https?://[^\s"\'<>]+)',
                        body, re.IGNORECASE,
                    )
                    for url in urls:
                        parsed = urlparse(url)
                        hostname = (parsed.hostname or "").lower()
                        if hostname and not hostname.endswith(target.host):
                            external_domains.add(hostname)
                            all_links.append(url)
                    break
            except Exception:
                continue

        if external_domains:
            findings.append(Finding.info(
                f"Found {len(external_domains)} external domains",
                evidence=", ".join(sorted(external_domains)[:20]),
                tags=["analysis", "links"],
            ))

            # Flag known tracking/analytics
            trackers = {d for d in external_domains if any(
                t in d for t in (
                    "google-analytics", "facebook", "doubleclick",
                    "hotjar", "mixpanel", "segment", "yandex", "mail.ru",
                )
            )}
            if trackers:
                findings.append(Finding.info(
                    f"Tracking services: {', '.join(sorted(trackers))}",
                    tags=["analysis", "tracking"],
                ))
        else:
            findings.append(Finding.info(
                "No external links found",
                tags=["analysis", "links"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "external_domains": sorted(external_domains),
                "external_links": all_links[:100],
            },
        )
