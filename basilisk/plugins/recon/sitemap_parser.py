"""sitemap.xml parser — discovers URLs and site structure."""

from __future__ import annotations

import re
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class SitemapParserPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="sitemap_parser",
        display_name="Sitemap Parser",
        category=PluginCategory.RECON,
        description="Parses sitemap.xml for URL discovery and site structure",
        produces=["sitemap_urls"],
        timeout=15.0,
    )

    SITEMAP_PATHS = [
        "/sitemap.xml", "/sitemap_index.xml", "/sitemap.xml.gz",
        "/sitemap1.xml", "/sitemaps/sitemap.xml", "/wp-sitemap.xml",
    ]

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        all_urls: list[str] = []
        found_sitemap = ""

        for scheme in ("https", "http"):
            for path in self.SITEMAP_PATHS:
                url = f"{scheme}://{target.host}{path}"
                try:
                    async with ctx.rate:
                        resp = await ctx.http.get(url, timeout=8.0)
                        if resp.status == 200:
                            body = await resp.text(encoding="utf-8", errors="replace")
                            if "<url" in body.lower() or "<sitemap" in body.lower():
                                urls = re.findall(
                                    r"<loc>\s*(https?://[^<]+)\s*</loc>",
                                    body, re.IGNORECASE,
                                )
                                all_urls.extend(urls)
                                found_sitemap = url
                                break
                except Exception:
                    continue
            if found_sitemap:
                break

        findings: list[Finding] = []
        if all_urls:
            findings.append(Finding.info(
                f"Sitemap: {len(all_urls)} URLs found",
                evidence=f"Source: {found_sitemap}",
                tags=["recon", "sitemap"],
            ))
            # Look for interesting patterns
            interesting = [
                u for u in all_urls
                if re.search(r"(api|admin|dashboard|login|internal)", u, re.IGNORECASE)
            ]
            if interesting:
                findings.append(Finding.low(
                    f"Sitemap reveals {len(interesting)} potentially sensitive URLs",
                    evidence="\n".join(interesting[:10]),
                    tags=["recon", "sitemap"],
                ))
        else:
            findings.append(Finding.info(
                "No sitemap found",
                tags=["recon", "sitemap"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "sitemap_url": found_sitemap,
                "urls_count": len(all_urls),
                "urls": all_urls[:200],
            },
        )
