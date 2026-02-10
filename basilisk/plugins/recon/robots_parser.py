"""robots.txt parser — discovers hidden paths and disallow rules."""

from __future__ import annotations

import re
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class RobotsParserPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="robots_parser",
        display_name="robots.txt Parser",
        category=PluginCategory.RECON,
        description="Parses robots.txt for hidden paths and security insights",
        produces=["robots_paths"],
        timeout=10.0,
    )

    INTERESTING_PATTERNS = re.compile(
        r"(admin|login|dashboard|panel|api|private|secret|backup|config|"
        r"internal|staging|dev|test|debug|old|temp|wp-admin|phpmyadmin|"
        r"\.env|\.git|\.svn|cgi-bin|server-status)",
        re.IGNORECASE,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        findings: list[Finding] = []
        disallow_paths: list[str] = []
        sitemap_urls: list[str] = []

        for scheme in ("https", "http"):
            url = f"{scheme}://{target.host}/robots.txt"
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(url, timeout=8.0)
                    if resp.status == 200:
                        body = await resp.text(encoding="utf-8", errors="replace")
                        disallow_paths, sitemap_urls = self._parse(body)
                        break
            except Exception:
                continue

        if not disallow_paths and not sitemap_urls:
            findings.append(Finding.info(
                "No robots.txt found or empty",
                tags=["recon", "robots"],
            ))
        else:
            findings.append(Finding.info(
                f"robots.txt: {len(disallow_paths)} disallowed paths",
                evidence=", ".join(disallow_paths[:20]),
                tags=["recon", "robots"],
            ))

            interesting = [
                p for p in disallow_paths if self.INTERESTING_PATTERNS.search(p)
            ]
            if interesting:
                findings.append(Finding.low(
                    f"robots.txt reveals {len(interesting)} sensitive paths",
                    description="Disallowed paths may indicate admin panels or sensitive areas",
                    evidence="\n".join(interesting[:15]),
                    remediation="Review robots.txt — avoid disclosing sensitive directory names",
                    tags=["recon", "robots", "info-disclosure"],
                ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "disallow_paths": disallow_paths,
                "sitemaps": sitemap_urls,
            },
        )

    @staticmethod
    def _parse(body: str) -> tuple[list[str], list[str]]:
        disallow: list[str] = []
        sitemaps: list[str] = []
        for line in body.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    disallow.append(path)
            elif line.lower().startswith("sitemap:"):
                url = line.split(":", 1)[1].strip()
                if url:
                    sitemaps.append(url)
        return disallow, sitemaps
