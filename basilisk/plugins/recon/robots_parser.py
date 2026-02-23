"""robots.txt parser — discovers hidden paths, directives, and security insights.

Enhanced with resolve_base_url, per-user-agent analysis, expanded sensitive
patterns, wildcard analysis, crawl-delay detection, sitemap extraction,
and pipeline state storage for downstream plugins.
"""

from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass, field
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target
from basilisk.utils.http_check import resolve_base_url

# Extended sensitive path patterns
_SENSITIVE_PATTERNS = re.compile(
    r"(admin|login|dashboard|panel|api|private|secret|backup|config|"
    r"internal|staging|dev|test|debug|old|temp|wp-admin|phpmyadmin|"
    r"\.env|\.git|\.svn|cgi-bin|server-status|database|upload|download|"
    r"\.sql|\.bak|\.zip|\.tar|\.gz|log|error|trace|stack|dump|"
    r"\.key|\.pem|\.p12|credentials|token|auth|password|"
    r"console|manager|monitoring|graphql|swagger|actuator|"
    r"phpinfo|xmlrpc|\.htpasswd|\.htaccess|\.DS_Store)",
    re.IGNORECASE,
)


@dataclass
class _UserAgentBlock:
    """Parsed block of rules for a single User-Agent."""

    user_agent: str
    disallow: list[str] = field(default_factory=list)
    allow: list[str] = field(default_factory=list)
    crawl_delay: float | None = None


class RobotsParserPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="robots_parser",
        display_name="robots.txt Parser",
        category=PluginCategory.RECON,
        description=(
            "Parses robots.txt: per-user-agent rules, sensitive paths, "
            "crawl-delay, sitemaps, wildcard analysis, pipeline state export"
        ),
        produces=["robots_paths"],
        timeout=10.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        findings: list[Finding] = []
        body: str = ""

        # --- Phase 1: Fetch robots.txt using resolve_base_url ---
        base_url = await resolve_base_url(target.host, ctx)
        if base_url:
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(
                        f"{base_url}/robots.txt", timeout=8.0,
                    )
                    if resp.status == 200:
                        body = await resp.text(encoding="utf-8", errors="replace")
            except Exception:
                pass

        if not body.strip():
            findings.append(Finding.info(
                "No robots.txt found or empty",
                tags=["recon", "robots"],
            ))
            return PluginResult.success(
                self.meta.name, target.host,
                findings=findings,
                data={"disallow_paths": [], "sitemaps": [], "blocks": []},
            )

        # --- Phase 2: Full parse ---
        blocks, sitemap_urls = self._parse_full(body)

        # Collect all disallow paths across all user-agents
        all_disallow: list[str] = []
        all_allow: list[str] = []
        seen_disallow: set[str] = set()
        for block in blocks:
            for path in block.disallow:
                if path not in seen_disallow:
                    all_disallow.append(path)
                    seen_disallow.add(path)
            all_allow.extend(block.allow)

        # --- Phase 3: Summary finding ---
        findings.append(Finding.info(
            f"robots.txt: {len(all_disallow)} disallowed, "
            f"{len(all_allow)} allowed, {len(sitemap_urls)} sitemaps, "
            f"{len(blocks)} user-agent blocks",
            evidence=", ".join(all_disallow[:20]),
            tags=["recon", "robots"],
        ))

        # --- Phase 4: Sensitive path detection ---
        interesting = [
            p for p in all_disallow if _SENSITIVE_PATTERNS.search(p)
        ]
        if interesting:
            findings.append(Finding.low(
                f"robots.txt reveals {len(interesting)} sensitive paths",
                description=(
                    "Disallowed paths may indicate admin panels, backup "
                    "files, or other sensitive areas"
                ),
                evidence="\n".join(interesting[:20]),
                remediation=(
                    "Review robots.txt — avoid disclosing sensitive directory "
                    "names. Use authentication rather than robots.txt for access control."
                ),
                tags=["recon", "robots", "info-disclosure"],
            ))

        # --- Phase 5: Per-user-agent analysis ---
        wildcard_block: _UserAgentBlock | None = None
        specific_blocks: list[_UserAgentBlock] = []

        for block in blocks:
            if block.user_agent == "*":
                wildcard_block = block
            else:
                specific_blocks.append(block)

        # Detect when specific bots are blocked
        if specific_blocks:
            blocked_bots = [
                b.user_agent for b in specific_blocks if b.disallow
            ]
            if blocked_bots:
                findings.append(Finding.info(
                    f"robots.txt blocks {len(blocked_bots)} specific bots",
                    evidence=", ".join(blocked_bots[:10]),
                    tags=["recon", "robots", "bot-blocking"],
                ))

        # --- Phase 6: Wildcard / overly permissive analysis ---
        if (
            wildcard_block
            and "/" in wildcard_block.disallow
            and len(wildcard_block.disallow) == 1
            and not wildcard_block.allow
        ):
            findings.append(Finding.info(
                "robots.txt blocks all crawling (Disallow: /)",
                description=(
                    "The entire site is disallowed for all user-agents. "
                    "This may hide content from search engines but does "
                    "not provide security."
                ),
                tags=["recon", "robots", "full-block"],
            ))

        # Check for empty disallow (allows everything)
        for block in blocks:
            if not block.disallow and block.user_agent == "*":
                findings.append(Finding.info(
                    "robots.txt has no restrictions for wildcard user-agent",
                    tags=["recon", "robots"],
                ))

        # --- Phase 7: Crawl-delay detection ---
        delays = [
            (b.user_agent, b.crawl_delay)
            for b in blocks
            if b.crawl_delay is not None
        ]
        if delays:
            delay_info = ", ".join(
                f"{ua}: {d}s" for ua, d in delays
            )
            findings.append(Finding.info(
                f"Crawl-delay configured: {delay_info}",
                tags=["recon", "robots", "crawl-delay"],
            ))

        # --- Phase 8: Sitemaps ---
        if sitemap_urls:
            findings.append(Finding.info(
                f"robots.txt references {len(sitemap_urls)} sitemaps",
                evidence=", ".join(sitemap_urls[:5]),
                tags=["recon", "robots", "sitemap"],
            ))

        # --- Phase 9: Store in pipeline state for downstream plugins ---
        if all_disallow:
            ctx.state.setdefault("robots_disallow_paths", {})[target.host] = (
                all_disallow
            )

        # Serialisable block data
        blocks_data = [
            {
                "user_agent": b.user_agent,
                "disallow": b.disallow,
                "allow": b.allow,
                "crawl_delay": b.crawl_delay,
            }
            for b in blocks
        ]

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "disallow_paths": all_disallow,
                "allow_paths": all_allow,
                "sitemaps": sitemap_urls,
                "blocks": blocks_data,
                "sensitive_paths": interesting,
            },
        )

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_full(body: str) -> tuple[list[_UserAgentBlock], list[str]]:
        """Parse robots.txt into per-user-agent blocks + sitemap URLs."""
        blocks: list[_UserAgentBlock] = []
        sitemaps: list[str] = []

        current_ua: str | None = None
        current_block: _UserAgentBlock | None = None

        for raw_line in body.splitlines():
            # Strip comments
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue

            lower = line.lower()

            if lower.startswith("user-agent:"):
                ua_value = line.split(":", 1)[1].strip()
                if not ua_value:
                    continue
                # If we were building a previous block, save it
                if current_block is not None and current_ua != ua_value:
                    blocks.append(current_block)
                current_ua = ua_value
                current_block = _UserAgentBlock(user_agent=ua_value)

            elif lower.startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if current_block is None:
                    current_block = _UserAgentBlock(user_agent="*")
                if path:
                    current_block.disallow.append(path)

            elif lower.startswith("allow:"):
                path = line.split(":", 1)[1].strip()
                if current_block is None:
                    current_block = _UserAgentBlock(user_agent="*")
                if path:
                    current_block.allow.append(path)

            elif lower.startswith("crawl-delay:"):
                value = line.split(":", 1)[1].strip()
                if current_block is None:
                    current_block = _UserAgentBlock(user_agent="*")
                with contextlib.suppress(ValueError):
                    current_block.crawl_delay = float(value)

            elif lower.startswith("sitemap:"):
                # Sitemap lines are global (not per-user-agent)
                url = line.split(":", 1)[1].strip()
                # Re-join because URL contains ':'
                if "://" not in url:
                    url = line.split(" ", 1)[1].strip() if " " in line else ""
                if url and url.startswith("http"):
                    sitemaps.append(url)

        # Don't forget the last block
        if current_block is not None:
            blocks.append(current_block)

        return blocks, sitemaps
