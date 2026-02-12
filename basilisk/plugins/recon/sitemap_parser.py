"""sitemap.xml parser — discovers URLs, structure, and parameters.

Enhanced with resolve_base_url, recursive sitemap index handling,
lastmod analysis, URL classification, query parameter extraction,
and pipeline state storage for downstream plugins.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import ClassVar
from urllib.parse import parse_qs, urlparse

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target
from basilisk.utils.http_check import resolve_base_url

# Extended sitemap discovery paths
_SITEMAP_PATHS = [
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/sitemap-index.xml",
    "/sitemap.xml.gz",
    "/sitemap1.xml",
    "/sitemaps/sitemap.xml",
    "/wp-sitemap.xml",
    "/sitemap_news.xml",
    "/post-sitemap.xml",
    "/page-sitemap.xml",
    "/category-sitemap.xml",
    "/product-sitemap.xml",
]

# Regex for extracting <loc> and <lastmod>
_LOC_RE = re.compile(r"<loc>\s*(https?://[^<]+?)\s*</loc>", re.IGNORECASE)
_LASTMOD_RE = re.compile(r"<lastmod>\s*([^<]+?)\s*</lastmod>", re.IGNORECASE)
_SITEMAP_TAG_RE = re.compile(
    r"<sitemap>\s*(.*?)\s*</sitemap>", re.IGNORECASE | re.DOTALL,
)

# Interesting URL patterns for findings
_INTERESTING_RE = re.compile(
    r"(api|admin|dashboard|login|internal|graphql|debug|staging|private|console)",
    re.IGNORECASE,
)

# Classification patterns
_IMAGE_EXTS = frozenset({".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico"})
_FILE_EXTS = frozenset({
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".rar", ".tar", ".gz", ".csv", ".txt",
})

MAX_RECURSION_DEPTH = 3
MAX_URLS = 2000


class SitemapParserPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="sitemap_parser",
        display_name="Sitemap Parser",
        category=PluginCategory.RECON,
        description=(
            "Parses sitemap.xml: recursive index follow, lastmod analysis, "
            "URL classification, parameter extraction, pipeline state export"
        ),
        produces=["sitemap_urls"],
        timeout=30.0,
    )

    SITEMAP_PATHS = _SITEMAP_PATHS

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        # --- Phase 1: Resolve base URL ---
        base_url = await resolve_base_url(target.host, ctx)
        if not base_url:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info(
                    "Host not reachable — skipping sitemap discovery",
                    tags=["recon", "sitemap"],
                )],
                data={"sitemap_url": "", "urls_count": 0, "urls": []},
            )

        # --- Phase 2: Discover sitemap location ---
        sitemap_body = ""
        found_sitemap = ""

        for path in self.SITEMAP_PATHS:
            if ctx.should_stop:
                break
            url = f"{base_url}{path}"
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(url, timeout=8.0)
                    if resp.status == 200:
                        body = await resp.text(encoding="utf-8", errors="replace")
                        lower = body.lower()
                        if "<url" in lower or "<sitemap" in lower:
                            sitemap_body = body
                            found_sitemap = url
                            break
            except Exception:
                continue

        # Also check robots.txt for sitemap references
        robots_sitemaps: list[str] = []
        if not found_sitemap:
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(
                        f"{base_url}/robots.txt", timeout=5.0,
                    )
                    if resp.status == 200:
                        robots_body = await resp.text(
                            encoding="utf-8", errors="replace",
                        )
                        for line in robots_body.splitlines():
                            if line.strip().lower().startswith("sitemap:"):
                                sm_url = line.split(":", 1)[1].strip()
                                # Rejoin URL that was split on ':'
                                if "://" not in sm_url and " " in line:
                                    sm_url = line.split(" ", 1)[1].strip()
                                if sm_url.startswith("http"):
                                    robots_sitemaps.append(sm_url)
            except Exception:
                pass

            # Try the first robots-referenced sitemap
            for sm_url in robots_sitemaps[:3]:
                if ctx.should_stop:
                    break
                try:
                    async with ctx.rate:
                        resp = await ctx.http.get(sm_url, timeout=8.0)
                        if resp.status == 200:
                            body = await resp.text(
                                encoding="utf-8", errors="replace",
                            )
                            lower = body.lower()
                            if "<url" in lower or "<sitemap" in lower:
                                sitemap_body = body
                                found_sitemap = sm_url
                                break
                except Exception:
                    continue

        if not found_sitemap:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info(
                    "No sitemap found",
                    tags=["recon", "sitemap"],
                )],
                data={"sitemap_url": "", "urls_count": 0, "urls": []},
            )

        # --- Phase 3: Recursive sitemap parsing ---
        all_urls: list[str] = []
        all_lastmods: dict[str, str] = {}  # url -> lastmod string
        visited_sitemaps: set[str] = {found_sitemap}

        self._extract_urls(sitemap_body, all_urls, all_lastmods)

        # Process sitemap indexes recursively
        child_sitemaps = self._extract_child_sitemaps(sitemap_body)
        await self._follow_sitemaps(
            ctx, child_sitemaps, visited_sitemaps,
            all_urls, all_lastmods, depth=1,
        )

        # Deduplicate URLs preserving order
        seen: set[str] = set()
        unique_urls: list[str] = []
        for u in all_urls:
            if u not in seen:
                seen.add(u)
                unique_urls.append(u)
                if len(unique_urls) >= MAX_URLS:
                    break

        # --- Phase 4: Build findings ---
        findings: list[Finding] = []

        findings.append(Finding.info(
            f"Sitemap: {len(unique_urls)} URLs found "
            f"({len(visited_sitemaps)} sitemaps processed)",
            evidence=f"Source: {found_sitemap}",
            tags=["recon", "sitemap"],
        ))

        # Interesting / sensitive URLs
        interesting = [
            u for u in unique_urls if _INTERESTING_RE.search(u)
        ]
        if interesting:
            findings.append(Finding.low(
                f"Sitemap reveals {len(interesting)} potentially sensitive URLs",
                evidence="\n".join(interesting[:10]),
                tags=["recon", "sitemap", "info-disclosure"],
            ))

        # --- Phase 5: lastmod analysis ---
        if all_lastmods:
            stale = self._detect_stale(all_lastmods)
            if stale:
                findings.append(Finding.info(
                    f"Sitemap: oldest content updated {stale['oldest']}",
                    description=(
                        f"Newest update: {stale['newest']}. "
                        f"{stale['stale_count']}/{len(all_lastmods)} URLs "
                        "not updated in over a year."
                    ),
                    tags=["recon", "sitemap", "freshness"],
                ))

        # --- Phase 6: URL classification ---
        classified = self._classify_urls(unique_urls)
        class_summary = ", ".join(
            f"{k}: {len(v)}" for k, v in classified.items() if v
        )
        if class_summary:
            findings.append(Finding.info(
                f"Sitemap URL types: {class_summary}",
                tags=["recon", "sitemap", "classification"],
            ))

        # --- Phase 7: Parameter extraction ---
        params = self._extract_params(unique_urls)
        if params:
            findings.append(Finding.info(
                f"Sitemap: {len(params)} unique query parameters found",
                evidence=", ".join(sorted(params)[:30]),
                tags=["recon", "sitemap", "parameters"],
            ))

        # --- Phase 8: Store in pipeline state ---
        ctx.state.setdefault("sitemap_urls", {})[target.host] = unique_urls
        if params:
            ctx.state.setdefault("sitemap_params", {})[target.host] = sorted(params)

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "sitemap_url": found_sitemap,
                "sitemaps_processed": sorted(visited_sitemaps),
                "urls_count": len(unique_urls),
                "urls": unique_urls[:500],
                "lastmods": dict(list(all_lastmods.items())[:100]),
                "classified": {
                    k: v[:50] for k, v in classified.items()
                },
                "parameters": sorted(params),
            },
        )

    # ------------------------------------------------------------------
    # Sitemap traversal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_urls(
        body: str,
        out_urls: list[str],
        out_lastmods: dict[str, str],
    ) -> None:
        """Extract <loc> URLs and optional <lastmod> from sitemap XML."""
        # Pair each <url> block's loc and lastmod
        url_blocks = re.findall(
            r"<url>\s*(.*?)\s*</url>", body, re.IGNORECASE | re.DOTALL,
        )
        if url_blocks:
            for block in url_blocks:
                loc = _LOC_RE.search(block)
                if not loc:
                    continue
                url_val = loc.group(1)
                out_urls.append(url_val)
                mod = _LASTMOD_RE.search(block)
                if mod:
                    out_lastmods[url_val] = mod.group(1)
        else:
            # Fallback: loose <loc> tags (e.g. in sitemap indexes listing URLs)
            for match in _LOC_RE.findall(body):
                out_urls.append(match)

    @staticmethod
    def _extract_child_sitemaps(body: str) -> list[str]:
        """Extract <sitemap><loc>...</loc></sitemap> entries."""
        children: list[str] = []
        for block in _SITEMAP_TAG_RE.findall(body):
            loc = _LOC_RE.search(block)
            if loc:
                children.append(loc.group(1))
        return children

    async def _follow_sitemaps(
        self,
        ctx,
        sitemap_urls: list[str],
        visited: set[str],
        out_urls: list[str],
        out_lastmods: dict[str, str],
        depth: int,
    ) -> None:
        """Recursively follow sitemap index entries up to MAX_RECURSION_DEPTH."""
        if depth > MAX_RECURSION_DEPTH:
            return

        for sm_url in sitemap_urls:
            if ctx.should_stop or len(out_urls) >= MAX_URLS:
                break
            if sm_url in visited:
                continue
            visited.add(sm_url)

            try:
                async with ctx.rate:
                    resp = await ctx.http.get(sm_url, timeout=8.0)
                    if resp.status != 200:
                        continue
                    body = await resp.text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            lower = body.lower()
            if "<url" not in lower and "<sitemap" not in lower:
                continue

            self._extract_urls(body, out_urls, out_lastmods)

            # Recurse into child sitemaps
            children = self._extract_child_sitemaps(body)
            if children:
                await self._follow_sitemaps(
                    ctx, children, visited, out_urls, out_lastmods,
                    depth=depth + 1,
                )

    # ------------------------------------------------------------------
    # Analysis helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_stale(lastmods: dict[str, str]) -> dict | None:
        """Analyze lastmod dates for freshness."""
        dates: list[datetime] = []
        now = datetime.now(UTC)

        for datestr in lastmods.values():
            try:
                # Try ISO 8601 (YYYY-MM-DD or full datetime)
                cleaned = datestr.strip()[:25]
                if "T" in cleaned:
                    dt = datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
                else:
                    dt = datetime.strptime(cleaned[:10], "%Y-%m-%d").replace(
                        tzinfo=UTC,
                    )
                dates.append(dt)
            except (ValueError, IndexError):
                continue

        if not dates:
            return None

        oldest = min(dates)
        newest = max(dates)
        stale_count = sum(1 for d in dates if (now - d).days > 365)

        return {
            "oldest": oldest.strftime("%Y-%m-%d"),
            "newest": newest.strftime("%Y-%m-%d"),
            "stale_count": stale_count,
        }

    @staticmethod
    def _classify_urls(urls: list[str]) -> dict[str, list[str]]:
        """Classify URLs into categories."""
        classified: dict[str, list[str]] = {
            "pages": [],
            "api": [],
            "images": [],
            "files": [],
            "other": [],
        }

        for url in urls:
            parsed = urlparse(url)
            path_lower = parsed.path.lower()

            if "/api/" in path_lower or "/v1/" in path_lower or "/v2/" in path_lower:
                classified["api"].append(url)
            elif any(path_lower.endswith(ext) for ext in _IMAGE_EXTS):
                classified["images"].append(url)
            elif any(path_lower.endswith(ext) for ext in _FILE_EXTS):
                classified["files"].append(url)
            elif (
                path_lower.endswith((".html", ".htm", ".php", ".asp", ".aspx", "/"))
                or "." not in path_lower.rsplit("/", 1)[-1]
            ):
                classified["pages"].append(url)
            else:
                classified["other"].append(url)

        return classified

    @staticmethod
    def _extract_params(urls: list[str]) -> set[str]:
        """Extract unique query parameter names from URLs."""
        params: set[str] = set()
        for url in urls:
            parsed = urlparse(url)
            if parsed.query:
                qs = parse_qs(parsed.query, keep_blank_values=True)
                params.update(qs.keys())
        return params
