"""HTML & JS comment finder — discovers developer comments, debug info, credentials.

Checks multiple pages, extracts HTML and JavaScript comments (inline + external),
classifies sensitive patterns by category and severity, deduplicates similar comments.
"""

from __future__ import annotations

import re
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target
from basilisk.utils.http_check import resolve_base_url

# ---------------------------------------------------------------------------
# Sensitive pattern categories with severity
# ---------------------------------------------------------------------------
_CREDENTIAL_RE = re.compile(
    r"(?i)(password|passwd|pwd\b|secret|token|api[_-]?key|apikey|"
    r"access[_-]?key|private[_-]?key|auth[_-]?token|credentials|"
    r"client[_-]?secret|bearer\s)",
)
_TODO_DEBUG_RE = re.compile(
    r"(?i)\b(TODO|FIXME|HACK|BUG|XXX|DEBUG|TEMP|REMOVE)\b",
)
_INTERNAL_IP_RE = re.compile(
    r"(?:^|\D)(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|"
    r"127\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\D|$)",
)
_INTERNAL_URL_RE = re.compile(
    r"(?i)(https?://[^\s\"'<>]*(?:intranet|internal|staging|dev|localhost)"
    r"[^\s\"'<>]*)",
)
_SQL_RE = re.compile(
    r"(?i)\b(SELECT\s.+?\sFROM|INSERT\s+INTO|UPDATE\s+\S+\s+SET|"
    r"DELETE\s+FROM|CREATE\s+TABLE|ALTER\s+TABLE|DROP\s+TABLE)",
)
_CONN_STRING_RE = re.compile(
    r"(?i)((?:mysql|postgres|mongodb|redis|amqp|mssql|sqlite|jdbc)"
    r"://[^\s\"'<>]+)",
)
_SERVER_PATH_RE = re.compile(
    r"(/var/www/\S+|/home/\S+|/opt/\S+|/etc/\S+|"
    r"[A-Z]:\\\\[^\s\"'<>]+)",
)
_EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
)

# Comment extraction patterns
_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_JS_SINGLE_RE = re.compile(r"(?<![:\\])//(?!/)\s*(.+)")
_JS_MULTI_RE = re.compile(r"/\*(.+?)\*/", re.DOTALL)
_SCRIPT_BLOCK_RE = re.compile(
    r"<script[^>]*>(.*?)</script>", re.DOTALL | re.IGNORECASE,
)
_EXTERNAL_JS_RE = re.compile(
    r'<script[^>]+src\s*=\s*["\']([^"\']+\.js)["\']',
    re.IGNORECASE,
)

# Default pages to check
_DEFAULT_PATHS = ["/", "/login", "/about", "/contact", "/admin"]

# Category → (pattern, severity, category_name)
_PATTERN_CHECKS: list[tuple[re.Pattern, str, str]] = [
    (_CREDENTIAL_RE, "high", "credentials"),
    (_CONN_STRING_RE, "high", "connection_string"),
    (_SQL_RE, "high", "sql_query"),
    (_INTERNAL_IP_RE, "medium", "internal_ip"),
    (_INTERNAL_URL_RE, "medium", "internal_url"),
    (_TODO_DEBUG_RE, "medium", "debug_marker"),
    (_SERVER_PATH_RE, "medium", "server_path"),
    (_EMAIL_RE, "low", "developer_info"),
]


def _classify_comment(text: str) -> tuple[str, str] | None:
    """Return (severity, category) for a sensitive comment, or None."""
    for pattern, severity, category in _PATTERN_CHECKS:
        if pattern.search(text):
            return severity, category
    return None


def _dedup_key(text: str) -> str:
    """Deduplication key: normalized first 50 chars."""
    return " ".join(text.split())[:50].lower()


class CommentFinderPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="comment_finder",
        display_name="HTML & JS Comment Finder",
        category=PluginCategory.ANALYSIS,
        description=(
            "Finds HTML/JS comments that may reveal sensitive information: "
            "credentials, TODOs, internal IPs, SQL queries, server paths"
        ),
        produces=["html_comments"],
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
                data={"total_comments": 0, "sensitive_comments": [],
                      "pages_checked": 0},
            )

        findings: list[Finding] = []
        all_comments: list[dict] = []
        sensitive_comments: list[dict] = []
        seen_keys: set[str] = set()
        pages_checked = 0

        # Collect pages to check
        paths = list(_DEFAULT_PATHS)
        admin_paths = ctx.state.get("admin_paths", [])
        for ap in admin_paths:
            p = ap.get("path", "") if isinstance(ap, dict) else str(ap)
            if p and p not in paths:
                paths.append(p)
        crawled = ctx.state.get("crawled_urls", [])
        for curl in crawled:
            if isinstance(curl, str) and curl.startswith(base_url):
                path = curl[len(base_url):]
                if path and path not in paths:
                    paths.append(path)

        # Limit pages to avoid timeout
        paths = paths[:20]

        for path in paths:
            if ctx.should_stop:
                break
            url = f"{base_url}{path}"
            body = await self._fetch_page(url, ctx)
            if body is None:
                continue
            pages_checked += 1

            # Extract HTML comments
            for match in _HTML_COMMENT_RE.findall(body):
                self._process_comment(
                    match, path, "html", all_comments,
                    sensitive_comments, seen_keys,
                )

            # Extract JS comments from inline scripts
            for script_body in _SCRIPT_BLOCK_RE.findall(body):
                self._extract_js_comments(
                    script_body, path, all_comments,
                    sensitive_comments, seen_keys,
                )

            # Fetch and scan external JS files
            for js_src in _EXTERNAL_JS_RE.findall(body):
                if ctx.should_stop:
                    break
                js_url = self._resolve_js_url(js_src, base_url)
                if not js_url:
                    continue
                js_body = await self._fetch_page(js_url, ctx)
                if js_body:
                    js_path = js_src if js_src.startswith("/") else f"[ext]{js_src}"
                    self._extract_js_comments(
                        js_body, js_path, all_comments,
                        sensitive_comments, seen_keys,
                    )

        # Generate findings by severity
        high_comments = [c for c in sensitive_comments if c["severity"] == "high"]
        medium_comments = [
            c for c in sensitive_comments if c["severity"] == "medium"
        ]
        low_comments = [c for c in sensitive_comments if c["severity"] == "low"]

        if high_comments:
            evidence = "\n---\n".join(
                f"[{c['page']}] ({c['category']}): {c['text']}"
                for c in high_comments[:5]
            )
            findings.append(Finding.high(
                f"Comments with credentials/secrets ({len(high_comments)})",
                description=(
                    "HTML/JS comments contain potential credentials, "
                    "connection strings, or SQL queries"
                ),
                evidence=evidence,
                remediation=(
                    "Remove all sensitive comments from production code. "
                    "Use environment variables for secrets."
                ),
                tags=["analysis", "comments", "credentials"],
            ))

        if medium_comments:
            evidence = "\n---\n".join(
                f"[{c['page']}] ({c['category']}): {c['text']}"
                for c in medium_comments[:5]
            )
            findings.append(Finding.medium(
                f"Comments with internal info ({len(medium_comments)})",
                description=(
                    "Comments reveal internal IPs, URLs, debug markers, "
                    "or server paths"
                ),
                evidence=evidence,
                remediation="Remove internal infrastructure details from comments",
                tags=["analysis", "comments", "info-disclosure"],
            ))

        if low_comments:
            evidence = "\n---\n".join(
                f"[{c['page']}] ({c['category']}): {c['text']}"
                for c in low_comments[:5]
            )
            findings.append(Finding.low(
                f"Comments with developer info ({len(low_comments)})",
                description="Comments contain email addresses or developer names",
                evidence=evidence,
                remediation="Remove developer-specific comments from production",
                tags=["analysis", "comments", "developer-info"],
            ))

        total = len(all_comments)
        if not sensitive_comments and total > 0:
            findings.append(Finding.info(
                f"Found {total} comments (none sensitive) on {pages_checked} pages",
                tags=["analysis", "comments"],
            ))
        elif total == 0:
            findings.append(Finding.info(
                f"No comments found across {pages_checked} pages",
                tags=["analysis", "comments"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "total_comments": total,
                "sensitive_comments": sensitive_comments[:50],
                "pages_checked": pages_checked,
            },
        )

    def _process_comment(
        self,
        text: str,
        page: str,
        comment_type: str,
        all_comments: list[dict],
        sensitive_comments: list[dict],
        seen_keys: set[str],
    ) -> None:
        """Classify a comment and add to the appropriate list."""
        text = text.strip()
        if not text or len(text) < 5:
            return

        key = _dedup_key(text)
        if key in seen_keys:
            return
        seen_keys.add(key)

        truncated = text[:300]
        all_comments.append({
            "text": truncated, "page": page, "type": comment_type,
        })

        result = _classify_comment(text)
        if result:
            severity, category = result
            sensitive_comments.append({
                "text": truncated,
                "page": page,
                "type": comment_type,
                "category": category,
                "severity": severity,
            })

    def _extract_js_comments(
        self,
        js_body: str,
        page: str,
        all_comments: list[dict],
        sensitive_comments: list[dict],
        seen_keys: set[str],
    ) -> None:
        """Extract single-line and multi-line JS comments."""
        for match in _JS_MULTI_RE.findall(js_body):
            self._process_comment(
                match, page, "js_multi", all_comments,
                sensitive_comments, seen_keys,
            )
        for match in _JS_SINGLE_RE.findall(js_body):
            self._process_comment(
                match, page, "js_single", all_comments,
                sensitive_comments, seen_keys,
            )

    @staticmethod
    def _resolve_js_url(src: str, base_url: str) -> str | None:
        """Resolve a JS src attribute to an absolute URL."""
        if src.startswith("//"):
            return f"https:{src}"
        if src.startswith("http://") or src.startswith("https://"):
            return src
        if src.startswith("/"):
            return f"{base_url}{src}"
        return f"{base_url}/{src}"

    @staticmethod
    async def _fetch_page(url: str, ctx) -> str | None:
        """Fetch a page, return body text or None on error."""
        try:
            async with ctx.rate:
                resp = await ctx.http.get(url, timeout=8.0)
                if resp.status != 200:
                    return None
                return await resp.text(encoding="utf-8", errors="replace")
        except Exception:
            return None
