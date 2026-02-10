"""HTML comment finder — discovers developer comments and debug info."""

from __future__ import annotations

import re
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

SENSITIVE_PATTERNS = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|credentials|"
    r"todo|fixme|hack|bug|debug|admin|internal|private|"
    r"sql|query|database|db_|config|root|ssh|ftp|"
    r"@[a-zA-Z0-9._%+-]+\.[a-zA-Z]{2,})",
)


class CommentFinderPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="comment_finder",
        display_name="HTML Comment Finder",
        category=PluginCategory.ANALYSIS,
        description="Finds HTML comments that may reveal sensitive information",
        produces=["html_comments"],
        timeout=10.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        findings: list[Finding] = []
        comments: list[str] = []
        sensitive: list[str] = []

        for scheme in ("https", "http"):
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(
                        f"{scheme}://{target.host}/", timeout=8.0,
                    )
                    body = await resp.text(encoding="utf-8", errors="replace")
                    comments = re.findall(r'<!--(.*?)-->', body, re.DOTALL)
                    break
            except Exception:
                continue

        for comment in comments:
            comment = comment.strip()
            if not comment or len(comment) < 5:
                continue
            if SENSITIVE_PATTERNS.search(comment):
                sensitive.append(comment[:200])

        if sensitive:
            findings.append(Finding.low(
                f"HTML comments with sensitive content ({len(sensitive)})",
                description="HTML comments may reveal internal info, TODOs, or credentials",
                evidence="\n---\n".join(sensitive[:5]),
                remediation="Remove sensitive comments from production HTML",
                tags=["analysis", "comments", "info-disclosure"],
            ))

        if comments and not sensitive:
            findings.append(Finding.info(
                f"Found {len(comments)} HTML comments (none sensitive)",
                tags=["analysis", "comments"],
            ))
        elif not comments:
            findings.append(Finding.info(
                "No HTML comments found",
                tags=["analysis", "comments"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "total_comments": len(comments),
                "sensitive_comments": sensitive,
            },
        )
