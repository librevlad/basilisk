"""GitHub dorking — searches GitHub for leaked credentials and code references."""

from __future__ import annotations

import json
import os
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

# Search dorks: (query_suffix, description, severity)
DORKS: list[tuple[str, str, str]] = [
    ("password", "Hardcoded password", "critical"),
    ("secret", "Secret/token value", "critical"),
    ("api_key", "API key leak", "critical"),
    ("apikey", "API key leak", "critical"),
    ("private_key", "Private key leak", "critical"),
    ("aws_access_key", "AWS access key", "critical"),
    ("Authorization: Bearer", "Bearer token", "critical"),
    ("jdbc:", "JDBC connection string", "high"),
    ("mongodb://", "MongoDB connection string", "high"),
    ("postgres://", "PostgreSQL connection string", "high"),
    ("mysql://", "MySQL connection string", "high"),
    ("redis://", "Redis connection string", "high"),
    (".env", "Environment config", "high"),
    ("config", "Configuration file", "medium"),
    ("internal", "Internal reference", "low"),
]


class GithubDorkingPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="github_dorking",
        display_name="GitHub Code Leak Detection",
        category=PluginCategory.RECON,
        description="Searches GitHub for leaked credentials and code referencing the domain",
        produces=["github_leaks"],
        timeout=30.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        github_token = (
            ctx.state.get("GITHUB_TOKEN", "")
            or os.environ.get("GITHUB_TOKEN", "")
        )
        if not github_token:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info(
                    "GitHub token not configured (set github_token in config)",
                    tags=["recon", "github"],
                )],
                data={},
            )

        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        domain = target.host
        findings: list[Finding] = []
        leaks: list[dict] = []

        for dork_suffix, desc, severity in DORKS:
            if ctx.should_stop:
                break

            query = f"{domain} {dork_suffix}"
            results = await self._search_github(
                ctx, query, github_token,
            )

            for item in results:
                repo = item.get("repository", {}).get("full_name", "unknown")
                path = item.get("path", "")
                html_url = item.get("html_url", "")

                # Extract matched text snippets
                matches = []
                for match in item.get("text_matches", []):
                    fragment = match.get("fragment", "")
                    if fragment:
                        matches.append(fragment[:150])

                leak = {
                    "repo": repo,
                    "path": path,
                    "url": html_url,
                    "dork": dork_suffix,
                    "description": desc,
                    "severity": severity,
                    "snippets": matches[:3],
                }
                leaks.append(leak)

                finding_fn = {
                    "critical": Finding.critical,
                    "high": Finding.high,
                    "medium": Finding.medium,
                    "low": Finding.low,
                }.get(severity, Finding.info)

                findings.append(finding_fn(
                    f"GitHub leak: {desc} in {repo}",
                    description=f"File: {path}",
                    evidence=matches[0][:200] if matches else html_url,
                    remediation=(
                        "Rotate exposed credentials. Remove sensitive data from "
                        "public repositories. Use .gitignore and secret scanning."
                    ),
                    tags=["recon", "github", "leak"],
                ))

            # Rate limit: 10 searches/min for code search
            if not ctx.should_stop:
                await self._sleep_rate_limit()

        if not findings:
            findings.append(Finding.info(
                f"No GitHub code leaks found for {domain}",
                tags=["recon", "github"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "github_leaks": leaks,
                "dorks_tested": len(DORKS),
            },
        )

    @staticmethod
    async def _search_github(
        ctx, query: str, token: str,
    ) -> list[dict]:
        """Search GitHub Code API."""
        import asyncio
        from urllib.parse import quote

        url = f"https://api.github.com/search/code?q={quote(query)}&per_page=5"
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3.text-match+json",
        }

        try:
            async with ctx.rate:
                resp = await ctx.http.get(url, headers=headers, timeout=10.0)
                if resp.status == 403:
                    # Rate limited
                    await asyncio.sleep(5)
                    return []
                if resp.status != 200:
                    return []

                body = await resp.text(encoding="utf-8", errors="replace")
                data = json.loads(body)
                return data.get("items", [])
        except Exception:
            return []

    @staticmethod
    async def _sleep_rate_limit() -> None:
        """Sleep to respect GitHub code search rate limit (10/min)."""
        import asyncio
        await asyncio.sleep(6)
