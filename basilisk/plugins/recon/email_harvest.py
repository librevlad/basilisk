"""Email harvesting from web pages and public sources."""

from __future__ import annotations

import re
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class EmailHarvestPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="email_harvest",
        display_name="Email Harvester",
        category=PluginCategory.RECON,
        description="Discovers email addresses from web pages and public sources",
        produces=["emails"],
        timeout=20.0,
    )

    EMAIL_RE = re.compile(
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    )

    # File-like extensions to exclude from email results
    _EXCLUDE_EXT = (
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".js",
        ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map",
    )

    _PAGES = [
        "/", "/contact", "/contacts", "/about", "/team",
        "/impressum", "/privacy", "/legal", "/staff",
        "/about-us", "/support", "/help",
    ]

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available",
            )

        from basilisk.utils.http_check import resolve_base_url

        emails: set[str] = set()

        base_url = await resolve_base_url(target.host, ctx)
        if not base_url:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info("Host not reachable")],
                data={"domain_emails": [], "other_emails": []},
            )

        # Scrape pages for emails
        for page in self._PAGES:
            if ctx.should_stop:
                break
            url = f"{base_url}{page}"
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(url, timeout=8.0)
                    if resp.status == 200:
                        body = await resp.text(
                            encoding="utf-8", errors="replace",
                        )
                        found = self.EMAIL_RE.findall(body)
                        for email in found:
                            email = email.lower()
                            if not email.endswith(self._EXCLUDE_EXT):
                                emails.add(email)
            except Exception:
                continue

        domain_emails = {e for e in emails if e.endswith(f"@{target.host}")}
        other_emails = emails - domain_emails

        findings: list[Finding] = []
        if domain_emails:
            findings.append(Finding.info(
                f"Found {len(domain_emails)} emails for {target.host}",
                evidence=", ".join(sorted(domain_emails)[:15]),
                tags=["recon", "email"],
            ))
        if other_emails:
            findings.append(Finding.info(
                f"Found {len(other_emails)} external emails",
                evidence=", ".join(sorted(other_emails)[:10]),
                tags=["recon", "email"],
            ))
        if not findings:
            findings.append(Finding.info(
                "No email addresses found",
                tags=["recon", "email"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "domain_emails": sorted(domain_emails),
                "other_emails": sorted(other_emails),
            },
        )
