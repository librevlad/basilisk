"""Email harvesting plugin — multi-source email enumeration.

Sources: PGP keyservers, GitHub API, web scraping.
"""

from __future__ import annotations

import re
from typing import ClassVar
from urllib.parse import quote

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")


class EmailHarvestPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="email_harvest",
        display_name="Email Harvester",
        category=PluginCategory.RECON,
        description=(
            "Multi-source email enumeration: PGP keyservers, GitHub, "
            "web scraping, and search engine dorking."
        ),
        produces=["emails"],
        timeout=60.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available",
            )

        domain = target.host
        findings: list[Finding] = []
        all_emails: set[str] = set()

        # Source 1: PGP Keyserver (keys.openpgp.org)
        if not ctx.should_stop:
            pgp_emails = await self._search_pgp(ctx, domain)
            all_emails.update(pgp_emails)

        # Source 2: GitHub search
        if not ctx.should_stop:
            gh_emails = await self._search_github(ctx, domain)
            all_emails.update(gh_emails)

        # Source 3: Target website scraping
        if not ctx.should_stop:
            web_emails = await self._scrape_website(ctx, domain)
            all_emails.update(web_emails)

        # Filter to domain-specific emails
        domain_emails = sorted(e for e in all_emails if domain.lower() in e.lower())
        other_emails = sorted(e for e in all_emails if domain.lower() not in e.lower())

        if domain_emails:
            findings.append(Finding.info(
                f"Found {len(domain_emails)} domain emails",
                evidence=", ".join(domain_emails[:20]),
                tags=["recon", "email"],
            ))

        if other_emails:
            findings.append(Finding.info(
                f"Found {len(other_emails)} associated emails",
                evidence=", ".join(other_emails[:10]),
                tags=["recon", "email"],
            ))

        if not findings:
            findings.append(Finding.info(
                "No emails discovered",
                tags=["recon", "email"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "domain_emails": domain_emails,
                "other_emails": other_emails[:20],
                "total": len(all_emails),
            },
        )

    async def _search_pgp(self, ctx, domain: str) -> set[str]:
        """Search PGP keyservers for domain emails."""
        emails: set[str] = set()
        url = f"https://keys.openpgp.org/vks/v1/by-email/@{domain}"
        try:
            async with ctx.rate:
                resp = await ctx.http.get(url, timeout=10.0)
                if resp.status == 200:
                    body = await resp.text(encoding="utf-8", errors="replace")
                    emails.update(_EMAIL_RE.findall(body))
        except Exception:
            pass

        # Also try keys.gnupg.net
        url2 = (
            f"https://keys.gnupg.net/pks/lookup?search=%40{domain}"
            f"&op=index&options=mr"
        )
        try:
            async with ctx.rate:
                resp = await ctx.http.get(url2, timeout=10.0)
                if resp.status == 200:
                    body = await resp.text(encoding="utf-8", errors="replace")
                    emails.update(_EMAIL_RE.findall(body))
        except Exception:
            pass

        return emails

    async def _search_github(self, ctx, domain: str) -> set[str]:
        """Search GitHub for domain-associated emails."""
        emails: set[str] = set()
        url = (
            f"https://api.github.com/search/users"
            f"?q={quote(domain)}+in:email&per_page=30"
        )
        try:
            async with ctx.rate:
                resp = await ctx.http.get(
                    url, timeout=10.0,
                    headers={"Accept": "application/vnd.github.v3+json"},
                )
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    for user in data.get("items", []):
                        email = user.get("email")
                        if email:
                            emails.add(email)
        except Exception:
            pass
        return emails

    async def _scrape_website(self, ctx, domain: str) -> set[str]:
        """Scrape target website pages for email addresses."""
        from basilisk.utils.http_check import resolve_base_url

        emails: set[str] = set()
        base_url = await resolve_base_url(domain, ctx)
        if not base_url:
            return emails

        paths = [
            "/", "/contact", "/about", "/team", "/support",
            "/privacy", "/impressum", "/legal",
        ]
        for path in paths:
            if ctx.should_stop:
                break
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(
                        f"{base_url}{path}", timeout=8.0,
                    )
                    if resp.status == 200:
                        body = await resp.text(encoding="utf-8", errors="replace")
                        found = _EMAIL_RE.findall(body)
                        # Filter out common false positives
                        for email in found:
                            if not email.endswith((".png", ".jpg", ".gif", ".css", ".js")):
                                emails.add(email.lower())
            except Exception:
                continue
        return emails
