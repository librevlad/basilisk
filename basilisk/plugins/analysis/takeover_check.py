"""Subdomain takeover detection plugin."""

from __future__ import annotations

import re
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

# Fingerprints indicating potential subdomain takeover
TAKEOVER_FINGERPRINTS: list[tuple[str, str]] = [
    ("GitHub Pages", r"There isn't a GitHub Pages site here"),
    ("Heroku", r"No such app|herokucdn\.com/error-pages"),
    ("Amazon S3", r"NoSuchBucket|The specified bucket does not exist"),
    ("Amazon CloudFront", r"The request could not be satisfied.*CloudFront"),
    ("Shopify", r"Sorry, this shop is currently unavailable"),
    ("Tumblr", r"There's nothing here|Whatever you were looking for doesn't"),
    ("WordPress.com", r"Do you want to register"),
    ("Zendesk", r"Help Center Closed"),
    ("Fastly", r"Fastly error: unknown domain"),
    ("Pantheon", r"404 error unknown site"),
    ("Surge.sh", r"project not found"),
    ("Bitbucket", r"Repository not found"),
    ("Ghost", r"The thing you were looking for is no longer here"),
    ("Readme.io", r"Project doesnt exist"),
    ("HatenaBlog", r"404 Blog is not found"),
    ("Cargo Collective", r"<title>404 &mdash; Cargo"),
    ("Netlify", r"Not Found - Request ID:"),
    ("Fly.io", r"404 Not Found.*Fly\.io"),
    ("Vercel", r"The deployment could not be found"),
    ("Webflow", r"The page you are looking for doesn't exist.*webflow"),
    ("Discourse", r"you've found a page that doesn't exist"),
    ("Freshdesk", r"There is no helpdesk here"),
    ("Azure Traffic Manager", r"Web App - Pair Not Found"),
    ("Unbounce", r"The requested URL was not found on this server"),
    ("Statuspage", r"You are being redirected|statuspage\.io"),
    ("Strikingly", r"page not found.*strikingly"),
    ("UserVoice", r"This UserVoice subdomain is currently available"),
    ("LaunchRock", r"It looks like you may have taken a wrong turn"),
    ("Kinsta", r"No site with that domain"),
    ("Agile CRM", r"Sorry, this page is no longer available"),
    ("Canny", r"Company Not Found"),
    ("ReadTheDocs", r"unknown to Read the Docs"),
    ("Render", r"not found.*onrender"),
    ("Gemfury", r"404: This page could not be found"),
    ("Thinkific", r"You may have mistyped the address"),
]


class TakeoverCheckPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="takeover_check",
        display_name="Subdomain Takeover Check",
        category=PluginCategory.ANALYSIS,
        description="Detects potential subdomain takeover vulnerabilities",
        produces=["takeover_findings"],
        timeout=15.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        findings: list[Finding] = []
        body = ""

        for scheme in ("https", "http"):
            url = f"{scheme}://{target.host}"
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(url, timeout=10.0)
                    body = await resp.text(encoding="utf-8", errors="replace")
                    break
            except Exception:
                continue

        if not body:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info("Could not fetch page for takeover check")],
                data={"takeover_vulnerable": False},
            )

        for service, pattern in TAKEOVER_FINGERPRINTS:
            if re.search(pattern, body, re.IGNORECASE):
                findings.append(Finding.high(
                    f"Potential subdomain takeover ({service})",
                    description=(
                        f"Response matches {service} takeover fingerprint. "
                        f"The subdomain {target.host} may be claimable."
                    ),
                    evidence=body[:300],
                    remediation=(
                        f"Remove the DNS record pointing to {service}, "
                        "or reclaim the resource on the platform."
                    ),
                    tags=["analysis", "takeover", service.lower()],
                ))
                break  # One match is enough

        if not findings:
            findings.append(Finding.info(
                "No takeover fingerprints matched",
                tags=["analysis", "takeover"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"takeover_vulnerable": any(
                f.severity.label != "INFO" for f in findings
            )},
        )
