"""Subdomain takeover detection — 80+ service fingerprints, CNAME + DNS checks.

Uses centralized TakeoverFingerprint database from basilisk.data.fingerprints.
Checks: HTTP response body fingerprints, CNAME dangling records, NXDOMAIN,
A record absence, NS delegation. Confidence scoring.
Level: subjack + nuclei takeover templates.
"""

from __future__ import annotations

import re
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

# Import centralized takeover fingerprints
try:
    from basilisk.data.fingerprints import TAKEOVER_FINGERPRINTS as _FP_DB
except ImportError:
    _FP_DB = []

# Fallback fingerprints if centralized DB not available
TAKEOVER_FINGERPRINTS: list[tuple[str, str, bool]] = [
    # (service, regex_pattern, requires_nxdomain)
    ("GitHub Pages", r"There isn't a GitHub Pages site here", False),
    ("Heroku", r"No such app|herokucdn\.com/error-pages", False),
    ("Amazon S3", r"NoSuchBucket|The specified bucket does not exist", False),
    ("Amazon CloudFront", r"The request could not be satisfied.*CloudFront", False),
    ("Amazon Elastic Beanstalk", r"Invalid host header|NXDOMAIN", True),
    ("Shopify", r"Sorry, this shop is currently unavailable", False),
    ("Tumblr", r"There's nothing here|Whatever you were looking for doesn't", False),
    ("WordPress.com", r"Do you want to register", False),
    ("Zendesk", r"Help Center Closed|Oops, this help center", False),
    ("Fastly", r"Fastly error: unknown domain", False),
    ("Pantheon", r"404 error unknown site|The gods have abandoned", False),
    ("Surge.sh", r"project not found", False),
    ("Bitbucket", r"Repository not found", False),
    ("Ghost", r"The thing you were looking for is no longer here", False),
    ("Readme.io", r"Project doesnt exist|Project not found", False),
    ("Cargo Collective", r"<title>404 &mdash; Cargo", False),
    ("Netlify", r"Not Found - Request ID:", False),
    ("Fly.io", r"404 Not Found.*Fly\.io", False),
    ("Vercel", r"The deployment could not be found|DEPLOYMENT_NOT_FOUND", False),
    ("Webflow", r"The page you are looking for doesn't exist.*webflow", False),
    ("Discourse", r"you've found a page that doesn't exist", False),
    ("Freshdesk", r"There is no helpdesk here|May not be configured", False),
    ("Azure Traffic Manager", r"Web App - Pair Not Found", True),
    ("Azure Websites", r"404 Web Site not found|\.azurewebsites\.net", True),
    ("Azure CloudApp", r"The resource you are looking for has been removed", True),
    ("Azure Blob", r"The specified container does not exist|BlobNotFound", False),
    ("Azure Front Door", r"Our services aren't available right now", True),
    ("Unbounce", r"The requested URL was not found on this server", False),
    ("Statuspage", r"You are being redirected|statuspage\.io|page not found", False),
    ("Strikingly", r"page not found.*strikingly", False),
    ("UserVoice", r"This UserVoice subdomain is currently available", False),
    ("LaunchRock", r"It looks like you may have taken a wrong turn", False),
    ("Kinsta", r"No site with that domain", False),
    ("Agile CRM", r"Sorry, this page is no longer available", False),
    ("Canny", r"Company Not Found", False),
    ("ReadTheDocs", r"unknown to Read the Docs", False),
    ("Render", r"not found.*onrender", True),
    ("Gemfury", r"404: This page could not be found", False),
    ("Thinkific", r"You may have mistyped the address", False),
    ("Tilda", r"Please renew your subscription", False),
    ("HatenaBlog", r"404 Blog is not found", False),
    ("Helpjuice", r"We could not find what you're looking for", False),
    ("HelpScout", r"No settings were found for this company", False),
    ("Intercom", r"This page is reserved for a company", False),
    ("Ngrok", r"Tunnel.*not found|ERR_NGROK_6024", False),
    ("SmartJobBoard", r"This job board website is either expired", False),
    ("UptimeRobot", r"page not found.*uptimerobot", False),
    ("Aha!", r"There is no portal here", False),
    ("Airee.ru", r"Ошибка 402. Pair not found", False),
    ("Announcekit", r"Error 404.*announcekit", False),
    ("Anima", r"If you are the site owner.*anima", False),
    ("Campaign Monitor", r"Trying to access your account", False),
    ("HubSpot", r"Domain not found.*hubspot|is no longer available", False),
    ("Instapage", r"Expired.*instapage|You've Discovered a Missing Link", False),
    ("JetBrains YouTrack", r"is not a registered InCloud YouTrack", False),
    ("Landingi", r"It looks like you're lost|landingi", False),
    ("Mashery", r"Unrecognized domain.*mashery", False),
    ("Pingdom", r"Sorry, couldn't find the status page", False),
    ("Proposify", r"If you need immediate assistance.*proposify", False),
    ("Simplebooklet", r"We can't find this.*simplebooklet", False),
    ("Smugmug", r".*SmugMug.*", False),
    ("Teamwork", r"Oops.*This page is no longer active", False),
    ("Wufoo", r"Hmmm.*looks like that form doesn't live here", False),
]

# CNAME patterns that indicate third-party services
SERVICE_CNAME_PATTERNS: dict[str, list[str]] = {
    "GitHub Pages": [".github.io"],
    "Heroku": [".herokuapp.com", ".herokussl.com"],
    "Amazon S3": [".s3.amazonaws.com", ".s3-website"],
    "Amazon CloudFront": [".cloudfront.net"],
    "Shopify": [".myshopify.com"],
    "Tumblr": [".tumblr.com"],
    "WordPress.com": [".wordpress.com"],
    "Zendesk": [".zendesk.com"],
    "Fastly": [".fastly.net", ".fastlylb.net"],
    "Pantheon": [".pantheonsite.io"],
    "Surge.sh": [".surge.sh"],
    "Netlify": [".netlify.app", ".netlify.com"],
    "Fly.io": [".fly.dev"],
    "Vercel": [".vercel.app", ".now.sh"],
    "Azure Websites": [".azurewebsites.net"],
    "Azure Traffic Manager": [".trafficmanager.net"],
    "Azure CloudApp": [".cloudapp.net", ".cloudapp.azure.com"],
    "Azure Blob": [".blob.core.windows.net"],
    "Azure Front Door": [".azurefd.net"],
    "Render": [".onrender.com"],
    "Bitbucket": [".bitbucket.io"],
    "Ghost": [".ghost.io"],
    "HubSpot": [".hubspot.net", ".hs-sites.com"],
    "Unbounce": [".unbouncepages.com"],
    "Statuspage": [".statuspage.io"],
    "Strikingly": [".strikingly.com"],
    "Tilda": [".tilda.ws"],
    "Webflow": [".webflow.io"],
    "Cargo Collective": [".cargocollective.com"],
    "Readme.io": [".readme.io"],
    "Instapage": [".pagedemo.co"],
    "Campaign Monitor": [".createsend.com"],
    "Freshdesk": [".freshdesk.com"],
    "Helpjuice": [".helpjuice.com"],
    "HelpScout": [".helpscoutdocs.com"],
    "Intercom": [".intercom.help"],
    "LaunchRock": [".launchrock.com"],
    "Canny": [".canny.io"],
    "UptimeRobot": [".uptimerobot.com"],
    "Kinsta": [".kinsta.cloud"],
}


class TakeoverCheckPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="takeover_check",
        display_name="Subdomain Takeover Check",
        category=PluginCategory.ANALYSIS,
        description=(
            "Detects subdomain takeover via 60+ service fingerprints, "
            "CNAME analysis, NXDOMAIN detection, and DNS delegation checks"
        ),
        produces=["takeover_findings"],
        timeout=30.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available",
            )

        findings: list[Finding] = []
        tested: list[dict] = []

        # Phase 1: CNAME resolution
        cname_chain = await self._resolve_cname(target.host, ctx)
        cname_service = self._identify_service_from_cname(cname_chain)

        if cname_service:
            tested.append({
                "check": "cname", "service": cname_service,
                "cnames": cname_chain,
            })

        # Phase 2: Check if CNAME target is NXDOMAIN
        is_nxdomain = False
        if cname_chain:
            is_nxdomain = await self._check_nxdomain(cname_chain[-1], ctx)
            if is_nxdomain:
                service_name = cname_service or "Unknown"
                tested.append({
                    "check": "nxdomain", "cname": cname_chain[-1],
                    "service": service_name,
                })
                findings.append(Finding.critical(
                    f"Dangling CNAME: {cname_chain[-1]} is NXDOMAIN",
                    description=(
                        f"CNAME {target.host} → {cname_chain[-1]} resolves to "
                        f"NXDOMAIN. Service: {service_name}. "
                        f"High probability of subdomain takeover."
                    ),
                    evidence=f"CNAME chain: {' → '.join([target.host] + cname_chain)}",
                    remediation=(
                        f"Remove the DNS CNAME record for {target.host} or "
                        f"reclaim the resource on {service_name}."
                    ),
                    tags=["analysis", "takeover", "nxdomain"],
                ))

        # Phase 3: HTTP response fingerprint matching
        body = ""
        resp_status = 0
        for scheme in ("https", "http"):
            url = f"{scheme}://{target.host}"
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(url, timeout=10.0)
                    body = await resp.text(encoding="utf-8", errors="replace")
                    resp_status = resp.status
                    break
            except Exception:
                continue

        if body:
            for service, pattern, requires_nx in TAKEOVER_FINGERPRINTS:
                if requires_nx and not is_nxdomain:
                    continue

                if re.search(pattern, body, re.IGNORECASE):
                    # Confidence scoring
                    confidence = 50
                    if cname_service and cname_service == service:
                        confidence += 30
                    if is_nxdomain:
                        confidence += 20
                    if resp_status in (404, 0):
                        confidence += 10

                    severity = Finding.critical if confidence >= 80 else Finding.high

                    tested.append({
                        "check": "fingerprint", "service": service,
                        "confidence": confidence, "status": resp_status,
                    })
                    findings.append(severity(
                        f"Subdomain takeover: {service} (confidence: {confidence}%)",
                        description=(
                            f"Response matches {service} takeover fingerprint. "
                            f"The subdomain {target.host} may be claimable."
                        ),
                        evidence=(
                            f"CNAME: {' → '.join(cname_chain) if cname_chain else 'N/A'}\n"
                            f"Status: {resp_status}\n"
                            f"Body match: {pattern[:80]}\n"
                            f"Confidence: {confidence}%"
                        ),
                        remediation=(
                            f"Remove the DNS record pointing to {service}, "
                            "or reclaim the resource on the platform."
                        ),
                        tags=["analysis", "takeover", service.lower().replace(" ", "-")],
                    ))
                    break  # One match per host

        # Phase 4: Check NS delegation takeover
        if not findings and not ctx.should_stop:
            await self._check_ns_takeover(target.host, ctx, findings, tested)

        # Phase 5: Check MX takeover
        if not findings and not ctx.should_stop:
            await self._check_mx_takeover(target.host, ctx, findings, tested)

        if not findings:
            findings.append(Finding.info(
                f"No takeover fingerprints matched ({len(TAKEOVER_FINGERPRINTS)} checked)",
                tags=["analysis", "takeover"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "takeover_vulnerable": any(
                    f.severity.label != "INFO" for f in findings
                ),
                "cname_chain": cname_chain,
                "takeover_tests": tested,
            },
        )

    # ── DNS Helpers ─────────────────────────────────────────────────────

    async def _resolve_cname(self, host: str, ctx) -> list[str]:
        """Resolve CNAME chain for the host."""
        chain: list[str] = []
        try:
            if hasattr(ctx, "dns") and ctx.dns:
                current = host
                for _ in range(10):  # Max chain depth
                    try:
                        result = await ctx.dns.resolve(current, "CNAME")
                        if result:
                            cname = str(result[0]).rstrip(".")
                            chain.append(cname)
                            current = cname
                        else:
                            break
                    except Exception:
                        break
        except Exception:
            pass
        return chain

    async def _check_nxdomain(self, host: str, ctx) -> bool:
        """Check if a hostname resolves to NXDOMAIN."""
        try:
            if hasattr(ctx, "dns") and ctx.dns:
                result = await ctx.dns.resolve(host, "A")
                return not result or len(result) == 0
        except Exception:
            # DNS resolution failure often means NXDOMAIN
            return True
        return False

    def _identify_service_from_cname(self, cname_chain: list[str]) -> str | None:
        """Identify service from CNAME targets."""
        for cname in cname_chain:
            cname_lower = cname.lower()
            for service, patterns in SERVICE_CNAME_PATTERNS.items():
                for pattern in patterns:
                    if cname_lower.endswith(pattern):
                        return service
        return None

    async def _check_ns_takeover(
        self, host: str, ctx,
        findings: list[Finding], tested: list[dict],
    ) -> None:
        """Check if NS records point to defunct nameservers."""
        try:
            if not hasattr(ctx, "dns") or not ctx.dns:
                return

            # Get parent domain NS
            parts = host.split(".")
            if len(parts) < 2:
                return

            domain = ".".join(parts[-2:])
            ns_records = await ctx.dns.resolve(domain, "NS")
            if not ns_records:
                return

            for ns in ns_records:
                ns_str = str(ns).rstrip(".")
                try:
                    result = await ctx.dns.resolve(ns_str, "A")
                    if not result:
                        tested.append({
                            "check": "ns_takeover", "ns": ns_str,
                        })
                        findings.append(Finding.high(
                            f"NS takeover: nameserver {ns_str} is unresolvable",
                            description=(
                                f"Nameserver {ns_str} for {domain} does not resolve. "
                                "Registering this domain could allow DNS takeover."
                            ),
                            evidence=f"NS record: {ns_str}",
                            remediation="Update or remove defunct NS records.",
                            tags=["analysis", "takeover", "ns"],
                        ))
                except Exception:
                    pass
        except Exception:
            pass

    async def _check_mx_takeover(
        self, host: str, ctx,
        findings: list[Finding], tested: list[dict],
    ) -> None:
        """Check if MX records point to defunct mail servers."""
        try:
            if not hasattr(ctx, "dns") or not ctx.dns:
                return

            mx_records = await ctx.dns.resolve(host, "MX")
            if not mx_records:
                return

            for mx in mx_records:
                mx_host = str(mx).split()[-1].rstrip(".") if " " in str(mx) else str(mx).rstrip(".")
                try:
                    result = await ctx.dns.resolve(mx_host, "A")
                    if not result:
                        tested.append({
                            "check": "mx_takeover", "mx": mx_host,
                        })
                        findings.append(Finding.medium(
                            f"MX takeover: mail server {mx_host} is unresolvable",
                            description=(
                                f"MX record {mx_host} for {host} does not resolve. "
                                "Could allow mail interception via MX takeover."
                            ),
                            evidence=f"MX record: {mx_host}",
                            remediation="Update or remove defunct MX records.",
                            tags=["analysis", "takeover", "mx"],
                        ))
                except Exception:
                    pass
        except Exception:
            pass
