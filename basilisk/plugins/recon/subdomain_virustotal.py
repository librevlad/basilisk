"""VirusTotal passive DNS subdomain enumeration."""

from __future__ import annotations

from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class SubdomainVirusTotalPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="subdomain_virustotal",
        display_name="VirusTotal Subdomains",
        category=PluginCategory.RECON,
        description="Discovers subdomains via VirusTotal passive DNS",
        provides="subdomains",
        produces=["subdomains"],
        timeout=20.0,
        requires_http=False,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        subdomains: set[str] = set()
        base_url = (
            f"https://www.virustotal.com/ui/domains"
            f"/{target.host}/subdomains?limit=40"
        )

        # VirusTotal /ui/ endpoint is protected by reCAPTCHA since late 2025.
        # The v3 API requires an API key. Try the /ui/ endpoint first, then
        # fall back to the v3 API with a key from config if available.
        api_key = getattr(ctx.config, "virustotal_api_key", "") or ""
        rate_limited = False

        if api_key:
            # Use official v3 API with key
            v3_url = (
                f"https://www.virustotal.com/api/v3/domains"
                f"/{target.host}/subdomains?limit=40"
            )
            cursor = ""
            for _ in range(5):
                if ctx.should_stop:
                    break
                url = v3_url + (f"&cursor={cursor}" if cursor else "")
                try:
                    async with ctx.rate:
                        resp = await ctx.http.get(
                            url, timeout=15.0,
                            headers={"x-apikey": api_key},
                        )
                        if resp.status == 429:
                            rate_limited = True
                            break
                        if resp.status != 200:
                            break
                        data = await resp.json(content_type=None)
                        items = data.get("data", [])
                        if not items:
                            break
                        for item in items:
                            sub = item.get("id", "").strip().lower()
                            if (
                                sub
                                and sub != target.host
                                and sub.endswith(f".{target.host}")
                            ):
                                subdomains.add(sub)
                        cursor = data.get("meta", {}).get("cursor", "")
                        if not cursor:
                            break
                except Exception:
                    break
        else:
            # No API key — try /ui/ endpoint (may be blocked by reCAPTCHA)
            cursor = ""
            for _ in range(5):
                if ctx.should_stop:
                    break
                url = base_url + (f"&cursor={cursor}" if cursor else "")
                try:
                    async with ctx.rate:
                        resp = await ctx.http.get(url, timeout=15.0)
                        if resp.status in (429, 403):
                            rate_limited = True
                            break
                        if resp.status != 200:
                            break
                        data = await resp.json(content_type=None)
                        items = data.get("data", [])
                        if not items:
                            break
                        for item in items:
                            sub = item.get("id", "").strip().lower()
                            if (
                                sub
                                and sub != target.host
                                and sub.endswith(f".{target.host}")
                            ):
                                subdomains.add(sub)
                        cursor = data.get("links", {}).get("next", "")
                        if not cursor:
                            break
                except Exception:
                    break

        findings: list[Finding] = []
        if rate_limited and not subdomains:
            note = " (set virustotal_api_key in config)" if not api_key else ""
            findings.append(Finding.info(
                f"VirusTotal: rate limited / blocked{note}",
                tags=["recon", "subdomains", "virustotal"],
            ))
        else:
            findings.append(Finding.info(
                f"VirusTotal: {len(subdomains)} subdomains",
                evidence=", ".join(sorted(subdomains)[:20]) or "none",
                tags=["recon", "subdomains", "virustotal"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"subdomains": sorted(subdomains)},
        )
