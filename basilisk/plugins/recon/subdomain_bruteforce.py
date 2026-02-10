"""Subdomain bruteforce using wordlists and DNS resolution."""

from __future__ import annotations

import asyncio
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class SubdomainBruteforcePlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="subdomain_bruteforce",
        display_name="Subdomains (Bruteforce)",
        category=PluginCategory.RECON,
        description="Discovers subdomains via DNS bruteforce with wordlists",
        produces=["subdomains"],
        provides="subdomains",
        default_enabled=False,
        timeout=120.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.dns is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="DNS client not available"
            )

        wordlist_name = "subdomains_common"
        words: list[str] = []
        try:
            words = await ctx.wordlists.get_all(wordlist_name)
        except FileNotFoundError:
            return PluginResult.fail(
                self.meta.name, target.host,
                error=f"Wordlist '{wordlist_name}' not found",
            )

        if not words:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info("Empty wordlist, skipping bruteforce")],
                data={"subdomains": []},
            )

        found: set[str] = set()
        sem = asyncio.Semaphore(ctx.config.scan.max_concurrency)

        async def check_sub(word: str) -> str | None:
            fqdn = f"{word}.{target.host}"
            async with sem, ctx.rate:
                ips = await ctx.dns.get_ips(fqdn)
                if ips:
                    return fqdn
                return None

        tasks = [check_sub(w) for w in words]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, str):
                found.add(r)

        sorted_subs = sorted(found)

        findings = [
            Finding.info(
                f"Bruteforce: {len(sorted_subs)}/{len(words)} subdomains resolved",
                evidence=", ".join(sorted_subs[:20]),
                tags=["recon", "subdomains", "bruteforce"],
            )
        ]

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"subdomains": sorted_subs},
        )
