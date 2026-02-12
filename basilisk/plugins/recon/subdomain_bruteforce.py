"""Subdomain bruteforce using wordlists and DNS resolution.

Enhanced with wildcard detection, dynamic wordlist support, permutation mode,
chunked concurrency, IP enrichment, and progress reporting.
"""

from __future__ import annotations

import asyncio
import contextlib
import secrets
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

# Common prefixes for permutation mode
_PERMUTATION_PREFIXES = [
    "dev", "staging", "api", "test", "prod", "www", "mail", "ftp",
    "admin", "beta", "pre", "uat", "qa", "demo", "internal",
    "vpn", "portal", "cdn", "static", "assets", "docs", "git",
]

CHUNK_SIZE = 500


class SubdomainBruteforcePlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="subdomain_bruteforce",
        display_name="Subdomains (Bruteforce)",
        category=PluginCategory.RECON,
        description=(
            "Discovers subdomains via DNS bruteforce with wordlists, wildcard "
            "detection, dynamic wordlist, permutation mode, and IP enrichment"
        ),
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

        # --- Phase 1: Load base wordlist ---
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

        # --- Phase 2: Dynamic wordlist augmentation ---
        if ctx.dynamic_wordlist is not None:
            try:
                extra = ctx.dynamic_wordlist.generate_from_pipeline(
                    target.host, ctx.state, scope="subdomains",
                )
                if extra:
                    existing = set(words)
                    for w in extra:
                        if w not in existing:
                            words.append(w)
                            existing.add(w)
            except Exception:
                pass  # dynamic wordlist is best-effort

        # --- Phase 3: Permutation mode with known subdomains ---
        known_subs: list[str] = ctx.state.get("subdomains", {}).get(target.host, [])
        if known_subs:
            existing = set(words)
            for sub_fqdn in known_subs:
                label = sub_fqdn.split(".")[0] if "." in sub_fqdn else sub_fqdn
                for prefix in _PERMUTATION_PREFIXES:
                    candidate_a = f"{prefix}-{label}"
                    candidate_b = f"{label}-{prefix}"
                    if candidate_a not in existing:
                        words.append(candidate_a)
                        existing.add(candidate_a)
                    if candidate_b not in existing:
                        words.append(candidate_b)
                        existing.add(candidate_b)

        # --- Phase 4: Wildcard detection ---
        wildcard_ips: set[str] = set()
        is_wildcard = False
        random_label = f"bsk-wc-{secrets.token_hex(10)}"
        try:
            wc_ips = await ctx.dns.get_ips(f"{random_label}.{target.host}")
            if wc_ips:
                wildcard_ips = set(wc_ips)
                is_wildcard = True
        except Exception:
            pass

        # --- Phase 5: Chunked bruteforce with concurrency control ---
        found: dict[str, list[str]] = {}  # fqdn -> [ips]
        sem = asyncio.Semaphore(ctx.config.scan.max_concurrency)
        total = len(words)
        resolved_count = 0

        async def check_sub(word: str) -> tuple[str, list[str]] | None:
            fqdn = f"{word}.{target.host}"
            async with sem, ctx.rate:
                ips = await ctx.dns.get_ips(fqdn)
                if not ips:
                    return None
                # Filter wildcard IPs
                if is_wildcard:
                    real_ips = [ip for ip in ips if ip not in wildcard_ips]
                    if not real_ips:
                        return None
                    return fqdn, real_ips
                return fqdn, ips

        # Process in chunks to avoid overwhelming resolvers
        findings: list[Finding] = []
        for chunk_start in range(0, total, CHUNK_SIZE):
            if ctx.should_stop:
                break

            chunk = words[chunk_start : chunk_start + CHUNK_SIZE]
            tasks = [check_sub(w) for w in chunk]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for r in results:
                if isinstance(r, tuple):
                    fqdn, ips = r
                    found[fqdn] = ips

            resolved_count += len(chunk)

            # Report progress via emit
            with contextlib.suppress(Exception):
                ctx.emit(
                    Finding.info(
                        f"Bruteforce progress: {resolved_count}/{total} "
                        f"({len(found)} found)",
                        tags=["recon", "subdomains", "bruteforce", "progress"],
                    ),
                    target.host,
                )

        # --- Phase 6: Build results ---
        sorted_subs = sorted(found.keys())

        if is_wildcard:
            findings.append(Finding.info(
                f"Wildcard DNS detected (*.{target.host} → "
                f"{', '.join(sorted(wildcard_ips))})",
                description=(
                    "Wildcard DNS resolves random subdomains. Results have been "
                    "filtered to exclude wildcard IPs."
                ),
                tags=["recon", "subdomains", "wildcard"],
            ))

        findings.append(Finding.info(
            f"Bruteforce: {len(sorted_subs)}/{total} subdomains resolved",
            evidence=", ".join(sorted_subs[:20]),
            tags=["recon", "subdomains", "bruteforce"],
        ))

        if len(sorted_subs) > 50:
            findings.append(Finding.low(
                f"Large attack surface: {len(sorted_subs)} subdomains discovered",
                description="A high number of subdomains increases the attack surface",
                remediation="Review and decommission unused subdomains",
                tags=["recon", "subdomains", "attack-surface"],
            ))

        # Build enriched data: subdomain -> IPs mapping
        subdomain_details = [
            {"subdomain": fqdn, "ips": ips} for fqdn, ips in sorted(found.items())
        ]

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "subdomains": sorted_subs,
                "subdomain_details": subdomain_details,
                "wildcard": is_wildcard,
                "wildcard_ips": sorted(wildcard_ips),
                "words_tested": total,
            },
        )
