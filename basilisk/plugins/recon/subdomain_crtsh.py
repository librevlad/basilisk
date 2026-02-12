"""Subdomain discovery via crt.sh (Certificate Transparency logs).

Enhanced with pagination, wildcard expansion, deduplication, and
organization name extraction.  Level: beyond crt.sh CLI tools.
"""

from __future__ import annotations

import json
import re
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

# Max pages to fetch for large domains
MAX_PAGES = 5
PAGE_SIZE = 1000


class SubdomainCrtshPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="subdomain_crtsh",
        display_name="Subdomains (crt.sh)",
        category=PluginCategory.RECON,
        description=(
            "Discovers subdomains via Certificate Transparency logs (crt.sh) "
            "with pagination, wildcard expansion, and org extraction"
        ),
        produces=["subdomains"],
        provides="subdomains",
        timeout=45.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        subdomains: set[str] = set()
        orgs: set[str] = set()
        issuers: set[str] = set()
        total_certs = 0

        # Phase 1: Standard query with JSON output
        entries = await self._fetch_crtsh(ctx, target.host)
        total_certs = len(entries)

        for entry in entries:
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower()
                name = re.sub(r"^\*\.", "", name)
                if name and (
                    name.endswith(f".{target.host}") or name == target.host
                ):
                    subdomains.add(name)

            # Extract organization info
            issuer_name = entry.get("issuer_name", "")
            if issuer_name:
                issuers.add(issuer_name)
            org = self._extract_org(entry.get("name_value", ""))
            if org:
                orgs.add(org)

        subdomains.discard(target.host)

        # Phase 2: Wildcard expansion — query for known wildcard patterns
        if not ctx.should_stop:
            wildcard_subs = await self._expand_wildcards(
                ctx, target.host, subdomains,
            )
            subdomains.update(wildcard_subs)

        # Phase 3: Organization-based search (find related certs)
        org_domains: set[str] = set()
        if not ctx.should_stop and orgs:
            for org in list(orgs)[:2]:
                org_entries = await self._fetch_crtsh_org(ctx, org, target.host)
                for entry in org_entries:
                    for name in entry.get("name_value", "").split("\n"):
                        name = name.strip().lower()
                        name = re.sub(r"^\*\.", "", name)
                        if name and name.endswith(f".{target.host}"):
                            org_domains.add(name)
            subdomains.update(org_domains)

        sorted_subs = sorted(subdomains)

        findings = []
        if sorted_subs:
            findings.append(Finding.info(
                f"crt.sh: {len(sorted_subs)} subdomains from {total_certs} certificates",
                evidence=", ".join(sorted_subs[:30]),
                tags=["recon", "subdomains", "crt.sh"],
            ))
        else:
            findings.append(Finding.info(
                "crt.sh: no subdomains found",
                tags=["recon", "subdomains", "crt.sh"],
            ))

        if org_domains:
            findings.append(Finding.info(
                f"crt.sh org search: {len(org_domains)} additional subdomains",
                evidence=", ".join(sorted(org_domains)[:10]),
                tags=["recon", "subdomains", "crt.sh", "org"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "subdomains": sorted_subs,
                "total_certs": total_certs,
                "issuers": sorted(issuers),
            },
        )

    async def _fetch_crtsh(
        self, ctx, domain: str, page: int = 0,
    ) -> list[dict]:
        """Fetch crt.sh JSON results with pagination support."""
        all_entries: list[dict] = []

        for p in range(MAX_PAGES):
            if ctx.should_stop:
                break
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            if p > 0:
                url += f"&p={p + 1}"
            try:
                async with ctx.rate:
                    text = await ctx.http.fetch_text(url, timeout=25.0)
                if not text:
                    break
                entries = json.loads(text)
                if not entries:
                    break
                all_entries.extend(entries)
                # If we got fewer than expected, no more pages
                if len(entries) < PAGE_SIZE:
                    break
            except Exception:
                break

        return all_entries

    async def _fetch_crtsh_org(
        self, ctx, org: str, domain: str,
    ) -> list[dict]:
        """Search crt.sh by organization name."""
        try:
            url = f"https://crt.sh/?O={org}&output=json"
            async with ctx.rate:
                text = await ctx.http.fetch_text(url, timeout=15.0)
            if not text:
                return []
            entries = json.loads(text)
            # Filter to only entries matching our domain
            return [
                e for e in entries
                if domain in e.get("name_value", "").lower()
            ][:100]
        except Exception:
            return []

    async def _expand_wildcards(
        self, ctx, domain: str, existing: set[str],
    ) -> set[str]:
        """Expand wildcard subdomains by querying common prefixes."""
        expanded: set[str] = set()
        # Find wildcards in existing set
        wildcard_bases = set()
        for sub in existing:
            parts = sub.split(".")
            if len(parts) > 2:
                # e.g., for mail.sub.domain.com, try querying sub.domain.com
                parent = ".".join(parts[1:])
                if parent != domain and parent.endswith(f".{domain}"):
                    wildcard_bases.add(parent)

        # Query each wildcard base
        for base in list(wildcard_bases)[:10]:
            if ctx.should_stop:
                break
            try:
                url = f"https://crt.sh/?q=%.{base}&output=json"
                async with ctx.rate:
                    text = await ctx.http.fetch_text(url, timeout=10.0)
                if text:
                    entries = json.loads(text)
                    for entry in entries[:200]:
                        for name in entry.get("name_value", "").split("\n"):
                            name = name.strip().lower()
                            name = re.sub(r"^\*\.", "", name)
                            if name.endswith(f".{domain}"):
                                expanded.add(name)
            except Exception:
                continue

        return expanded - existing

    @staticmethod
    def _extract_org(name_value: str) -> str:
        """Extract organization from certificate name_value if present."""
        # Simple heuristic — look for O= in the name
        match = re.search(r"O=([^/,]+)", name_value)
        return match.group(1).strip() if match else ""
