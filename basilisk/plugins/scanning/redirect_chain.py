"""HTTP redirect chain analyzer."""

from __future__ import annotations

from typing import ClassVar
from urllib.parse import urlparse

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class RedirectChainPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="redirect_chain",
        display_name="Redirect Chain Analyzer",
        category=PluginCategory.SCANNING,
        description="Traces HTTP redirect chains and detects issues",
        produces=["redirect_chain"],
        timeout=15.0,
    )

    MAX_REDIRECTS = 10

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        findings: list[Finding] = []
        chain: list[dict] = []

        for scheme in ("http", "https"):
            url = f"{scheme}://{target.host}/"
            visited: set[str] = set()

            for _step in range(self.MAX_REDIRECTS):
                if url in visited:
                    findings.append(Finding.medium(
                        "Redirect loop detected",
                        evidence=f"Loop at: {url}",
                        remediation="Fix redirect configuration",
                        tags=["scanning", "redirect"],
                    ))
                    break
                visited.add(url)

                try:
                    async with ctx.rate:
                        resp = await ctx.http.get(
                            url, allow_redirects=False, timeout=8.0,
                        )
                        chain.append({
                            "url": url,
                            "status": resp.status,
                            "location": resp.headers.get("Location", ""),
                        })

                        if resp.status in (301, 302, 303, 307, 308):
                            location = resp.headers.get("Location", "")
                            if not location:
                                break

                            # Check for HTTP → HTTPS upgrade
                            if url.startswith("http://") and location.startswith("https://"):
                                pass  # Good practice

                            # Check for HTTPS → HTTP downgrade
                            if url.startswith("https://") and location.startswith("http://"):
                                findings.append(Finding.medium(
                                    "HTTPS to HTTP downgrade in redirect",
                                    evidence=f"{url} → {location}",
                                    remediation="Never redirect from HTTPS to HTTP",
                                    tags=["scanning", "redirect", "ssl"],
                                ))

                            # Check for open redirect (external domain)
                            src = urlparse(url).hostname
                            dst = urlparse(location).hostname
                            if dst and src and dst != src and not dst.endswith(
                                f".{target.host}"
                            ):
                                findings.append(Finding.low(
                                    f"Redirect to external domain: {dst}",
                                    evidence=f"{url} → {location}",
                                    tags=["scanning", "redirect"],
                                ))

                            url = location
                        else:
                            break
                except Exception:
                    break

        # Check HTTP → HTTPS redirect
        http_chain = [
            c for c in chain if c["url"].startswith("http://")
        ]
        if http_chain and not any(
            c.get("location", "").startswith("https://")
            for c in http_chain
            if c["status"] in (301, 302, 307, 308)
        ):
            findings.append(Finding.low(
                "No HTTP to HTTPS redirect",
                description="HTTP requests are not redirected to HTTPS",
                remediation="Configure HTTP → HTTPS redirect (301)",
                tags=["scanning", "redirect", "ssl"],
            ))

        if not findings:
            findings.append(Finding.info(
                f"Redirect chain: {len(chain)} hops",
                evidence=" → ".join(c["url"] for c in chain),
                tags=["scanning", "redirect"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"chain": chain},
        )
