"""Registry lookup — probe Docker registries for exposed catalogs."""

from __future__ import annotations

import json
import logging
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)

REGISTRY_PORTS = [5000, 443]


class RegistryLookupPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="registry_lookup",
        display_name="Container Registry Lookup",
        category=PluginCategory.SCANNING,
        description="Probe Docker registries for exposed image catalogs",
        produces=["registries"],
        timeout=20.0,
        requires_http=True,
        risk_level="safe",
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available",
            )

        findings: list[Finding] = []
        registries: list[dict] = []

        for port in REGISTRY_PORTS:
            if ctx.should_stop:
                break
            result = await self._probe_registry(ctx, target.host, port, findings)
            if result:
                registries.append(result)

        if not findings:
            findings.append(Finding.info(
                "No exposed container registries found", tags=["container", "registry"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"registries": registries},
        )

    async def _probe_registry(
        self, ctx, host: str, port: int, findings: list[Finding],
    ) -> dict | None:
        """Probe a Docker registry on the given port."""
        scheme = "https" if port == 443 else "http"
        base = f"{scheme}://{host}:{port}"

        # Check /v2/ endpoint
        try:
            async with ctx.rate:
                resp = await ctx.http.get(base + "/v2/", timeout=5.0)
                if resp.status not in (200, 401):
                    return None

                registry_info: dict = {"url": base, "port": port}

                if resp.status == 200:
                    findings.append(Finding.high(
                        f"Unauthenticated Docker registry on port {port}",
                        evidence=f"GET {base}/v2/ returned 200 OK",
                        description="Docker registry accessible without authentication",
                        tags=["container", "registry"],
                    ))
                    registry_info["authenticated"] = False

                    # Try to list catalog
                    catalog = await self._get_catalog(ctx, base, findings)
                    if catalog:
                        registry_info["repositories"] = catalog

                elif resp.status == 401:
                    findings.append(Finding.info(
                        f"Docker registry detected on port {port} (auth required)",
                        tags=["container", "registry"],
                    ))
                    registry_info["authenticated"] = True

                return registry_info

        except Exception:
            logger.debug("Registry probe failed on %s:%d", host, port)
            return None

    async def _get_catalog(
        self, ctx, base: str, findings: list[Finding],
    ) -> list[str]:
        """Attempt to list registry catalog."""
        try:
            async with ctx.rate:
                resp = await ctx.http.get(base + "/v2/_catalog", timeout=5.0)
                if resp.status != 200:
                    return []
                body = await resp.text(encoding="utf-8", errors="replace")
                data = json.loads(body)
                repos = data.get("repositories", [])

                if repos:
                    findings.append(Finding.medium(
                        f"Registry catalog exposed: {len(repos)} repositories",
                        evidence="\n".join(repos[:20]),
                        description="Public catalog listing may reveal internal image names",
                        tags=["container", "registry", "catalog"],
                    ))

                return repos[:100]
        except Exception:
            return []
