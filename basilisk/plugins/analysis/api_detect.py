"""API endpoint detection — discovers REST/GraphQL/SOAP APIs."""

from __future__ import annotations

import logging
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)


class ApiDetectPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="api_detect",
        display_name="API Detector",
        category=PluginCategory.ANALYSIS,
        description="Detects API endpoints (REST, GraphQL, Swagger, OpenAPI)",
        produces=["api_endpoints"],
        timeout=20.0,
    )

    API_PATHS = [
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/rest", "/rest/v1", "/v1", "/v2",
        "/swagger.json", "/swagger/", "/swagger-ui.html",
        "/openapi.json", "/openapi.yaml", "/api-docs",
        "/docs", "/redoc",
        "/graphql", "/graphiql",
        "/health", "/healthz", "/status", "/info",
        "/actuator", "/actuator/health",
        "/.well-known/openid-configuration",
        "/wp-json/", "/wp-json/wp/v2",
    ]

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        findings: list[Finding] = []
        discovered: list[dict] = []
        base_url = ""

        for scheme in ("https", "http"):
            try:
                async with ctx.rate:
                    resp = await ctx.http.head(
                        f"{scheme}://{target.host}/", timeout=5.0,
                    )
                    base_url = f"{scheme}://{target.host}"
                    break
            except Exception as e:
                logger.debug("api_detect: %s probe failed: %s", scheme, e)
                continue

        if not base_url:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info("Host not reachable")],
                data={"api_endpoints": []},
            )

        # Fetch SPA baseline to detect catch-all routing
        spa_baseline = ""
        try:
            async with ctx.rate:
                r = await ctx.http.get(
                    f"{base_url}/_nonexistent_8x7z_api/", timeout=5.0,
                )
                if r.status == 200:
                    spa_baseline = await r.text(
                        encoding="utf-8", errors="replace",
                    )
        except Exception as e:
            logger.debug("api_detect: SPA baseline fetch failed: %s", e)

        for path in self.API_PATHS:
            if ctx.should_stop:
                break
            url = f"{base_url}{path}"
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(url, timeout=5.0)
                    if resp.status in (200, 301, 302, 401, 403):
                        body = await resp.text(encoding="utf-8", errors="replace")
                        content_type = resp.headers.get("Content-Type", "")

                        # Skip SPA catch-all responses
                        if (
                            resp.status == 200
                            and spa_baseline
                            and abs(len(body) - len(spa_baseline)) < 100
                            and body[:200] == spa_baseline[:200]
                        ):
                            continue

                        endpoint = {
                            "path": path,
                            "status": resp.status,
                            "content_type": content_type,
                        }

                        # Auth-required endpoints
                        if resp.status in (401, 403):
                            endpoint["auth_required"] = True
                            discovered.append(endpoint)
                            continue

                        # Swagger/OpenAPI documentation
                        if (
                            ("swagger" in path or "openapi" in path or "api-docs" in path)
                            and resp.status == 200
                            and ("swagger" in body.lower() or "openapi" in body.lower())
                        ):
                                discovered.append(endpoint)
                                findings.append(Finding.medium(
                                    f"API documentation exposed: {path}",
                                    description="Public API docs reveal endpoint structure",
                                    evidence=url,
                                    remediation="Restrict API docs to authorized users",
                                    tags=["analysis", "api", "info-disclosure"],
                                ))
                                continue

                        # Actuator endpoints (Spring Boot) — must be JSON
                        if (
                            "actuator" in path
                            and resp.status == 200
                            and "json" in content_type
                        ):
                            discovered.append(endpoint)
                            findings.append(Finding.high(
                                f"Spring Actuator exposed: {path}",
                                description="Actuator may reveal env vars, heap dumps, etc.",
                                evidence=url,
                                remediation="Restrict actuator endpoints",
                                tags=["analysis", "api", "actuator"],
                            ))
                            continue

                        if resp.status == 200 and "json" in content_type:
                            discovered.append(endpoint)

            except Exception as e:
                logger.debug("api_detect: %s failed: %s", path, e)
                continue

        if discovered and not findings:
            findings.append(Finding.info(
                f"Discovered {len(discovered)} API endpoints",
                evidence=", ".join(e["path"] for e in discovered[:10]),
                tags=["analysis", "api"],
            ))
        elif not discovered and not findings:
            findings.append(Finding.info(
                "No API endpoints detected",
                tags=["analysis", "api"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"api_endpoints": discovered},
        )
