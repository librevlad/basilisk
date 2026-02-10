"""GraphQL endpoint detection and introspection check."""

from __future__ import annotations

import json
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class GraphqlDetectPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="graphql_detect",
        display_name="GraphQL Detector",
        category=PluginCategory.SCANNING,
        description="Detects GraphQL endpoints and checks for introspection",
        produces=["graphql_endpoints"],
        timeout=15.0,
    )

    GQL_PATHS = [
        "/graphql", "/graphiql", "/gql", "/api/graphql",
        "/v1/graphql", "/v2/graphql", "/query", "/api/gql",
        "/graphql/console", "/playground",
    ]

    INTROSPECTION_QUERY = json.dumps({
        "query": "{__schema{types{name}}}"
    })

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        findings: list[Finding] = []
        endpoints: list[dict] = []
        base_url = ""

        for scheme in ("https", "http"):
            try:
                async with ctx.rate:
                    await ctx.http.head(f"{scheme}://{target.host}/", timeout=5.0)
                    base_url = f"{scheme}://{target.host}"
                    break
            except Exception:
                continue

        if not base_url:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info("Host not reachable")],
                data={"graphql_endpoints": []},
            )

        for path in self.GQL_PATHS:
            url = f"{base_url}{path}"
            try:
                async with ctx.rate:
                    resp = await ctx.http.post(
                        url,
                        data=self.INTROSPECTION_QUERY,
                        headers={"Content-Type": "application/json"},
                        timeout=8.0,
                    )
                    body = await resp.text(encoding="utf-8", errors="replace")

                    if resp.status == 200 and "__schema" in body:
                        endpoints.append({
                            "path": path, "introspection": True,
                        })
                        findings.append(Finding.medium(
                            f"GraphQL introspection enabled at {path}",
                            description=(
                                "GraphQL introspection reveals the entire API schema"
                            ),
                            evidence=f"{url} returns schema data",
                            remediation="Disable introspection in production",
                            tags=["scanning", "graphql", "introspection"],
                        ))
                    elif resp.status == 200 and ("data" in body or "errors" in body):
                        endpoints.append({
                            "path": path, "introspection": False,
                        })
                        findings.append(Finding.info(
                            f"GraphQL endpoint at {path} (introspection disabled)",
                            tags=["scanning", "graphql"],
                        ))
            except Exception:
                continue

        if not findings:
            findings.append(Finding.info(
                "No GraphQL endpoints found",
                tags=["scanning", "graphql"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"graphql_endpoints": endpoints},
        )
