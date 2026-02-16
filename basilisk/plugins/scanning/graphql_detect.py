"""GraphQL endpoint detection and introspection check."""

from __future__ import annotations

import json
import logging
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)


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
        "/graphql/console", "/playground", "/graphql/playground",
        "/api/v1/graphql", "/api/v2/graphql", "/graphql/v1",
        "/graphql/schema", "/altair", "/voyager",
        "/admin/graphql", "/internal/graphql", "/graph",
        "/graphql-explorer", "/api/graph",
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
        from basilisk.utils.http_check import resolve_base_url

        base_url = await resolve_base_url(target.host, ctx)
        if not base_url:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info("Host not reachable")],
                data={"graphql_endpoints": []},
            )

        for path in self.GQL_PATHS:
            if ctx.should_stop:
                break
            url = f"{base_url}{path}"

            # Try POST first (standard)
            found = False
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
                            "path": path, "introspection": True, "method": "POST",
                        })
                        findings.append(Finding.medium(
                            f"GraphQL introspection enabled at {path}",
                            description=(
                                "GraphQL introspection reveals the entire API "
                                "schema"
                            ),
                            evidence=f"{url} returns schema data",
                            remediation="Disable introspection in production",
                            tags=["scanning", "graphql", "introspection"],
                        ))
                        found = True
                    elif resp.status == 200 and (
                        "data" in body or "errors" in body
                    ):
                        endpoints.append({
                            "path": path, "introspection": False,
                            "method": "POST",
                        })
                        findings.append(Finding.info(
                            f"GraphQL endpoint at {path} "
                            "(introspection disabled)",
                            tags=["scanning", "graphql"],
                        ))
                        found = True
            except Exception as e:
                logger.debug("graphql_detect: POST %s failed: %s", url, e)

            # Try GET-based query (some servers only accept GET)
            if not found:
                try:
                    get_url = (
                        f"{url}?query="
                        "%7B__schema%7Btypes%7Bname%7D%7D%7D"
                    )
                    async with ctx.rate:
                        resp = await ctx.http.get(get_url, timeout=8.0)
                        body = await resp.text(
                            encoding="utf-8", errors="replace",
                        )
                        if resp.status == 200 and "__schema" in body:
                            endpoints.append({
                                "path": path, "introspection": True,
                                "method": "GET",
                            })
                            findings.append(Finding.medium(
                                f"GraphQL introspection via GET at {path}",
                                description=(
                                    "GraphQL accepts GET queries with "
                                    "introspection enabled"
                                ),
                                evidence=f"{get_url}",
                                remediation=(
                                    "Disable introspection in production. "
                                    "Restrict to POST-only."
                                ),
                                tags=[
                                    "scanning", "graphql", "introspection",
                                ],
                            ))
                        elif resp.status == 200 and (
                            "data" in body or "errors" in body
                        ):
                            endpoints.append({
                                "path": path, "introspection": False,
                                "method": "GET",
                            })
                            findings.append(Finding.info(
                                f"GraphQL endpoint at {path} (GET, no "
                                "introspection)",
                                tags=["scanning", "graphql"],
                            ))
                except Exception as e:
                    logger.debug("graphql_detect: GET %s failed: %s", get_url, e)
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
