"""CORS misconfiguration scanner."""

from __future__ import annotations

from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class CorsScanPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="cors_scan",
        display_name="CORS Scanner",
        category=PluginCategory.SCANNING,
        description="Detects CORS misconfigurations allowing unauthorized cross-origin access",
        produces=["cors_issues"],
        timeout=15.0,
    )

    EVIL_ORIGINS = [
        "https://evil.com",
        "https://attacker.com",
        "null",
    ]

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        findings: list[Finding] = []
        issues: list[dict] = []
        base_url = ""

        for scheme in ("https", "http"):
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(
                        f"{scheme}://{target.host}/", timeout=8.0,
                    )
                    base_url = f"{scheme}://{target.host}"
                    break
            except Exception:
                continue

        if not base_url:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info("Host not reachable")],
                data={"cors_issues": []},
            )

        for origin in self.EVIL_ORIGINS:
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(
                        f"{base_url}/",
                        headers={"Origin": origin},
                        timeout=8.0,
                    )
                    acao = resp.headers.get("Access-Control-Allow-Origin", "")
                    acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                    if acao == "*":
                        issues.append({"origin": origin, "acao": acao, "acac": acac})
                        findings.append(Finding.medium(
                            "CORS: wildcard origin (*)",
                            description="Server allows any origin via ACAO: *",
                            evidence=f"ACAO: {acao}",
                            remediation="Restrict CORS to specific trusted origins",
                            tags=["scanning", "cors"],
                        ))
                        break
                    elif acao == origin and origin != "null":
                        sev = "high" if acac.lower() == "true" else "medium"
                        issues.append({"origin": origin, "acao": acao, "acac": acac})
                        f = getattr(Finding, sev)(
                            f"CORS: reflects arbitrary origin{' with credentials' if acac else ''}",
                            description=f"Server reflects Origin header: {origin}",
                            evidence=f"ACAO: {acao}, ACAC: {acac}",
                            remediation="Validate Origin against a whitelist",
                            tags=["scanning", "cors"],
                        )
                        findings.append(f)
                        break
                    elif acao == "null":
                        issues.append({"origin": origin, "acao": acao, "acac": acac})
                        findings.append(Finding.medium(
                            "CORS: null origin allowed",
                            description="Server allows null origin (sandboxed iframe exploit)",
                            evidence="ACAO: null",
                            remediation="Do not reflect null as allowed origin",
                            tags=["scanning", "cors"],
                        ))
                        break
            except Exception:
                continue

        if not findings:
            findings.append(Finding.info(
                "No CORS misconfigurations detected",
                tags=["scanning", "cors"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"cors_issues": issues},
        )
