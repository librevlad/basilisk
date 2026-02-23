"""CORS misconfiguration scanner — CORScanner-level (12+ checks)."""

from __future__ import annotations

from typing import Any, ClassVar
from urllib.parse import urlparse

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target
from basilisk.utils.http_check import resolve_base_url


class CorsScanPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="cors_scan",
        display_name="CORS Scanner",
        category=PluginCategory.SCANNING,
        description="Detects CORS misconfigurations allowing unauthorized cross-origin access",
        produces=["cors_issues"],
        timeout=30.0,
    )

    # Internal network origins for trust boundary check
    _INTERNAL_ORIGINS = [
        "http://192.168.1.1",
        "http://10.0.0.1",
        "http://172.16.0.1",
        "http://127.0.0.1",
        "http://localhost",
        "http://[::1]",
    ]

    # Third-party origins commonly mis-trusted
    _THIRD_PARTY_ORIGINS = [
        "https://cdn.jsdelivr.net",
        "https://cdnjs.cloudflare.com",
        "https://unpkg.com",
        "https://googleapis.com",
        "https://s3.amazonaws.com",
    ]

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        findings: list[Finding] = []
        issues: list[dict] = []

        base_url = await resolve_base_url(target.host, ctx)
        if not base_url:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info(
                    "Host not reachable via HTTP/HTTPS",
                    tags=["scanning", "cors"],
                )],
                data={"cors_issues": []},
            )

        parsed = urlparse(base_url)
        host = target.host

        # ---- 1. Wildcard origin (*) ----
        if not ctx.should_stop:
            r = await self._test_origin(
                base_url, "https://anything.example.com", ctx
            )
            if r and r["acao"] == "*":
                creds = r["acac"].lower() == "true"
                if creds:
                    issues.append(r)
                    findings.append(Finding.critical(
                        "CORS: wildcard (*) with credentials",
                        description=(
                            "Access-Control-Allow-Origin: * combined with "
                            "Access-Control-Allow-Credentials: true allows any "
                            "site to read authenticated responses"
                        ),
                        evidence=f"ACAO: {r['acao']}, ACAC: {r['acac']}",
                        remediation="Never combine wildcard origin with credentials",
                        tags=["scanning", "cors", "owasp:a01"],
                    ))
                else:
                    issues.append(r)
                    findings.append(Finding.medium(
                        "CORS: wildcard origin (*) allowed",
                        description="Server allows any origin via ACAO: *",
                        evidence=f"ACAO: {r['acao']}",
                        remediation="Restrict CORS to specific trusted origins",
                        tags=["scanning", "cors"],
                    ))

        # ---- 2. Arbitrary origin reflection (attacker.com) ----
        if not ctx.should_stop:
            r = await self._test_origin(base_url, "https://attacker.com", ctx)
            if r and r["reflected"]:
                sev = "high" if r["acac"].lower() == "true" else "medium"
                issues.append(r)
                findings.append(getattr(Finding, sev)(
                    "CORS: reflects arbitrary origin"
                    + (" with credentials" if r["acac"] else ""),
                    description=(
                        "Server echoes any Origin header back in ACAO, "
                        "allowing cross-origin data theft"
                    ),
                    evidence=f"Origin: {r['origin']} -> ACAO: {r['acao']}",
                    remediation="Validate Origin against a strict whitelist",
                    tags=["scanning", "cors", "owasp:a01"],
                ))

        # ---- 3. Null origin ----
        if not ctx.should_stop:
            r = await self._test_origin(base_url, "null", ctx)
            if r and r["acao"] == "null":
                creds = r["acac"].lower() == "true"
                sev = "high" if creds else "medium"
                issues.append(r)
                findings.append(getattr(Finding, sev)(
                    "CORS: null origin allowed"
                    + (" with credentials" if creds else ""),
                    description=(
                        "Server allows Origin: null, exploitable from "
                        "sandboxed iframes and data: URIs"
                    ),
                    evidence=f"ACAO: null, ACAC: {r['acac']}",
                    remediation="Do not reflect null as allowed origin",
                    tags=["scanning", "cors", "owasp:a01"],
                ))

        # ---- 4. Subdomain trust test (sub.<target>) ----
        if not ctx.should_stop:
            sub_origin = f"{parsed.scheme}://evil.{host}"
            r = await self._test_origin(base_url, sub_origin, ctx)
            if r and r["reflected"]:
                issues.append(r)
                findings.append(Finding.medium(
                    "CORS: trusts any subdomain origin",
                    description=(
                        "Server reflects subdomain origins; compromised "
                        "subdomain enables cross-origin access"
                    ),
                    evidence=f"Origin: {sub_origin} -> ACAO: {r['acao']}",
                    remediation="Whitelist specific subdomains instead of suffix match",
                    tags=["scanning", "cors", "subdomain-trust"],
                ))

        # ---- 5. Prefix bypass (target.com.attacker.com) ----
        if not ctx.should_stop:
            prefix_origin = f"{parsed.scheme}://{host}.attacker.com"
            r = await self._test_origin(base_url, prefix_origin, ctx)
            if r and r["reflected"]:
                issues.append(r)
                findings.append(Finding.high(
                    "CORS: prefix bypass — origin validation flaw",
                    description=(
                        f"Server trusts {prefix_origin} which an attacker "
                        "can register, indicating regex/string prefix matching"
                    ),
                    evidence=f"Origin: {prefix_origin} -> ACAO: {r['acao']}",
                    remediation="Use exact domain matching, not prefix/contains",
                    tags=["scanning", "cors", "bypass", "owasp:a01"],
                ))

        # ---- 6. Suffix bypass (attacker-target.com) ----
        if not ctx.should_stop:
            # e.g. attacker-example.com for example.com
            suffix_origin = f"{parsed.scheme}://attacker-{host}"
            r = await self._test_origin(base_url, suffix_origin, ctx)
            if r and r["reflected"]:
                issues.append(r)
                findings.append(Finding.high(
                    "CORS: suffix bypass — origin validation flaw",
                    description=(
                        f"Server trusts {suffix_origin}; attacker can "
                        "register a domain containing target domain as suffix"
                    ),
                    evidence=f"Origin: {suffix_origin} -> ACAO: {r['acao']}",
                    remediation="Use exact domain matching, not suffix/contains",
                    tags=["scanning", "cors", "bypass", "owasp:a01"],
                ))

        # ---- 7. Special characters in origin ----
        if not ctx.should_stop:
            for char, name in [
                ("`", "backtick"), ("%60", "encoded-backtick"),
                ("{", "brace"), ("|", "pipe"), ("_", "underscore"),
            ]:
                special_origin = f"{parsed.scheme}://{host}{char}attacker.com"
                r = await self._test_origin(base_url, special_origin, ctx)
                if r and r["reflected"]:
                    issues.append(r)
                    findings.append(Finding.high(
                        f"CORS: special char bypass ({name}) in origin",
                        description=(
                            f"Server accepts origin with special character "
                            f"'{char}' in hostname, indicating weak validation"
                        ),
                        evidence=f"Origin: {special_origin} -> ACAO: {r['acao']}",
                        remediation="Implement strict origin parsing and validation",
                        tags=["scanning", "cors", "bypass", "special-char"],
                    ))
                    break  # One special char finding is enough
                if ctx.should_stop:
                    break

        # ---- 8. Vary: Origin header check ----
        if not ctx.should_stop:
            vary_finding = await self._check_vary_origin(base_url, ctx)
            if vary_finding:
                findings.append(vary_finding)

        # ---- 9. Pre-flight (OPTIONS) analysis ----
        if not ctx.should_stop:
            preflight_findings = await self._check_preflight(base_url, host, ctx)
            findings.extend(preflight_findings)

        # ---- 10. Internal network origin ----
        if not ctx.should_stop:
            for internal_origin in self._INTERNAL_ORIGINS:
                r = await self._test_origin(base_url, internal_origin, ctx)
                if r and r["reflected"]:
                    issues.append(r)
                    findings.append(Finding.high(
                        f"CORS: trusts internal network origin ({internal_origin})",
                        description=(
                            "Server reflects internal/private IP as allowed origin; "
                            "SSRF or internal network access could exploit this"
                        ),
                        evidence=(
                            f"Origin: {internal_origin} -> ACAO: {r['acao']}"
                        ),
                        remediation="Never trust internal network origins in CORS policy",
                        tags=["scanning", "cors", "internal-network", "owasp:a01"],
                    ))
                    break  # One internal origin finding is enough
                if ctx.should_stop:
                    break

        # ---- 11. Third-party origin trust ----
        if not ctx.should_stop:
            trusted_third_parties: list[str] = []
            for tp_origin in self._THIRD_PARTY_ORIGINS:
                r = await self._test_origin(base_url, tp_origin, ctx)
                if r and r["reflected"]:
                    trusted_third_parties.append(tp_origin)
                    issues.append(r)
                if ctx.should_stop:
                    break

            if trusted_third_parties:
                findings.append(Finding.medium(
                    f"CORS: trusts {len(trusted_third_parties)} third-party origin(s)",
                    description=(
                        "Server trusts CDN/cloud origins that host user-uploaded "
                        "content, potentially allowing data exfiltration"
                    ),
                    evidence=f"Trusted: {', '.join(trusted_third_parties[:5])}",
                    remediation="Only trust origins you fully control",
                    tags=["scanning", "cors", "third-party"],
                ))

        # ---- 12. HTTP vs HTTPS origin trust ----
        if not ctx.should_stop and parsed.scheme == "https":
            http_origin = f"http://{host}"
            r = await self._test_origin(base_url, http_origin, ctx)
            if r and r["reflected"]:
                issues.append(r)
                findings.append(Finding.medium(
                    "CORS: trusts HTTP origin on HTTPS site",
                    description=(
                        "HTTPS site accepts the HTTP origin, allowing "
                        "MitM attacker on HTTP to access HTTPS-protected data"
                    ),
                    evidence=f"Origin: {http_origin} -> ACAO: {r['acao']}",
                    remediation="Only trust HTTPS origins on HTTPS endpoints",
                    tags=["scanning", "cors", "downgrade"],
                ))

        # ---- Summary ----
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

    # ================================================================
    # Helpers
    # ================================================================

    async def _test_origin(
        self, base_url: str, origin: str, ctx: Any,
    ) -> dict | None:
        """Send GET with Origin header and parse CORS response headers."""
        try:
            async with ctx.rate:
                resp = await ctx.http.get(
                    f"{base_url}/",
                    headers={"Origin": origin},
                    timeout=8.0,
                )
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                acam = resp.headers.get("Access-Control-Allow-Methods", "")
                acah = resp.headers.get("Access-Control-Allow-Headers", "")
                aceh = resp.headers.get("Access-Control-Expose-Headers", "")

                reflected = acao == origin and origin != "*"

                return {
                    "origin": origin,
                    "acao": acao,
                    "acac": acac,
                    "acam": acam,
                    "acah": acah,
                    "aceh": aceh,
                    "reflected": reflected,
                }
        except Exception:
            return None

    async def _check_vary_origin(
        self, base_url: str, ctx: Any,
    ) -> Finding | None:
        """Check if server sends Vary: Origin when ACAO is dynamic."""
        try:
            # Request with origin
            async with ctx.rate:
                resp1 = await ctx.http.get(
                    f"{base_url}/",
                    headers={"Origin": "https://check-vary.example.com"},
                    timeout=5.0,
                )
                acao1 = resp1.headers.get("Access-Control-Allow-Origin", "")
                vary = resp1.headers.get("Vary", "")

            if acao1 and acao1 != "*" and "origin" not in vary.lower():
                return Finding.low(
                    "CORS: missing Vary: Origin header",
                    description=(
                        "When ACAO is dynamic (reflects Origin), the response "
                        "must include Vary: Origin to prevent cache poisoning"
                    ),
                    evidence=f"ACAO: {acao1}, Vary: {vary or '(not set)'}",
                    remediation="Add Vary: Origin when reflecting Origin in ACAO",
                    tags=["scanning", "cors", "cache-poisoning"],
                )
        except Exception:
            pass
        return None

    async def _check_preflight(
        self, base_url: str, host: str, ctx: Any,
    ) -> list[Finding]:
        """Analyze OPTIONS pre-flight response."""
        findings: list[Finding] = []
        try:
            async with ctx.rate:
                resp = await ctx.http.request(
                    "OPTIONS",
                    f"{base_url}/",
                    headers={
                        "Origin": "https://attacker.com",
                        "Access-Control-Request-Method": "DELETE",
                        "Access-Control-Request-Headers": "X-Custom-Header",
                    },
                    timeout=5.0,
                )

                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acam = resp.headers.get("Access-Control-Allow-Methods", "")
                acah = resp.headers.get("Access-Control-Allow-Headers", "")
                max_age = resp.headers.get("Access-Control-Max-Age", "")

                if acao == "https://attacker.com" or acao == "*":
                    # Check for overly permissive methods
                    if acam:
                        methods = [m.strip().upper() for m in acam.split(",")]
                        dangerous = {"PUT", "DELETE", "PATCH"}
                        exposed = dangerous & set(methods)
                        if exposed:
                            findings.append(Finding.medium(
                                f"CORS pre-flight allows dangerous methods: "
                                f"{', '.join(exposed)}",
                                description=(
                                    "Pre-flight response allows destructive HTTP "
                                    "methods from untrusted origins"
                                ),
                                evidence=f"ACAO: {acao}, ACAM: {acam}",
                                remediation="Restrict allowed methods to GET, POST, HEAD",
                                tags=["scanning", "cors", "preflight"],
                            ))

                    # Wildcard headers
                    if acah == "*":
                        findings.append(Finding.medium(
                            "CORS pre-flight allows all request headers (*)",
                            description=(
                                "Server allows any custom header from cross-origin "
                                "requests"
                            ),
                            evidence=f"ACAH: {acah}",
                            remediation="Whitelist specific allowed headers",
                            tags=["scanning", "cors", "preflight"],
                        ))

                    # Max-Age too long (cache poisoning window)
                    if max_age:
                        try:
                            age_sec = int(max_age)
                            if age_sec > 86400:  # > 1 day
                                findings.append(Finding.low(
                                    f"CORS Max-Age too long: {age_sec}s "
                                    f"({age_sec // 3600}h)",
                                    description=(
                                        "Long pre-flight cache allows persistent "
                                        "CORS bypass after brief policy change"
                                    ),
                                    evidence=f"Access-Control-Max-Age: {max_age}",
                                    remediation="Set Max-Age to 3600 (1 hour) or less",
                                    tags=["scanning", "cors", "preflight"],
                                ))
                        except ValueError:
                            pass

        except Exception:
            pass

        return findings
