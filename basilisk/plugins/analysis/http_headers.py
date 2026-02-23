"""HTTP security headers analyzer plugin.

Comprehensive check of 15+ security headers with A-F grading,
aligned with securityheaders.com methodology.
"""

from __future__ import annotations

import contextlib
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target
from basilisk.utils.http import resolve_base_urls

# ---------------------------------------------------------------------------
# Header definitions: each key is the canonical header name (case-insensitive
# matching is used during checks). Fields:
#   severity  - default severity when the header is completely missing
#   weight    - points deducted from the grade when absent/misconfigured
#   title     - short finding title
#   remediation - recommended fix
# ---------------------------------------------------------------------------
SECURITY_HEADERS: dict[str, dict] = {
    "Strict-Transport-Security": {
        "severity": "medium",
        "weight": 15,
        "title": "Missing HSTS header",
        "remediation": (
            "Add Strict-Transport-Security: max-age=31536000; "
            "includeSubDomains; preload"
        ),
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "weight": 15,
        "title": "Missing Content-Security-Policy",
        "remediation": "Implement a strict Content-Security-Policy header",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "weight": 10,
        "title": "Missing X-Content-Type-Options",
        "remediation": "Add X-Content-Type-Options: nosniff",
    },
    "X-Frame-Options": {
        "severity": "low",
        "weight": 10,
        "title": "Missing X-Frame-Options",
        "remediation": "Add X-Frame-Options: DENY or SAMEORIGIN",
    },
    "Referrer-Policy": {
        "severity": "low",
        "weight": 8,
        "title": "Missing Referrer-Policy",
        "remediation": (
            "Add Referrer-Policy: strict-origin-when-cross-origin "
            "or no-referrer"
        ),
    },
    "Permissions-Policy": {
        "severity": "low",
        "weight": 8,
        "title": "Missing Permissions-Policy",
        "remediation": (
            "Add Permissions-Policy to restrict browser features "
            "(camera, microphone, geolocation, etc.)"
        ),
    },
    "Cross-Origin-Opener-Policy": {
        "severity": "low",
        "weight": 5,
        "title": "Missing Cross-Origin-Opener-Policy (COOP)",
        "remediation": "Add Cross-Origin-Opener-Policy: same-origin",
    },
    "Cross-Origin-Embedder-Policy": {
        "severity": "low",
        "weight": 5,
        "title": "Missing Cross-Origin-Embedder-Policy (COEP)",
        "remediation": "Add Cross-Origin-Embedder-Policy: require-corp",
    },
    "Cross-Origin-Resource-Policy": {
        "severity": "low",
        "weight": 5,
        "title": "Missing Cross-Origin-Resource-Policy (CORP)",
        "remediation": "Add Cross-Origin-Resource-Policy: same-origin",
    },
    "X-Permitted-Cross-Domain-Policies": {
        "severity": "low",
        "weight": 3,
        "title": "Missing X-Permitted-Cross-Domain-Policies",
        "remediation": "Add X-Permitted-Cross-Domain-Policies: none",
    },
    "Cache-Control": {
        "severity": "low",
        "weight": 5,
        "title": "Missing Cache-Control header",
        "remediation": (
            "Add Cache-Control: no-store, no-cache, must-revalidate "
            "for sensitive pages"
        ),
    },
}

# Information disclosure headers that should be removed/obfuscated
INFO_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "Via",
    "X-Runtime",
    "X-Version",
]

# Deprecated header — presence should trigger a specific note
DEPRECATED_HEADERS = ["X-XSS-Protection"]

# Safe Referrer-Policy values (secure enough to avoid leaking full URL)
_SAFE_REFERRER_POLICIES = {
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "no-referrer-when-downgrade",
}

# Maximum score (sum of all weights)
_MAX_SCORE = sum(h["weight"] for h in SECURITY_HEADERS.values())


def _get_header_value(headers: dict[str, str], name: str) -> str | None:
    """Case-insensitive header lookup."""
    lower = name.lower()
    for k, v in headers.items():
        if k.lower() == lower:
            return v
    return None


def _compute_grade(score: int) -> str:
    """Map a 0-100 percentage score to a letter grade A-F."""
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 65:
        return "C"
    if score >= 50:
        return "D"
    if score >= 35:
        return "E"
    return "F"


class HttpHeadersPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="http_headers",
        display_name="HTTP Security Headers",
        category=PluginCategory.ANALYSIS,
        description=(
            "Checks 15+ security headers, validates values, "
            "detects info disclosure, and assigns an A-F grade"
        ),
        produces=["http_info"],
        timeout=20.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        findings: list[Finding] = []
        headers_data: dict = {}

        base_urls = await resolve_base_urls(target, ctx)
        for url in base_urls:
            try:
                resp = await ctx.http.get(url, timeout=10.0)
                async with resp:
                    headers = dict(resp.headers)
                    if not headers_data:
                        headers_data = {
                            "url": str(resp.url),
                            "status": resp.status,
                            "headers": headers,
                        }
                    findings.extend(self._check_security_headers(headers, url))
                    findings.extend(self._check_header_values(headers, url))
                    findings.extend(self._check_info_disclosure(headers, url))
                    findings.extend(self._check_deprecated(headers, url))
                    findings.extend(self._check_cors(headers, url))
                    findings.extend(self._check_clickjacking(headers, url))
            except Exception:
                continue

        if not headers_data:
            return PluginResult(
                plugin=self.meta.name,
                target=target.host,
                status="partial",
                findings=[Finding.info(
                    f"Could not connect to {target.host} via HTTP/HTTPS",
                )],
            )

        # Compute grade
        grade_info = self._compute_grade_info(
            dict(headers_data.get("headers", {})),
        )
        headers_data["grade"] = grade_info["grade"]
        headers_data["grade_score"] = grade_info["score"]
        headers_data["present_headers"] = grade_info["present"]
        headers_data["missing_headers"] = grade_info["missing"]

        findings.append(Finding.info(
            f"Security headers grade: {grade_info['grade']} "
            f"({grade_info['score']}%) on {headers_data['url']}",
            description=(
                f"Present: {len(grade_info['present'])}/{len(SECURITY_HEADERS)} "
                f"security headers. "
                f"Missing: {', '.join(grade_info['missing'][:8]) or 'none'}"
            ),
            tags=["headers", "grade"],
        ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data=headers_data,
        )

    # ------------------------------------------------------------------
    # Missing header checks
    # ------------------------------------------------------------------

    def _check_security_headers(
        self, headers: dict[str, str], host: str,
    ) -> list[Finding]:
        """Report missing security headers."""
        findings: list[Finding] = []

        for header_name, config in SECURITY_HEADERS.items():
            value = _get_header_value(headers, header_name)
            if value is not None:
                continue
            severity = config["severity"]
            factory = getattr(Finding, severity)
            findings.append(factory(
                f"{config['title']} on {host}",
                description=f"The {header_name} header is not set",
                evidence=f"Response headers from {host} do not include {header_name}",
                remediation=config["remediation"],
                tags=["headers", header_name.lower()],
            ))

        return findings

    # ------------------------------------------------------------------
    # Value validation
    # ------------------------------------------------------------------

    def _check_header_values(
        self, headers: dict[str, str], host: str,
    ) -> list[Finding]:
        """Validate values of present security headers."""
        findings: list[Finding] = []

        # --- HSTS validation ---
        hsts = _get_header_value(headers, "Strict-Transport-Security")
        if hsts:
            findings.extend(self._validate_hsts(hsts, host))

        # --- CSP validation ---
        csp = _get_header_value(headers, "Content-Security-Policy")
        if csp:
            findings.extend(self._validate_csp(csp, host))

        # --- X-Content-Type-Options validation ---
        xcto = _get_header_value(headers, "X-Content-Type-Options")
        if xcto and xcto.strip().lower() != "nosniff":
            findings.append(Finding.low(
                f"Invalid X-Content-Type-Options value on {host}",
                description=f"Expected 'nosniff', got '{xcto.strip()}'",
                evidence=f"X-Content-Type-Options: {xcto}",
                remediation="Set X-Content-Type-Options: nosniff",
                tags=["headers", "x-content-type-options"],
            ))

        # --- X-Frame-Options validation ---
        xfo = _get_header_value(headers, "X-Frame-Options")
        if xfo and xfo.strip().upper() not in ("DENY", "SAMEORIGIN"):
            findings.append(Finding.low(
                f"Weak X-Frame-Options value on {host}",
                description=(
                    f"Value '{xfo.strip()}' is not DENY or SAMEORIGIN. "
                    "ALLOW-FROM is deprecated."
                ),
                evidence=f"X-Frame-Options: {xfo}",
                remediation="Set X-Frame-Options: DENY or SAMEORIGIN",
                tags=["headers", "x-frame-options"],
            ))

        # --- Referrer-Policy validation ---
        rp = _get_header_value(headers, "Referrer-Policy")
        if rp:
            # The header can contain a comma-separated fallback list
            policies = {p.strip().lower() for p in rp.split(",")}
            if "unsafe-url" in policies:
                findings.append(Finding.medium(
                    f"Unsafe Referrer-Policy on {host}",
                    description="Referrer-Policy 'unsafe-url' leaks full URL",
                    evidence=f"Referrer-Policy: {rp}",
                    remediation=(
                        "Use strict-origin-when-cross-origin or no-referrer"
                    ),
                    tags=["headers", "referrer-policy"],
                ))
            elif not policies & _SAFE_REFERRER_POLICIES:
                findings.append(Finding.low(
                    f"Weak Referrer-Policy on {host}",
                    description=f"Policy '{rp}' may leak referrer information",
                    evidence=f"Referrer-Policy: {rp}",
                    remediation=(
                        "Use strict-origin-when-cross-origin or no-referrer"
                    ),
                    tags=["headers", "referrer-policy"],
                ))

        # --- Cache-Control validation ---
        cc = _get_header_value(headers, "Cache-Control")
        if cc:
            cc_lower = cc.lower()
            # Only flag if caching directives are overly permissive
            if "public" in cc_lower and "no-store" not in cc_lower:
                findings.append(Finding.low(
                    f"Cache-Control allows public caching on {host}",
                    description=(
                        "Public caching without no-store may expose "
                        "sensitive data in shared caches"
                    ),
                    evidence=f"Cache-Control: {cc}",
                    remediation=(
                        "Add no-store for pages with sensitive content"
                    ),
                    tags=["headers", "cache-control"],
                ))

        return findings

    # ------------------------------------------------------------------
    # HSTS deep validation
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_hsts(value: str, host: str) -> list[Finding]:
        findings: list[Finding] = []
        lower = value.lower()

        # Parse max-age
        max_age = 0
        for part in lower.split(";"):
            part = part.strip()
            if part.startswith("max-age"):
                with contextlib.suppress(IndexError, ValueError):
                    max_age = int(part.split("=", 1)[1].strip())

        if max_age < 31536000:
            findings.append(Finding.medium(
                f"HSTS max-age too low on {host}",
                description=(
                    f"max-age={max_age} is less than the recommended "
                    "31536000 (1 year)"
                ),
                evidence=f"Strict-Transport-Security: {value}",
                remediation=(
                    "Set max-age=31536000 or higher (63072000 for 2 years)"
                ),
                tags=["headers", "hsts"],
            ))

        if "includesubdomains" not in lower:
            findings.append(Finding.low(
                f"HSTS missing includeSubDomains on {host}",
                description=(
                    "Subdomains are not covered by HSTS; they can be "
                    "accessed over plain HTTP"
                ),
                evidence=f"Strict-Transport-Security: {value}",
                remediation="Add includeSubDomains directive to HSTS",
                tags=["headers", "hsts"],
            ))

        if "preload" not in lower:
            findings.append(Finding.info(
                f"HSTS missing preload directive on {host}",
                description=(
                    "The preload directive is needed for HSTS preload "
                    "list inclusion (hstspreload.org)"
                ),
                evidence=f"Strict-Transport-Security: {value}",
                remediation="Add preload directive to HSTS header",
                tags=["headers", "hsts"],
            ))

        return findings

    # ------------------------------------------------------------------
    # CSP deep validation
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_csp(value: str, host: str) -> list[Finding]:
        findings: list[Finding] = []
        lower = value.lower()

        # Check for unsafe directives
        unsafe_checks = [
            (
                "'unsafe-inline'",
                "CSP allows unsafe-inline",
                "unsafe-inline permits inline scripts, defeating XSS protection",
                "medium",
            ),
            (
                "'unsafe-eval'",
                "CSP allows unsafe-eval",
                "unsafe-eval permits eval(), enabling code injection",
                "medium",
            ),
        ]
        for token, title, desc, sev in unsafe_checks:
            if token in lower:
                factory = getattr(Finding, sev)
                findings.append(factory(
                    f"{title} on {host}",
                    description=desc,
                    evidence=f"Content-Security-Policy: ...{token}...",
                    remediation=f"Remove {token} from CSP; use nonces or hashes",
                    tags=["headers", "csp"],
                ))

        # Check for wildcard sources
        # Split into directives and look for standalone *
        directives = [d.strip() for d in lower.split(";") if d.strip()]
        for directive in directives:
            parts = directive.split()
            if len(parts) >= 2:
                directive_name = parts[0]
                sources = parts[1:]
                if "*" in sources:
                    findings.append(Finding.medium(
                        f"CSP wildcard source in {directive_name} on {host}",
                        description=(
                            f"Wildcard '*' in {directive_name} allows "
                            "loading resources from any origin"
                        ),
                        evidence=f"{directive_name}: *",
                        remediation=(
                            f"Replace wildcard in {directive_name} with "
                            "specific origins"
                        ),
                        tags=["headers", "csp"],
                    ))

        # Check for data: URI scheme (can bypass CSP in some contexts)
        if "data:" in lower:
            # Find which directives contain data:
            for directive in directives:
                parts = directive.split()
                if len(parts) >= 2 and "data:" in parts[1:]:
                    findings.append(Finding.low(
                        f"CSP allows data: URIs in {parts[0]} on {host}",
                        description=(
                            "data: URIs can be used to bypass CSP "
                            "protections in some scenarios"
                        ),
                        evidence=f"{parts[0]} ... data: ...",
                        remediation=f"Remove data: from {parts[0]} if possible",
                        tags=["headers", "csp"],
                    ))

        # Check for missing important directives
        important_directives = [
            "default-src", "script-src", "object-src", "base-uri",
        ]
        present_directives = {
            d.split()[0] for d in directives if d.split()
        }
        for directive in important_directives:
            if directive not in present_directives:
                # default-src covers others, so only flag if both missing
                if directive != "default-src" and "default-src" in present_directives:
                    continue
                findings.append(Finding.low(
                    f"CSP missing {directive} directive on {host}",
                    description=(
                        f"The {directive} directive is not set; "
                        "the browser will use a permissive default"
                    ),
                    remediation=f"Add {directive} directive to CSP",
                    tags=["headers", "csp"],
                ))

        # Report-only mode is not enforcement
        report_only = _get_header_value(
            {"Content-Security-Policy-Report-Only": value},
            "Content-Security-Policy-Report-Only",
        )
        if report_only:
            findings.append(Finding.info(
                f"CSP is in report-only mode on {host}",
                description="CSP-Report-Only does not block violations",
                tags=["headers", "csp"],
            ))

        return findings

    # ------------------------------------------------------------------
    # Info disclosure
    # ------------------------------------------------------------------

    def _check_info_disclosure(
        self, headers: dict[str, str], host: str,
    ) -> list[Finding]:
        findings: list[Finding] = []

        for header_name in INFO_HEADERS:
            value = _get_header_value(headers, header_name)
            if value is None:
                continue

            # Determine severity: version numbers are more concerning
            has_version = any(c.isdigit() for c in value)
            severity = "medium" if has_version else "low"
            factory = getattr(Finding, severity)

            desc = f"The {header_name} header reveals server information"
            if has_version:
                desc += " including version number"

            findings.append(factory(
                f"Information disclosure: {header_name} on {host}",
                description=desc,
                evidence=f"{header_name}: {value}",
                remediation=f"Remove or obfuscate the {header_name} header",
                tags=["headers", "info-disclosure"],
            ))

        return findings

    # ------------------------------------------------------------------
    # Deprecated headers
    # ------------------------------------------------------------------

    @staticmethod
    def _check_deprecated(
        headers: dict[str, str], host: str,
    ) -> list[Finding]:
        findings: list[Finding] = []

        xxp = _get_header_value(headers, "X-XSS-Protection")
        if xxp is not None:
            # X-XSS-Protection is deprecated; modern browsers ignore it.
            # Value "1" can actually introduce vulnerabilities in older IE.
            value_stripped = xxp.strip()
            if value_stripped == "0":
                findings.append(Finding.info(
                    f"X-XSS-Protection explicitly disabled on {host}",
                    description=(
                        "X-XSS-Protection: 0 is the recommended value if "
                        "the header is present at all (the feature is "
                        "deprecated in modern browsers)"
                    ),
                    evidence=f"X-XSS-Protection: {xxp}",
                    tags=["headers", "deprecated"],
                ))
            else:
                findings.append(Finding.low(
                    f"Deprecated X-XSS-Protection header on {host}",
                    description=(
                        "X-XSS-Protection is deprecated. In older IE "
                        "versions, enabling it can introduce XSS via "
                        "selective response blocking. Use CSP instead."
                    ),
                    evidence=f"X-XSS-Protection: {xxp}",
                    remediation=(
                        "Remove X-XSS-Protection or set to 0; "
                        "rely on Content-Security-Policy instead"
                    ),
                    tags=["headers", "deprecated"],
                ))
        else:
            # Not present — just note it (not a finding, skip)
            pass

        return findings

    # ------------------------------------------------------------------
    # CORS
    # ------------------------------------------------------------------

    @staticmethod
    def _check_cors(
        headers: dict[str, str], host: str,
    ) -> list[Finding]:
        findings: list[Finding] = []

        acao = _get_header_value(headers, "Access-Control-Allow-Origin")
        if not acao:
            return findings

        if acao.strip() == "*":
            # Check if credentials are also allowed (critical misconfiguration)
            acac = _get_header_value(
                headers, "Access-Control-Allow-Credentials",
            )
            if acac and acac.strip().lower() == "true":
                findings.append(Finding.high(
                    f"CORS wildcard with credentials on {host}",
                    description=(
                        "Access-Control-Allow-Origin: * combined with "
                        "Access-Control-Allow-Credentials: true is a "
                        "critical CORS misconfiguration (browsers block "
                        "this, but misconfigurations in reverse proxies "
                        "may still expose data)"
                    ),
                    evidence=(
                        f"Access-Control-Allow-Origin: {acao}, "
                        f"Access-Control-Allow-Credentials: {acac}"
                    ),
                    remediation="Restrict CORS to specific trusted origins",
                    tags=["headers", "cors"],
                ))
            else:
                findings.append(Finding.medium(
                    f"Wildcard CORS on {host}",
                    description=(
                        "Access-Control-Allow-Origin is set to '*', "
                        "allowing any origin to read responses"
                    ),
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    remediation="Restrict CORS to specific trusted origins",
                    tags=["headers", "cors"],
                ))
        elif acao.strip().lower() == "null":
            findings.append(Finding.medium(
                f"CORS allows null origin on {host}",
                description=(
                    "Access-Control-Allow-Origin: null can be exploited "
                    "via sandboxed iframes"
                ),
                evidence=f"Access-Control-Allow-Origin: {acao}",
                remediation="Do not reflect 'null' as an allowed origin",
                tags=["headers", "cors"],
            ))

        return findings

    # ------------------------------------------------------------------
    # Clickjacking (combined X-Frame-Options + CSP frame-ancestors)
    # ------------------------------------------------------------------

    @staticmethod
    def _check_clickjacking(
        headers: dict[str, str], host: str,
    ) -> list[Finding]:
        findings: list[Finding] = []

        xfo = _get_header_value(headers, "X-Frame-Options")
        csp = _get_header_value(headers, "Content-Security-Policy") or ""

        has_frame_ancestors = "frame-ancestors" in csp.lower()

        if not xfo and not has_frame_ancestors:
            findings.append(Finding.medium(
                f"No framing protection (clickjacking) on {host}",
                description=(
                    "Neither X-Frame-Options nor CSP frame-ancestors "
                    "is set; the page can be framed by any origin"
                ),
                evidence=(
                    f"Response from {host} lacks both X-Frame-Options "
                    f"and CSP frame-ancestors directives"
                ),
                remediation=(
                    "Add X-Frame-Options: DENY or "
                    "Content-Security-Policy: frame-ancestors 'none'"
                ),
                tags=["headers", "clickjacking"],
            ))

        return findings

    # ------------------------------------------------------------------
    # Grade computation
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_grade_info(headers: dict[str, str]) -> dict:
        """Compute an A-F grade based on header presence and correctness.

        Returns a dict with 'grade', 'score' (0-100), 'present', 'missing'.
        """
        earned = 0
        present: list[str] = []
        missing: list[str] = []

        for header_name, config in SECURITY_HEADERS.items():
            value = _get_header_value(headers, header_name)
            if value is not None:
                present.append(header_name)
                weight = config["weight"]

                # Partial credit for weak values
                lower_name = header_name.lower()
                if lower_name == "strict-transport-security":
                    # Check max-age >= 1 year
                    lv = value.lower()
                    try:
                        ma = int(
                            lv.split("max-age=")[1].split(";")[0].strip()
                        )
                    except (IndexError, ValueError):
                        ma = 0
                    if ma >= 31536000:
                        earned += weight
                    elif ma >= 86400:
                        earned += weight // 2
                    else:
                        earned += weight // 4

                elif lower_name == "content-security-policy":
                    lv = value.lower()
                    if "'unsafe-inline'" in lv or "'unsafe-eval'" in lv:
                        earned += weight // 2
                    elif "*" in lv.split():
                        earned += weight * 3 // 4
                    else:
                        earned += weight

                elif lower_name == "x-content-type-options":
                    if value.strip().lower() == "nosniff":
                        earned += weight
                    else:
                        earned += weight // 2

                else:
                    earned += weight
            else:
                missing.append(header_name)

        # Bonus: deduct points for info disclosure headers
        info_penalty = 0
        for hdr in INFO_HEADERS:
            val = _get_header_value(headers, hdr)
            if val and any(c.isdigit() for c in val):
                info_penalty += 3  # version info is worse
            elif val:
                info_penalty += 1

        score = max(0, min(100, round(earned / _MAX_SCORE * 100) - info_penalty))
        grade = _compute_grade(score)

        return {
            "grade": grade,
            "score": score,
            "present": present,
            "missing": missing,
        }
