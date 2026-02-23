"""Content Security Policy (CSP) analyzer.

Comprehensive CSP analysis: directive-by-directive checks, 50+ bypass
domains, nonce reuse detection, CSP level classification, and A-F grading.
"""

from __future__ import annotations

import re
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target
from basilisk.utils.http_check import resolve_base_url

# ── Dangerous directive values ───────────────────────────────────────

DANGEROUS_VALUES: dict[str, str] = {
    "unsafe-inline": "Allows inline scripts/styles (XSS risk)",
    "unsafe-eval": "Allows eval() and similar (code injection risk)",
    "unsafe-hashes": (
        "Allows specific inline event handlers (partial XSS risk)"
    ),
    "data:": "Allows data: URIs (script injection bypass)",
    "*": "Wildcard allows loading from any source",
}

# ── CSP bypass domains (50+) with reasons ────────────────────────────

CSP_BYPASS_DOMAINS: list[dict[str, str]] = [
    # CDN with JSONP / arbitrary script hosting
    {"domain": "cdnjs.cloudflare.com", "type": "jsonp",
     "reason": "JSONP callbacks allow arbitrary JS execution"},
    {"domain": "cdn.jsdelivr.net", "type": "script",
     "reason": "Serves any npm package including malicious ones"},
    {"domain": "unpkg.com", "type": "script",
     "reason": "Serves any npm package with XSS payloads"},
    {"domain": "raw.githubusercontent.com", "type": "script",
     "reason": "Serves raw files from any GitHub repository"},
    {"domain": "gist.githubusercontent.com", "type": "script",
     "reason": "Serves raw gist content from any user"},
    {"domain": "gitcdn.xyz", "type": "script",
     "reason": "CDN proxy for GitHub raw files"},
    {"domain": "rawgit.com", "type": "script",
     "reason": "CDN proxy for GitHub raw files"},
    {"domain": "cdn.rawgit.com", "type": "script",
     "reason": "CDN proxy for GitHub raw files"},
    # Google services
    {"domain": "*.googleapis.com", "type": "jsonp",
     "reason": "Google APIs with JSONP support"},
    {"domain": "accounts.google.com", "type": "redirect",
     "reason": "OAuth redirect can be abused for script exec"},
    {"domain": "*.google.com", "type": "jsonp",
     "reason": "Multiple Google services expose JSONP endpoints"},
    {"domain": "*.gstatic.com", "type": "script",
     "reason": "Google static content hosting"},
    {"domain": "translate.google.com", "type": "jsonp",
     "reason": "Google Translate has JSONP callback"},
    {"domain": "*.googleusercontent.com", "type": "script",
     "reason": "User-uploaded content on Google services"},
    # Angular CDN (template injection)
    {"domain": "ajax.googleapis.com", "type": "script",
     "reason": (
         "Hosts AngularJS which enables template injection"
     )},
    {"domain": "ajax.aspnetcdn.com", "type": "script",
     "reason": "Hosts AngularJS for template injection"},
    {"domain": "code.angularjs.org", "type": "script",
     "reason": "AngularJS CDN enables template injection"},
    # Cloud hosting (attacker-controlled content)
    {"domain": "*.cloudfront.net", "type": "script",
     "reason": "Any CloudFront distribution can serve scripts"},
    {"domain": "*.amazonaws.com", "type": "script",
     "reason": "S3 buckets can serve attacker-controlled scripts"},
    {"domain": "*.s3.amazonaws.com", "type": "script",
     "reason": "S3 direct bucket access for attacker scripts"},
    {"domain": "*.azureedge.net", "type": "script",
     "reason": "Azure CDN can serve attacker scripts"},
    {"domain": "*.azurewebsites.net", "type": "script",
     "reason": "Azure web apps can host attacker scripts"},
    {"domain": "*.blob.core.windows.net", "type": "script",
     "reason": "Azure Blob storage for attacker scripts"},
    {"domain": "storage.googleapis.com", "type": "script",
     "reason": "GCS buckets serve arbitrary content"},
    # PaaS platforms (anyone can deploy)
    {"domain": "*.herokuapp.com", "type": "script",
     "reason": "Heroku apps can host attacker scripts"},
    {"domain": "*.firebaseapp.com", "type": "script",
     "reason": "Firebase hosting for any project"},
    {"domain": "*.firebaseio.com", "type": "script",
     "reason": "Firebase Realtime DB for any project"},
    {"domain": "*.appspot.com", "type": "script",
     "reason": "Google App Engine hosts any project"},
    {"domain": "*.netlify.app", "type": "script",
     "reason": "Netlify hosting for attacker-controlled sites"},
    {"domain": "*.netlify.com", "type": "script",
     "reason": "Netlify hosting for attacker-controlled sites"},
    {"domain": "*.vercel.app", "type": "script",
     "reason": "Vercel hosting for attacker-controlled sites"},
    {"domain": "*.now.sh", "type": "script",
     "reason": "Vercel (formerly Now) hosting"},
    {"domain": "*.pages.dev", "type": "script",
     "reason": "Cloudflare Pages for attacker-controlled sites"},
    {"domain": "*.workers.dev", "type": "script",
     "reason": "Cloudflare Workers execute attacker code"},
    {"domain": "*.repl.co", "type": "script",
     "reason": "Replit hosting for attacker-controlled code"},
    {"domain": "*.glitch.me", "type": "script",
     "reason": "Glitch hosting for attacker-controlled code"},
    {"domain": "*.surge.sh", "type": "script",
     "reason": "Surge.sh static hosting"},
    {"domain": "*.render.com", "type": "script",
     "reason": "Render hosting for attacker apps"},
    {"domain": "*.fly.dev", "type": "script",
     "reason": "Fly.io hosting for attacker apps"},
    {"domain": "*.railway.app", "type": "script",
     "reason": "Railway hosting for attacker apps"},
    # File sharing / user content
    {"domain": "dl.dropboxusercontent.com", "type": "script",
     "reason": "Dropbox shared files can contain scripts"},
    {"domain": "*.dropbox.com", "type": "script",
     "reason": "Dropbox shared files can contain scripts"},
    {"domain": "docs.google.com", "type": "redirect",
     "reason": "Google Docs redirect abuse"},
    {"domain": "drive.google.com", "type": "redirect",
     "reason": "Google Drive file hosting"},
    # Social media (JSONP / redirect abuse)
    {"domain": "*.facebook.com", "type": "jsonp",
     "reason": "Facebook Graph API has JSONP endpoints"},
    {"domain": "*.fbcdn.net", "type": "script",
     "reason": "Facebook CDN serves user-uploaded content"},
    {"domain": "*.twitter.com", "type": "jsonp",
     "reason": "Twitter APIs have callback parameters"},
    {"domain": "*.twimg.com", "type": "script",
     "reason": "Twitter CDN serves user content"},
    {"domain": "*.youtube.com", "type": "jsonp",
     "reason": "YouTube API has JSONP callbacks"},
    # Other bypass vectors
    {"domain": "*.yandex.ru", "type": "jsonp",
     "reason": "Yandex services have JSONP callbacks"},
    {"domain": "*.yandex.net", "type": "script",
     "reason": "Yandex CDN can serve scripts"},
    {"domain": "*.vk.com", "type": "jsonp",
     "reason": "VK API has JSONP callbacks"},
    {"domain": "*.yahoo.com", "type": "jsonp",
     "reason": "Yahoo services have JSONP endpoints"},
    {"domain": "*.akamaihd.net", "type": "script",
     "reason": "Akamai CDN can serve user-uploaded content"},
]

# Critical directives that should be present
_CRITICAL_DIRECTIVES: dict[str, str] = {
    "object-src": (
        "Missing object-src allows Flash/Java applets "
        "(use object-src 'none')"
    ),
    "base-uri": (
        "Missing base-uri allows <base> tag hijack for "
        "relative URL manipulation"
    ),
    "form-action": (
        "Missing form-action allows forms to submit data "
        "to any origin"
    ),
    "frame-ancestors": (
        "Missing frame-ancestors leaves the page vulnerable "
        "to clickjacking"
    ),
}

# Nonce / hash regex patterns
_NONCE_RE = re.compile(r"'nonce-([A-Za-z0-9+/=]+)'")
_HASH_RE = re.compile(
    r"'sha(256|384|512)-[A-Za-z0-9+/=]+'"
)

# Meta CSP regex
_META_CSP_RE = re.compile(
    r'<meta[^>]+http-equiv=["\']Content-Security-Policy["\']'
    r'[^>]+content=["\']([^"\']+)',
    re.IGNORECASE,
)


def _parse_csp(raw: str) -> dict[str, list[str]]:
    """Parse a CSP header string into {directive: [values]}."""
    directives: dict[str, list[str]] = {}
    for part in raw.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if tokens:
            directives[tokens[0].lower()] = (
                tokens[1:] if len(tokens) > 1 else []
            )
    return directives


class CspAnalyzerPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="csp_analyzer",
        display_name="CSP Analyzer",
        category=PluginCategory.ANALYSIS,
        description=(
            "Analyzes Content Security Policy for weaknesses, "
            "bypass domains, nonce reuse, and assigns A-F grade"
        ),
        produces=["csp_analysis"],
        timeout=15.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host,
                error="HTTP client not available",
            )

        base_url = await resolve_base_url(target.host, ctx)
        if not base_url:
            return PluginResult.fail(
                self.meta.name, target.host,
                error="Could not reach target via HTTP/HTTPS",
            )

        findings: list[Finding] = []

        # ── Fetch two requests for nonce comparison ──────────
        csp_header = ""
        csp_report_only = ""
        body = ""
        resp1_nonces: set[str] = set()
        resp2_nonces: set[str] = set()

        url = f"{base_url}/"
        for i in range(2):
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(url, timeout=8.0)
                    hdrs = {
                        k.lower(): v
                        for k, v in resp.headers.items()
                    }
                    if i == 0:
                        csp_header = hdrs.get(
                            "content-security-policy", "",
                        )
                        csp_report_only = hdrs.get(
                            "content-security-policy-report-only",
                            "",
                        )
                        body = await resp.text(
                            encoding="utf-8", errors="replace",
                        )
                        resp1_nonces = set(
                            _NONCE_RE.findall(csp_header),
                        )
                    else:
                        csp2 = hdrs.get(
                            "content-security-policy", "",
                        )
                        resp2_nonces = set(
                            _NONCE_RE.findall(csp2),
                        )
            except Exception:
                continue

        # ── Check meta tag CSP ───────────────────────────────
        meta_csp = ""
        if body:
            m = _META_CSP_RE.search(body)
            if m:
                meta_csp = m.group(1)

        # Determine effective CSP
        effective_csp = csp_header or meta_csp
        csp_source = (
            "header" if csp_header
            else "meta" if meta_csp
            else "none"
        )

        # ── No CSP at all ────────────────────────────────────
        if not effective_csp and not csp_report_only:
            findings.append(Finding.medium(
                "No Content-Security-Policy",
                description=(
                    "No CSP header or meta tag found. The site "
                    "has no policy to prevent XSS attacks."
                ),
                evidence="Neither Content-Security-Policy header nor meta tag present",
                remediation=(
                    "Implement a Content-Security-Policy header "
                    "with at minimum: default-src 'self'; "
                    "script-src 'self'; object-src 'none'"
                ),
                tags=["analysis", "csp"],
            ))
            return PluginResult.success(
                self.meta.name, target.host,
                findings=findings,
                data={
                    "csp": None,
                    "csp_report_only": csp_report_only or None,
                    "directives": {},
                    "grade": "F",
                    "bypass_domains": [],
                    "level": 0,
                },
            )

        # ── Report-Only only (no enforced CSP) ───────────────
        is_report_only = False
        if not effective_csp and csp_report_only:
            is_report_only = True
            effective_csp = csp_report_only
            findings.append(Finding.medium(
                "CSP is report-only (not enforced)",
                description=(
                    "Content-Security-Policy-Report-Only does not "
                    "block violations. It only reports them."
                ),
                evidence=csp_report_only[:200],
                remediation=(
                    "Promote the policy to an enforced "
                    "Content-Security-Policy header"
                ),
                tags=["analysis", "csp"],
            ))
        elif csp_report_only:
            findings.append(Finding.info(
                "CSP-Report-Only header also present",
                evidence=csp_report_only[:200],
                tags=["analysis", "csp"],
            ))

        # ── Meta tag CSP note ────────────────────────────────
        if csp_source == "meta":
            findings.append(Finding.low(
                "CSP defined via meta tag instead of header",
                description=(
                    "Meta tag CSP cannot use frame-ancestors, "
                    "report-uri, or sandbox directives. "
                    "Headers are preferred."
                ),
                remediation=(
                    "Move CSP to a Content-Security-Policy "
                    "HTTP response header"
                ),
                tags=["analysis", "csp"],
            ))

        # ── Parse directives ─────────────────────────────────
        directives = _parse_csp(effective_csp)

        # ── Directive-by-directive analysis ───────────────────
        for directive, values in directives.items():
            for val in values:
                val_clean = val.strip("'").lower()
                if val_clean in DANGEROUS_VALUES:
                    sev = (
                        "high"
                        if val_clean in ("unsafe-eval", "*")
                        and directive in (
                            "script-src", "default-src",
                            "script-src-elem",
                        )
                        else "medium"
                    )
                    findings.append(getattr(Finding, sev)(
                        f"CSP {directive}: "
                        f"'{val_clean}' is dangerous",
                        description=(
                            DANGEROUS_VALUES[val_clean]
                        ),
                        evidence=(
                            f"{directive} {' '.join(values)}"
                        ),
                        remediation=(
                            f"Remove '{val_clean}' from "
                            f"{directive}; use nonces or hashes"
                        ),
                        tags=["analysis", "csp"],
                    ))

        # ── Missing critical directives ──────────────────────
        for directive, desc in _CRITICAL_DIRECTIVES.items():
            if directive not in directives:
                # frame-ancestors covered by default-src? No.
                # object-src falls back to default-src
                if directive in ("object-src",) and (
                    "default-src" in directives
                ):
                    ds_vals = directives["default-src"]
                    if "'none'" in ds_vals or "'self'" in ds_vals:
                        continue
                findings.append(Finding.medium(
                    f"CSP missing {directive} directive",
                    description=desc,
                    evidence=f"Current CSP directives: {', '.join(directives.keys())}",
                    remediation=(
                        f"Add {directive} directive to CSP"
                    ),
                    tags=["analysis", "csp"],
                ))

        # ── Missing default-src ──────────────────────────────
        if "default-src" not in directives:
            findings.append(Finding.medium(
                "CSP missing default-src directive",
                description=(
                    "Without default-src, unlisted resource types "
                    "have no restriction"
                ),
                evidence=f"Directives present: {', '.join(directives.keys())}",
                remediation="Add default-src 'self' as baseline",
                tags=["analysis", "csp"],
            ))

        # ── Missing script-src (and no default-src) ──────────
        if (
            "script-src" not in directives
            and "default-src" not in directives
        ):
            findings.append(Finding.high(
                "CSP has no script-src or default-src",
                evidence=f"CSP: {effective_csp[:200]}",
                description=(
                    "Scripts can be loaded from any origin"
                ),
                remediation=(
                    "Define script-src or default-src to "
                    "control script loading"
                ),
                tags=["analysis", "csp"],
            ))

        # ── report-uri / report-to presence ──────────────────
        has_report = (
            "report-uri" in directives
            or "report-to" in directives
        )
        if not has_report:
            findings.append(Finding.info(
                "CSP has no report-uri or report-to",
                description=(
                    "CSP violations are not reported. Configure "
                    "reporting to monitor policy violations."
                ),
                remediation=(
                    "Add report-uri or report-to directive"
                ),
                tags=["analysis", "csp"],
            ))

        # ── Bypass domain detection ──────────────────────────
        csp_lower = effective_csp.lower()
        found_bypasses: list[dict[str, str]] = []
        for entry in CSP_BYPASS_DOMAINS:
            domain = entry["domain"]
            check = domain.lstrip("*.")
            if check.lower() in csp_lower:
                found_bypasses.append(entry)

        for bypass in found_bypasses:
            findings.append(Finding.medium(
                f"CSP bypass domain: {bypass['domain']}",
                description=bypass["reason"],
                evidence=effective_csp[:200],
                remediation=(
                    f"Review if {bypass['domain']} is necessary "
                    f"in CSP ({bypass['type']} bypass)"
                ),
                tags=["analysis", "csp", "bypass"],
            ))

        # ── Nonce analysis ───────────────────────────────────
        all_nonces = _NONCE_RE.findall(effective_csp)
        all_hashes = _HASH_RE.findall(effective_csp)
        has_nonces = bool(all_nonces)
        has_hashes = bool(all_hashes)
        has_strict_dynamic = "'strict-dynamic'" in csp_lower

        # Static nonce detection (compare two requests)
        if (
            resp1_nonces
            and resp2_nonces
            and resp1_nonces & resp2_nonces
        ):
            static = resp1_nonces & resp2_nonces
            findings.append(Finding.high(
                "CSP nonces are static (reused across requests)",
                description=(
                    "Nonces must be unique per response. "
                    "Static nonces can be predicted and used "
                    "by attackers to bypass CSP."
                ),
                evidence=(
                    f"Same nonce in two requests: "
                    f"{', '.join(list(static)[:3])}"
                ),
                remediation=(
                    "Generate a cryptographically random nonce "
                    "for each HTTP response"
                ),
                tags=["analysis", "csp", "nonce"],
            ))

        # ── CSP Level detection ──────────────────────────────
        # Level 3: strict-dynamic
        # Level 2: nonces or hashes
        # Level 1: source-list only
        if has_strict_dynamic:
            csp_level = 3
        elif has_nonces or has_hashes:
            csp_level = 2
        else:
            csp_level = 1

        # ── Grade computation ────────────────────────────────
        grade = self._compute_grade(
            directives=directives,
            is_report_only=is_report_only,
            found_bypasses=found_bypasses,
            has_nonces=has_nonces,
            has_hashes=has_hashes,
            has_strict_dynamic=has_strict_dynamic,
        )

        findings.append(Finding.info(
            f"CSP grade: {grade} (level {csp_level}, "
            f"{len(directives)} directives, "
            f"source: {csp_source})",
            evidence=effective_csp[:300],
            tags=["analysis", "csp", "grade"],
        ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "csp": csp_header or meta_csp or None,
                "csp_report_only": (
                    csp_report_only or None
                ),
                "csp_source": csp_source,
                "directives": directives,
                "grade": grade,
                "level": csp_level,
                "bypass_domains": [
                    b["domain"] for b in found_bypasses
                ],
                "has_nonces": has_nonces,
                "has_hashes": has_hashes,
                "has_strict_dynamic": has_strict_dynamic,
                "has_report": has_report,
            },
        )

    # ── Grade computation ─────────────────────────────────────

    @staticmethod
    def _compute_grade(
        *,
        directives: dict[str, list[str]],
        is_report_only: bool,
        found_bypasses: list[dict[str, str]],
        has_nonces: bool,
        has_hashes: bool,
        has_strict_dynamic: bool,
    ) -> str:
        """Compute A-F grade for the CSP policy.

        A — strict CSP with nonces/hashes, no unsafe-*, no bypasses
        B — CSP present with minor issues
        C — weak CSP (unsafe-inline or many bypasses)
        D — report-only or very weak
        F — no CSP
        """
        # Start with 100 points and deduct
        score = 100

        # Report-only: cap at D
        if is_report_only:
            score = min(score, 40)

        # Check for dangerous values
        all_values_lower = " ".join(
            v
            for vals in directives.values()
            for v in vals
        ).lower()

        if "'unsafe-eval'" in all_values_lower:
            score -= 25
        if "'unsafe-inline'" in all_values_lower:
            # Less penalty if nonces are also present
            # (browsers ignore unsafe-inline with nonces)
            if has_nonces or has_hashes:
                score -= 5
            else:
                score -= 20
        if "data:" in all_values_lower:
            score -= 10

        # Wildcard in script-src or default-src
        script_vals = " ".join(
            directives.get("script-src", [])
            + directives.get("default-src", []),
        )
        if "*" in script_vals.split():
            score -= 30

        # Missing critical directives
        if "default-src" not in directives:
            score -= 15
        if (
            "script-src" not in directives
            and "default-src" not in directives
        ):
            score -= 15
        for crit in ("object-src", "base-uri"):
            if crit not in directives:
                ds = directives.get("default-src", [])
                if "'none'" not in ds and "'self'" not in ds:
                    score -= 5
        if "frame-ancestors" not in directives:
            score -= 5
        if "form-action" not in directives:
            score -= 3

        # Bypass domains
        score -= min(len(found_bypasses) * 5, 25)

        # Bonus for strong CSP features
        if has_strict_dynamic:
            score += 5
        if has_nonces or has_hashes:
            score += 5

        score = max(0, min(100, score))

        if score >= 90:
            return "A"
        if score >= 75:
            return "B"
        if score >= 55:
            return "C"
        if score >= 35:
            return "D"
        return "F"
