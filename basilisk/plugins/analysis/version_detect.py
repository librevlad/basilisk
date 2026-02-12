"""Software version detection — headers, meta tags, error pages, and CVE mapping."""

from __future__ import annotations

import re
from typing import Any, ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.data.fingerprints import match_technologies
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target
from basilisk.utils.http_check import resolve_base_url

# ── Version header extraction patterns ────────────────────────────────

_HEADER_VERSION_RULES: list[tuple[str, str, str]] = [
    # (header_name, regex_pattern, tech_name)
    ("Server", r"(Apache)[/ ]*([\d.]+)", "Apache"),
    ("Server", r"(nginx)[/ ]*([\d.]+)", "nginx"),
    ("Server", r"(Microsoft-IIS)[/ ]*([\d.]+)", "IIS"),
    ("Server", r"(LiteSpeed)[/ ]*([\d.]+)", "LiteSpeed"),
    ("Server", r"(openresty)[/ ]*([\d.]+)", "OpenResty"),
    ("Server", r"(Caddy)[/ ]*([\d.]+)", "Caddy"),
    ("Server", r"(gunicorn)[/ ]*([\d.]+)", "Gunicorn"),
    ("Server", r"(Werkzeug)[/ ]*([\d.]+)", "Werkzeug"),
    ("X-Powered-By", r"(PHP)[/ ]*([\d.]+)", "PHP"),
    ("X-Powered-By", r"(ASP\.NET)[/ ]*([\d.]+)", "ASP.NET"),
    ("X-Powered-By", r"(Express)", "Express"),
    ("X-Powered-By", r"(Next\.js)[/ ]*([\d.]+)", "Next.js"),
    ("X-Powered-By", r"(Phusion Passenger)[/ ]*([\d.]+)", "Passenger"),
    ("X-AspNet-Version", r"([\d.]+)", "ASP.NET"),
    ("X-Generator", r"(Drupal)\s*([\d.]+)?", "Drupal"),
    ("X-Generator", r"(WordPress)\s*([\d.]+)?", "WordPress"),
]

# ── Body / script version patterns ────────────────────────────────────

_BODY_VERSION_RULES: list[tuple[str, str]] = [
    (r"jquery[/.-]?([\d.]+)(?:\.min)?\.js", "jQuery"),
    (r"bootstrap[/.-]?([\d.]+)(?:\.min)?\.(?:js|css)", "Bootstrap"),
    (r"vue[/.-]?([\d.]+)(?:\.min)?\.js", "Vue.js"),
    (r'react(?:-dom)?[/.-]([\d.]+)', "React"),
    (r"angular(?:\.min)?[/.-]?([\d.]+)", "Angular"),
    (r"lodash[/.-]?([\d.]+)", "Lodash"),
    (r"moment[/.-]?([\d.]+)", "Moment.js"),
    (r"wordpress[/ ]+([\d.]+)", "WordPress"),
]

# ── Meta tag generator patterns ───────────────────────────────────────

_META_GENERATOR_RULES: list[tuple[str, str]] = [
    (r"WordPress\s+([\d.]+)", "WordPress"),
    (r"Joomla!\s*([\d.]+)", "Joomla"),
    (r"Drupal\s+([\d.]+)", "Drupal"),
    (r"MediaWiki\s+([\d.]+)", "MediaWiki"),
    (r"Ghost\s+([\d.]+)", "Ghost"),
    (r"Wix\.com", "Wix"),
    (r"Blogger", "Blogger"),
    (r"Hugo\s+([\d.]+)", "Hugo"),
    (r"Jekyll\s+v?([\d.]+)", "Jekyll"),
    (r"Gatsby\s+([\d.]+)", "Gatsby"),
]

# ── Known vulnerable version ranges ──────────────────────────────────
# Format: tech -> list of (comparator, version, severity, CVE/description)

_VULNERABLE_VERSIONS: dict[str, list[tuple[str, str, str, str]]] = {
    "Apache": [
        ("lt", "2.4.58", "high", "CVE-2023-43622 / CVE-2023-45802: HTTP/2 DoS"),
        ("lt", "2.4.55", "high", "CVE-2023-25690: HTTP request smuggling"),
        ("lt", "2.4.52", "medium", "CVE-2022-22721: mod_lua buffer overflow"),
    ],
    "nginx": [
        ("lt", "1.25.4", "high", "CVE-2024-24989/24990: HTTP/3 vulnerabilities"),
        ("lt", "1.25.3", "medium", "CVE-2023-44487: HTTP/2 rapid reset"),
    ],
    "PHP": [
        ("lt", "8.3.4", "high", "CVE-2024-2756: password_verify bypass"),
        ("lt", "8.2.17", "high", "CVE-2024-2756: cookie bypass in older 8.2.x"),
        ("lt", "8.1.0", "medium", "PHP 8.0.x is end-of-life"),
        ("lt", "7.5.0", "high", "PHP 7.x is end-of-life, no security patches"),
    ],
    "IIS": [
        ("lt", "10.0", "medium", "IIS < 10 is on unsupported Windows versions"),
    ],
    "jQuery": [
        ("lt", "3.5.0", "medium", "CVE-2020-11022/11023: XSS in htmlPrefilter"),
        ("lt", "3.0.0", "high", "CVE-2019-11358: prototype pollution"),
        ("lt", "1.12.0", "high", "CVE-2015-9251: XSS vulnerability"),
    ],
    "WordPress": [
        ("lt", "6.4.3", "high", "CVE-2024-0942: admin bypass vulnerability"),
        ("lt", "6.3.2", "high", "Multiple security fixes in 6.3.2+"),
    ],
    "Bootstrap": [
        ("lt", "3.4.1", "medium", "CVE-2019-8331: XSS in tooltip/popover"),
    ],
    "Angular": [
        ("lt", "16.0.0", "medium", "Older Angular versions have known XSS vectors"),
    ],
    "ASP.NET": [
        ("lt", "4.8", "medium", "Older ASP.NET versions have known vulnerabilities"),
    ],
    "Joomla": [
        ("lt", "5.0.3", "high", "CVE-2024-21726: XSS vulnerability"),
        ("lt", "4.4.3", "high", "CVE-2024-21726: XSS in mail template"),
    ],
    "Drupal": [
        ("lt", "10.2.3", "high", "SA-CORE-2024-001: access bypass"),
    ],
    "OpenResty": [
        ("lt", "1.21.4", "medium", "Multiple nginx CVEs in bundled nginx"),
    ],
    "Next.js": [
        ("lt", "14.1.1", "high", "CVE-2024-34351: SSRF via Server Actions"),
    ],
    "React": [
        ("lt", "18.0.0", "low", "React < 18 is in maintenance mode"),
    ],
}

# Server-side technologies — version disclosure is higher risk
_SERVER_SIDE = frozenset({
    "Apache", "nginx", "IIS", "LiteSpeed", "OpenResty", "Caddy",
    "Gunicorn", "Werkzeug", "Uvicorn", "Tomcat",
    "PHP", "ASP.NET", "Express", "Next.js", "Passenger",
    "WordPress", "Joomla", "Drupal", "Django", "Flask",
    "Laravel", "Ruby on Rails", "Spring",
})


def _parse_version(ver: str) -> tuple[int, ...]:
    """Parse a dotted version string into a tuple of integers."""
    parts: list[int] = []
    for segment in ver.split("."):
        # Strip non-numeric suffixes (e.g. "2.4.54ubuntu4")
        num = ""
        for ch in segment:
            if ch.isdigit():
                num += ch
            else:
                break
        if num:
            parts.append(int(num))
    return tuple(parts)


def _version_lt(version: str, threshold: str) -> bool:
    """Return True if version < threshold using simple tuple comparison."""
    v = _parse_version(version)
    t = _parse_version(threshold)
    if not v or not t:
        return False
    return v < t


def _check_cves(
    tech: str, version: str,
) -> list[dict[str, str]]:
    """Check a detected version against known vulnerable ranges."""
    rules = _VULNERABLE_VERSIONS.get(tech, [])
    hits: list[dict[str, str]] = []
    for comparator, threshold, severity, description in rules:
        if comparator == "lt" and _version_lt(version, threshold):
            hits.append({
                "threshold": threshold,
                "severity": severity,
                "description": description,
            })
    return hits


class VersionDetectPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="version_detect",
        display_name="Version Detector",
        category=PluginCategory.ANALYSIS,
        description=(
            "Detects software versions from headers, meta tags, "
            "error pages, and maps to known CVEs"
        ),
        produces=["versions"],
        timeout=20.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        findings: list[Finding] = []
        versions: dict[str, str] = {}
        cve_hits: list[dict[str, Any]] = []

        base_url = await resolve_base_url(target.host, ctx)
        if not base_url:
            findings.append(Finding.info(
                "Target not reachable via HTTP/HTTPS",
                tags=["analysis", "version"],
            ))
            return PluginResult.success(
                self.meta.name, target.host,
                findings=findings,
                data={"versions": versions},
            )

        headers: dict[str, str] = {}
        body = ""

        # ── Fetch main page ──────────────────────────────────────
        try:
            async with ctx.rate:
                resp = await ctx.http.get(f"{base_url}/", timeout=8.0)
                headers = dict(resp.headers)
                body = await resp.text(encoding="utf-8", errors="replace")
        except Exception as exc:
            ctx.log.debug("version_detect: main page fetch failed: %s", exc)

        # ── 1. Header-based version detection ────────────────────
        for hdr_name, pattern, tech in _HEADER_VERSION_RULES:
            hdr_value = headers.get(hdr_name, "")
            if not hdr_value:
                # Case-insensitive header lookup
                for k, v in headers.items():
                    if k.lower() == hdr_name.lower():
                        hdr_value = v
                        break
            if hdr_value:
                match = re.search(pattern, hdr_value, re.IGNORECASE)
                if match:
                    ver = match.group(2) if match.lastindex and match.lastindex >= 2 else ""
                    if tech not in versions or (
                        ver and versions.get(tech) == "detected"
                    ):
                        versions[tech] = ver or "detected"

        # ── 2. Meta tag generator detection ──────────────────────
        generator_match = re.search(
            r'<meta[^>]+name=["\']?generator["\']?[^>]+content=["\']([^"\']+)',
            body,
            re.IGNORECASE,
        )
        if generator_match:
            gen_content = generator_match.group(1).strip()
            for pattern, tech in _META_GENERATOR_RULES:
                m = re.search(pattern, gen_content, re.IGNORECASE)
                if m:
                    ver = m.group(1) if m.lastindex and m.lastindex >= 1 else ""
                    if tech not in versions or (
                        ver and versions.get(tech) == "detected"
                    ):
                        versions[tech] = ver or "detected"
                    break

        # ── 3. Body / script version patterns ────────────────────
        for pattern, tech in _BODY_VERSION_RULES:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                ver = match.group(1) if match.lastindex and match.lastindex >= 1 else ""
                if tech not in versions or (
                    ver and versions.get(tech) == "detected"
                ):
                    versions[tech] = ver or "detected"

        # ── 4. Fingerprint DB integration ────────────────────────
        fp_techs = match_technologies(headers, body)
        for tech_info in fp_techs:
            name = tech_info["name"]
            ver = tech_info.get("version", "")
            if ver and (
                name not in versions
                or versions.get(name) in ("", "detected")
            ):
                versions[name] = ver

        # ── 5. Error page version disclosure ─────────────────────
        if not ctx.should_stop:
            await self._check_error_page(
                base_url, ctx, versions, findings,
            )

        # ── 6. Generate findings ─────────────────────────────────
        for tech, ver in sorted(versions.items()):
            is_server = tech in _SERVER_SIDE

            # Check for known CVEs
            if ver and ver != "detected":
                hits = _check_cves(tech, ver)
                for hit in hits:
                    sev = hit["severity"]
                    desc = hit["description"]
                    cve_hits.append({
                        "technology": tech,
                        "version": ver,
                        **hit,
                    })
                    # Map severity string to Finding factory
                    factory = {
                        "critical": Finding.critical,
                        "high": Finding.high,
                        "medium": Finding.medium,
                        "low": Finding.low,
                    }.get(sev, Finding.medium)
                    findings.append(factory(
                        f"Vulnerable {tech} {ver}: {desc}",
                        description=(
                            f"{tech} {ver} is below the safe threshold "
                            f"{hit['threshold']}. "
                            "Upgrade to fix known vulnerabilities."
                        ),
                        remediation=f"Upgrade {tech} to >= {hit['threshold']}",
                        tags=["analysis", "version", "cve"],
                    ))

            # Version disclosure finding
            if is_server:
                # Only report if not already covered by a CVE finding
                if not any(
                    h["technology"] == tech for h in cve_hits
                ):
                    findings.append(Finding.low(
                        f"{tech} version disclosed: {ver}",
                        description=(
                            "Server-side version disclosure helps attackers "
                            "identify known vulnerabilities for targeted attacks."
                        ),
                        remediation=f"Hide {tech} version information",
                        tags=["analysis", "version", "info-disclosure"],
                    ))
            else:
                findings.append(Finding.info(
                    f"{tech}: {ver}",
                    tags=["analysis", "version"],
                ))

        if not versions:
            findings.append(Finding.info(
                "No software versions detected",
                tags=["analysis", "version"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "versions": versions,
                "cve_hits": cve_hits,
                "fingerprint_techs": [
                    {"name": t["name"], "confidence": t["confidence"]}
                    for t in fp_techs[:20]
                ],
            },
        )

    async def _check_error_page(
        self,
        base_url: str,
        ctx,
        versions: dict[str, str],
        findings: list[Finding],
    ) -> None:
        """Probe a non-existent path for version info in error pages."""
        try:
            async with ctx.rate:
                resp = await ctx.http.get(
                    f"{base_url}/nonexistent-page-bslk-12345",
                    timeout=8.0,
                )
                if resp.status in (404, 403, 500):
                    error_body = await resp.text(
                        encoding="utf-8", errors="replace",
                    )
                    error_headers = dict(resp.headers)

                    # Check error page headers
                    for hdr_name, pattern, tech in _HEADER_VERSION_RULES:
                        hdr_val = ""
                        for k, v in error_headers.items():
                            if k.lower() == hdr_name.lower():
                                hdr_val = v
                                break
                        if hdr_val:
                            match = re.search(pattern, hdr_val, re.IGNORECASE)
                            if match:
                                ver = (
                                    match.group(2)
                                    if match.lastindex and match.lastindex >= 2
                                    else ""
                                )
                                if tech not in versions or (
                                    ver and versions.get(tech) in ("", "detected")
                                ):
                                    versions[tech] = ver or "detected"

                    # Check error body for version patterns
                    error_patterns = [
                        (r"Apache/([\d.]+)", "Apache"),
                        (r"nginx/([\d.]+)", "nginx"),
                        (r"Microsoft-IIS/([\d.]+)", "IIS"),
                        (r"PHP/([\d.]+)", "PHP"),
                        (r"Tomcat/([\d.]+)", "Tomcat"),
                        (r"OpenSSL/([\d.a-z]+)", "OpenSSL"),
                        (r"Powered by ([A-Za-z]+)\s*([\d.]+)?", None),
                    ]
                    for pattern, tech in error_patterns:
                        match = re.search(pattern, error_body, re.IGNORECASE)
                        if match and tech:
                            ver = (
                                match.group(1)
                                if tech in ("Apache", "nginx", "IIS", "PHP",
                                            "Tomcat", "OpenSSL")
                                else ""
                            )
                            if tech not in versions or (
                                ver and versions.get(tech) in ("", "detected")
                            ):
                                versions[tech] = ver or "detected"

                    # Flag verbose error pages
                    verbose_markers = [
                        "stack trace", "traceback", "at line",
                        "syntax error", "debug", "exception",
                    ]
                    body_lower = error_body.lower()
                    for marker in verbose_markers:
                        if marker in body_lower:
                            findings.append(Finding.low(
                                "Verbose error page detected",
                                description=(
                                    "Error page contains debug information "
                                    "that may reveal internal details."
                                ),
                                evidence=f"Found '{marker}' in {resp.status} page",
                                remediation=(
                                    "Configure custom error pages that do "
                                    "not expose debug information"
                                ),
                                tags=["analysis", "version", "error-page"],
                            ))
                            break
        except Exception:
            pass
