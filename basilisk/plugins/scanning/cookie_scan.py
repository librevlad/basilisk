"""Cookie security analyzer — comprehensive audit of all cookie attributes."""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any, ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target
from basilisk.utils.http_check import resolve_base_url

# Cookie names that likely hold sensitive session/auth material
_SENSITIVE_NAMES = {
    "session", "sessionid", "sid", "phpsessid", "jsessionid",
    "csrf", "csrftoken", "xsrf-token", "_csrf",
    "token", "auth", "authtoken", "jwt", "access_token",
    "connect.sid", "asp.net_sessionid", "_session",
    "laravel_session", "ci_session", "rack.session",
    "remember_token", "remember_me", "api_key", "apikey",
    "sso_token", "refresh_token",
}

# Normalise cookie name for comparison (lowercase, strip -_)
_NORMALISE_RE = re.compile(r"[-_.]")


def _norm(name: str) -> str:
    return _NORMALISE_RE.sub("", name.lower())


_SENSITIVE_NORMALISED = {_norm(n) for n in _SENSITIVE_NAMES}


class CookieScanPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="cookie_scan",
        display_name="Cookie Security Scanner",
        category=PluginCategory.SCANNING,
        description="Analyzes cookies for security flags (Secure, HttpOnly, SameSite)",
        produces=["cookie_issues"],
        timeout=15.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        findings: list[Finding] = []
        cookies_data: list[dict] = []

        base_url = await resolve_base_url(target.host, ctx)
        if not base_url:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info(
                    "Host not reachable via HTTP/HTTPS",
                    tags=["scanning", "cookie"],
                )],
                data={"cookies": []},
            )

        is_https = base_url.startswith("https://")

        # ---- Collect cookies from main page + common paths ----
        paths = ["/", "/login", "/api", "/admin"]
        seen_names: set[str] = set()

        for path in paths:
            if ctx.should_stop:
                break
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(
                        f"{base_url}{path}", timeout=8.0,
                    )
                    set_cookies = resp.headers.getall("Set-Cookie", [])
                    for cookie_str in set_cookies:
                        info = self._parse_cookie(cookie_str, is_https)
                        if info["name"] not in seen_names:
                            seen_names.add(info["name"])
                            cookies_data.append(info)
            except Exception:
                continue

        # ---- Analyse each cookie ----
        for cookie in cookies_data:
            name = cookie["name"]
            is_sensitive = self._is_sensitive_cookie(name)
            raw_short = cookie["raw"][:200]

            # 1. Secure flag
            if not cookie["secure"] and is_https:
                sev = "high" if is_sensitive else "medium"
                findings.append(getattr(Finding, sev)(
                    f"Cookie '{name}' missing Secure flag (HTTPS site)",
                    description=(
                        "Cookie can be sent over unencrypted HTTP, "
                        "exposing it to MitM interception"
                    ),
                    evidence=raw_short,
                    remediation="Add Secure flag to prevent transmission over HTTP",
                    tags=["scanning", "cookie", "secure-flag", "owasp:a02"],
                ))

            # 2. HttpOnly flag
            if not cookie["httponly"]:
                if is_sensitive:
                    findings.append(Finding.high(
                        f"Sensitive cookie '{name}' missing HttpOnly flag",
                        description=(
                            "Cookie is accessible via document.cookie, "
                            "allowing theft through XSS"
                        ),
                        evidence=raw_short,
                        remediation="Add HttpOnly flag to prevent JavaScript access",
                        tags=["scanning", "cookie", "httponly", "xss", "owasp:a03"],
                    ))
                else:
                    findings.append(Finding.low(
                        f"Cookie '{name}' missing HttpOnly flag",
                        evidence=raw_short,
                        remediation="Add HttpOnly flag unless JavaScript access is required",
                        tags=["scanning", "cookie", "httponly"],
                    ))

            # 3. SameSite attribute
            samesite = cookie.get("samesite_value", "")
            if not cookie["samesite"]:
                sev = "medium" if is_sensitive else "low"
                findings.append(getattr(Finding, sev)(
                    f"Cookie '{name}' missing SameSite attribute",
                    description=(
                        "Without SameSite, the cookie is sent on all "
                        "cross-site requests (CSRF risk)"
                    ),
                    evidence=raw_short,
                    remediation="Add SameSite=Lax or SameSite=Strict",
                    tags=["scanning", "cookie", "samesite", "csrf"],
                ))
            elif samesite.lower() == "none":
                if not cookie["secure"]:
                    findings.append(Finding.high(
                        f"Cookie '{name}': SameSite=None without Secure flag",
                        description=(
                            "SameSite=None requires Secure flag; browsers "
                            "will reject the cookie otherwise"
                        ),
                        evidence=raw_short,
                        remediation="Add Secure flag when using SameSite=None",
                        tags=["scanning", "cookie", "samesite"],
                    ))
                elif is_sensitive:
                    findings.append(Finding.medium(
                        f"Sensitive cookie '{name}' has SameSite=None",
                        description=(
                            "Cookie is sent on cross-site requests, which "
                            "may enable CSRF attacks"
                        ),
                        evidence=raw_short,
                        remediation="Use SameSite=Lax or Strict for session cookies",
                        tags=["scanning", "cookie", "samesite", "csrf"],
                    ))

            # 4. Domain scope analysis
            domain = cookie.get("domain", "")
            if domain:
                # Domain too broad (e.g. .example.com includes all subdomains)
                parts = domain.lstrip(".").split(".")
                if len(parts) <= 2 and is_sensitive:
                    findings.append(Finding.medium(
                        f"Cookie '{name}' has broad domain scope: {domain}",
                        description=(
                            "Cookie is shared across all subdomains; a "
                            "compromised subdomain can steal it"
                        ),
                        evidence=f"Domain={domain}",
                        remediation="Restrict cookie to the specific hostname",
                        tags=["scanning", "cookie", "scope"],
                    ))

            # 5. Path scope
            path = cookie.get("path", "")
            if path == "/" and is_sensitive:
                # Path=/ is fine for session cookies, but flag if extremely broad
                pass  # Typical for session; no finding needed
            elif path and path != "/":
                findings.append(Finding.info(
                    f"Cookie '{name}' scoped to path: {path}",
                    tags=["scanning", "cookie", "scope"],
                ))

            # 6. Entropy check (session tokens should be random)
            value = cookie.get("value", "")
            if is_sensitive and value:
                entropy = self._shannon_entropy(value)
                if entropy < 3.0 and len(value) > 4:
                    findings.append(Finding.high(
                        f"Low entropy session cookie '{name}': {entropy:.1f} bits/char",
                        description=(
                            "Session token has low randomness, making it "
                            "predictable/brute-forceable"
                        ),
                        evidence=f"Value: {value[:40]}... Entropy: {entropy:.2f}",
                        remediation="Use a CSPRNG to generate session tokens (min 128 bits)",
                        tags=["scanning", "cookie", "entropy", "session", "owasp:a02"],
                    ))
                elif entropy < 4.0 and len(value) > 8:
                    findings.append(Finding.medium(
                        f"Medium entropy session cookie '{name}': {entropy:.1f} bits/char",
                        description="Session token may lack sufficient randomness",
                        evidence=f"Entropy: {entropy:.2f} bits/char",
                        remediation="Increase token length and randomness",
                        tags=["scanning", "cookie", "entropy"],
                    ))

            # 7. Lifetime analysis (persistent vs session)
            max_age = cookie.get("max_age")
            expires = cookie.get("expires", "")
            if max_age is not None:
                if is_sensitive and max_age > 86400 * 30:  # > 30 days
                    findings.append(Finding.medium(
                        f"Long-lived session cookie '{name}': "
                        f"{max_age // 86400} days",
                        description=(
                            "Persistent session cookie increases the window "
                            "for session hijacking"
                        ),
                        evidence=f"Max-Age: {max_age}",
                        remediation="Reduce session cookie lifetime to hours, not days",
                        tags=["scanning", "cookie", "lifetime", "session"],
                    ))
            elif not expires and is_sensitive:
                # Session cookie (no expiry) — fine for auth
                findings.append(Finding.info(
                    f"Session cookie '{name}' expires with browser session",
                    tags=["scanning", "cookie", "lifetime"],
                ))

            # 8. Cookie prefix checks (__Secure- / __Host-)
            if name.startswith("__Secure-"):
                if not cookie["secure"]:
                    findings.append(Finding.high(
                        f"__Secure- prefixed cookie '{name}' missing Secure flag",
                        description=(
                            "Cookies with __Secure- prefix MUST have the "
                            "Secure flag; browsers reject them otherwise"
                        ),
                        evidence=raw_short,
                        remediation="Add Secure flag to __Secure- cookies",
                        tags=["scanning", "cookie", "prefix"],
                    ))
            elif name.startswith("__Host-"):
                prefix_ok = (
                    cookie["secure"]
                    and not domain
                    and cookie.get("path") == "/"
                )
                if not prefix_ok:
                    issues_list: list[str] = []
                    if not cookie["secure"]:
                        issues_list.append("missing Secure")
                    if domain:
                        issues_list.append(f"Domain={domain}")
                    if cookie.get("path") != "/":
                        issues_list.append(f"Path={cookie.get('path', '(not set)')}")
                    findings.append(Finding.high(
                        f"__Host- prefixed cookie '{name}' violates constraints",
                        description=(
                            "__Host- cookies must have Secure, no Domain, "
                            "and Path=/"
                        ),
                        evidence=f"Issues: {', '.join(issues_list)}",
                        remediation="Fix cookie attributes to match __Host- requirements",
                        tags=["scanning", "cookie", "prefix"],
                    ))
            elif is_sensitive and is_https:
                # Suggest using cookie prefixes for sensitive cookies
                findings.append(Finding.info(
                    f"Sensitive cookie '{name}' could use __Host- or __Secure- prefix",
                    description="Cookie prefixes add browser-enforced security guarantees",
                    tags=["scanning", "cookie", "prefix", "recommendation"],
                ))

        # ---- Summary ----
        if not cookies_data:
            findings.append(Finding.info(
                "No cookies set by the server",
                tags=["scanning", "cookie"],
            ))
        else:
            secure_count = sum(1 for c in cookies_data if c["secure"])
            httponly_count = sum(1 for c in cookies_data if c["httponly"])
            samesite_count = sum(1 for c in cookies_data if c["samesite"])
            total = len(cookies_data)
            findings.append(Finding.info(
                f"Cookie summary: {total} total, "
                f"{secure_count} Secure, "
                f"{httponly_count} HttpOnly, "
                f"{samesite_count} SameSite",
                tags=["scanning", "cookie", "summary"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"cookies": cookies_data},
        )

    # ================================================================
    # Parsing helpers
    # ================================================================

    @staticmethod
    def _parse_cookie(raw: str, is_https: bool) -> dict[str, Any]:
        """Parse Set-Cookie header into structured dict."""
        parts = [p.strip() for p in raw.split(";")]
        name_val = parts[0]
        name = name_val.split("=", 1)[0].strip() if "=" in name_val else name_val
        value = name_val.split("=", 1)[1].strip() if "=" in name_val else ""

        flags_lower = raw.lower()

        # Extract SameSite value
        samesite_value = ""
        samesite_match = re.search(r"samesite\s*=\s*(\w+)", flags_lower)
        if samesite_match:
            samesite_value = samesite_match.group(1).capitalize()

        # Extract Domain
        domain = ""
        domain_match = re.search(r"domain\s*=\s*([^;]+)", flags_lower)
        if domain_match:
            domain = domain_match.group(1).strip()

        # Extract Path
        path = ""
        path_match = re.search(r"(?<![a-z])path\s*=\s*([^;]+)", flags_lower)
        if path_match:
            path = path_match.group(1).strip()

        # Extract Max-Age
        max_age = None
        max_age_match = re.search(r"max-age\s*=\s*(\d+)", flags_lower)
        if max_age_match:
            max_age = int(max_age_match.group(1))

        # Extract Expires
        expires = ""
        expires_match = re.search(r"expires\s*=\s*([^;]+)", flags_lower)
        if expires_match:
            expires = expires_match.group(1).strip()

        return {
            "name": name,
            "value": value,
            "secure": any(
                p.strip().lower() == "secure"
                for p in parts[1:]
            ),
            "httponly": any(
                p.strip().lower() == "httponly"
                for p in parts[1:]
            ),
            "samesite": bool(samesite_value),
            "samesite_value": samesite_value,
            "domain": domain,
            "path": path,
            "max_age": max_age,
            "expires": expires,
            "is_https": is_https,
            "raw": raw,
        }

    @staticmethod
    def _is_sensitive_cookie(name: str) -> bool:
        """Check if cookie name matches known sensitive/session patterns."""
        return _norm(name) in _SENSITIVE_NORMALISED

    @staticmethod
    def _shannon_entropy(data: str) -> float:
        """Calculate Shannon entropy of a string (bits per character)."""
        if not data:
            return 0.0
        counts = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy
