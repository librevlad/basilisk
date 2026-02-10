"""Cookie security analyzer — checks for missing flags and issues."""

from __future__ import annotations

from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class CookieScanPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="cookie_scan",
        display_name="Cookie Security Scanner",
        category=PluginCategory.SCANNING,
        description="Analyzes cookies for security flags (Secure, HttpOnly, SameSite)",
        produces=["cookie_issues"],
        timeout=10.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        findings: list[Finding] = []
        cookies_data: list[dict] = []

        for scheme in ("https", "http"):
            url = f"{scheme}://{target.host}/"
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(url, timeout=8.0)
                    set_cookies = resp.headers.getall("Set-Cookie", [])
                    for cookie_str in set_cookies:
                        info = self._parse_cookie(cookie_str, scheme == "https")
                        cookies_data.append(info)
                    if set_cookies:
                        break
            except Exception:
                continue

        for cookie in cookies_data:
            name = cookie["name"]
            if not cookie["secure"] and cookie.get("is_https"):
                findings.append(Finding.medium(
                    f"Cookie '{name}' missing Secure flag",
                    description="Cookie transmitted over HTTPS lacks Secure flag",
                    evidence=cookie["raw"][:200],
                    remediation="Add Secure flag to prevent transmission over HTTP",
                    tags=["scanning", "cookie"],
                ))
            if not cookie["httponly"] and self._is_session_cookie(name):
                findings.append(Finding.medium(
                    f"Session cookie '{name}' missing HttpOnly flag",
                    description="Session cookie accessible via JavaScript (XSS risk)",
                    evidence=cookie["raw"][:200],
                    remediation="Add HttpOnly flag to session cookies",
                    tags=["scanning", "cookie"],
                ))
            if not cookie["samesite"]:
                findings.append(Finding.low(
                    f"Cookie '{name}' missing SameSite attribute",
                    evidence=cookie["raw"][:200],
                    remediation="Add SameSite=Lax or SameSite=Strict",
                    tags=["scanning", "cookie"],
                ))

        if not cookies_data:
            findings.append(Finding.info(
                "No cookies set by the server",
                tags=["scanning", "cookie"],
            ))
        elif not findings:
            findings.append(Finding.info(
                f"{len(cookies_data)} cookies analyzed, all properly secured",
                tags=["scanning", "cookie"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"cookies": cookies_data},
        )

    @staticmethod
    def _parse_cookie(raw: str, is_https: bool) -> dict:
        parts = raw.split(";")
        name_val = parts[0].strip()
        name = name_val.split("=", 1)[0].strip() if "=" in name_val else name_val
        flags = raw.lower()
        return {
            "name": name,
            "secure": "secure" in flags,
            "httponly": "httponly" in flags,
            "samesite": "samesite" in flags,
            "is_https": is_https,
            "raw": raw,
        }

    @staticmethod
    def _is_session_cookie(name: str) -> bool:
        session_names = {
            "session", "sessionid", "sid", "phpsessid", "jsessionid",
            "csrf", "csrftoken", "token", "auth", "jwt",
            "connect.sid", "asp.net_sessionid", "_session",
        }
        return name.lower().replace("-", "").replace("_", "") in {
            s.replace("-", "").replace("_", "") for s in session_names
        }
