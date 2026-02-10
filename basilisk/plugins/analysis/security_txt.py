"""security.txt checker — RFC 9116 compliance."""

from __future__ import annotations

from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class SecurityTxtPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="security_txt",
        display_name="security.txt Check",
        category=PluginCategory.ANALYSIS,
        description="Checks for security.txt (RFC 9116) and its contents",
        produces=["security_txt"],
        timeout=10.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        findings: list[Finding] = []
        content = ""
        found_url = ""

        paths = [
            "/.well-known/security.txt",
            "/security.txt",
        ]

        for scheme in ("https", "http"):
            for path in paths:
                url = f"{scheme}://{target.host}{path}"
                try:
                    async with ctx.rate:
                        resp = await ctx.http.get(url, timeout=8.0)
                        if resp.status == 200:
                            content = await resp.text(encoding="utf-8", errors="replace")
                            if "contact:" in content.lower():
                                found_url = url
                                break
                except Exception:
                    continue
            if found_url:
                break

        if not found_url:
            findings.append(Finding.info(
                "No security.txt found",
                description="Consider adding /.well-known/security.txt (RFC 9116)",
                remediation="Create security.txt with Contact and Expires fields",
                tags=["analysis", "security-txt"],
            ))
        else:
            fields = self._parse_fields(content)

            findings.append(Finding.info(
                f"security.txt found at {found_url}",
                evidence=f"Fields: {', '.join(fields.keys())}",
                tags=["analysis", "security-txt"],
            ))

            # Check required fields
            if "contact" not in fields:
                findings.append(Finding.low(
                    "security.txt missing Contact field",
                    remediation="Add Contact: field (required by RFC 9116)",
                    tags=["analysis", "security-txt"],
                ))
            if "expires" not in fields:
                findings.append(Finding.low(
                    "security.txt missing Expires field",
                    remediation="Add Expires: field (required by RFC 9116)",
                    tags=["analysis", "security-txt"],
                ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "security_txt_url": found_url,
                "content": content[:1000] if content else "",
            },
        )

    @staticmethod
    def _parse_fields(content: str) -> dict[str, str]:
        fields: dict[str, str] = {}
        for line in content.splitlines():
            line = line.strip()
            if ":" in line and not line.startswith("#"):
                key, _, val = line.partition(":")
                fields[key.strip().lower()] = val.strip()
        return fields
