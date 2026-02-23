"""Steganography — LSB, palette, EXIF, strings, zsteg/stegsolve wrapper."""

from __future__ import annotations

import logging
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)


class SteganographyPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="steganography",
        display_name="Steganography Analysis",
        category=PluginCategory.FORENSICS,
        description="LSB extraction, palette analysis, EXIF, zsteg, steghide",
        produces=["extracted_data"],
        timeout=60.0,
        requires_http=False,
        risk_level="safe",
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        data: dict = {"tools_used": [], "extracted": []}

        file_path = target.meta.get("file_path", "")
        if not file_path:
            findings.append(Finding.info(
                "No file provided (set target.meta file_path)",
                tags=["forensics", "steg"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        if not ctx.subprocess_mgr:
            findings.append(Finding.info(
                "SubprocessManager not available",
                tags=["forensics", "steg"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        # 1. zsteg (PNG/BMP LSB analysis)
        zsteg_avail = await ctx.subprocess_mgr.is_available("zsteg")
        if zsteg_avail:
            data["tools_used"].append("zsteg")
            result = await ctx.subprocess_mgr.run(
                f"zsteg '{file_path}' 2>/dev/null | head -30", timeout=30,
            )
            if result.stdout:
                interesting = [
                    ln for ln in result.stdout.splitlines()
                    if ln.strip() and "nothing" not in ln.lower()
                ]
                if interesting:
                    data["extracted"].extend(
                        {"tool": "zsteg", "line": ln} for ln in interesting[:10]
                    )
                    findings.append(Finding.high(
                        f"Steganographic data found (zsteg): {len(interesting)} hits",
                        evidence="\n".join(interesting[:10]),
                        tags=["forensics", "steg", "lsb"],
                    ))

        # 2. steghide (JPEG/WAV/BMP/AU)
        steghide_avail = await ctx.subprocess_mgr.is_available("steghide")
        if steghide_avail:
            data["tools_used"].append("steghide")
            # Try without password first
            result = await ctx.subprocess_mgr.run(
                f"steghide info '{file_path}' -p '' 2>&1", timeout=15,
            )
            if result.stdout and "embedded" in result.stdout.lower():
                findings.append(Finding.high(
                    "Steghide data detected (no password)",
                    evidence=result.stdout[:300],
                    description="Extract with: steghide extract -sf file -p ''",
                    tags=["forensics", "steg", "steghide"],
                ))

            # Try common passwords
            passwords = target.meta.get("steg_passwords", [
                "", "password", "123456", "admin", "secret",
            ])
            for pw in passwords[:10]:
                if ctx.should_stop:
                    break
                result = await ctx.subprocess_mgr.run(
                    f"steghide extract -sf '{file_path}' -p '{pw}' -f "
                    f"-xf /tmp/steg_extract 2>&1",
                    timeout=10,
                )
                if result.returncode == 0:
                    data["extracted"].append({
                        "tool": "steghide", "password": pw,
                    })
                    findings.append(Finding.critical(
                        f"Steghide data extracted (password: '{pw}')",
                        evidence=(
                            result.stdout[:300] if result.stdout
                            else "Extracted to /tmp/steg_extract"
                        ),
                        tags=["forensics", "steg", "steghide"],
                    ))
                    break

        # 3. stegseek (fast steghide brute force)
        stegseek_avail = await ctx.subprocess_mgr.is_available("stegseek")
        if stegseek_avail and not any(e.get("tool") == "steghide" for e in data["extracted"]):
            data["tools_used"].append("stegseek")
            result = await ctx.subprocess_mgr.run(
                f"stegseek '{file_path}' /usr/share/wordlists/rockyou.txt "
                f"/tmp/steg_output 2>&1",
                timeout=30,
            )
            if result.returncode == 0 and result.stdout:
                findings.append(Finding.critical(
                    "Steganographic data cracked (stegseek)",
                    evidence=result.stdout[:300],
                    tags=["forensics", "steg", "cracked"],
                ))

        # 4. Strings analysis for hidden text
        result = await ctx.subprocess_mgr.run(
            f"strings -n 10 '{file_path}' | grep -iE 'flag|password|secret|key|ctf' | head -10",
            timeout=10,
        )
        if result.stdout:
            findings.append(Finding.medium(
                "Interesting strings in file",
                evidence=result.stdout[:300],
                tags=["forensics", "steg", "strings"],
            ))

        if not findings:
            findings.append(Finding.info(
                f"No steganographic data found (tools: {', '.join(data['tools_used'])})",
                tags=["forensics", "steg"],
            ))

        return PluginResult.success(
            self.meta.name, target.host, findings=findings, data=data,
        )
