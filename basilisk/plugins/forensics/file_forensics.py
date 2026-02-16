"""File forensics — file type detection, metadata, embedded data, carving."""

from __future__ import annotations

import logging
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)


class FileForensicsPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="file_forensics",
        display_name="File Forensics",
        category=PluginCategory.FORENSICS,
        description="File type detection, metadata extraction, embedded data, carving",
        produces=["extracted_data"],
        timeout=60.0,
        requires_http=False,
        risk_level="safe",
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        data: dict = {
            "file_type": "", "metadata": {}, "embedded": [],
            "strings_found": [],
        }

        file_path = target.meta.get("file_path", "")
        if not file_path:
            findings.append(Finding.info(
                "No file provided (set target.meta file_path)",
                tags=["forensics", "file"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        if not ctx.subprocess_mgr:
            findings.append(Finding.info(
                "SubprocessManager not available",
                tags=["forensics", "file"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        # File type detection
        file_result = await ctx.subprocess_mgr.run(
            f"file '{file_path}'", timeout=10,
        )
        if file_result.stdout:
            data["file_type"] = file_result.stdout.strip()
            findings.append(Finding.info(
                f"File type: {data['file_type'][:100]}",
                evidence=data["file_type"],
                tags=["forensics", "file"],
            ))

        # Metadata extraction with exiftool
        exif_avail = await ctx.subprocess_mgr.is_available("exiftool")
        if exif_avail:
            result = await ctx.subprocess_mgr.run(
                f"exiftool '{file_path}'", timeout=15,
            )
            if result.stdout:
                for line in result.stdout.splitlines():
                    if ":" in line:
                        key, _, value = line.partition(":")
                        data["metadata"][key.strip()] = value.strip()
                findings.append(Finding.info(
                    f"Metadata fields: {len(data['metadata'])}",
                    evidence=result.stdout[:500],
                    tags=["forensics", "file", "metadata"],
                ))

                # Check for GPS data
                gps_keys = [k for k in data["metadata"] if "gps" in k.lower()]
                if gps_keys:
                    findings.append(Finding.medium(
                        "GPS coordinates in file metadata",
                        evidence="\n".join(
                            f"{k}: {data['metadata'][k]}" for k in gps_keys
                        ),
                        tags=["forensics", "metadata", "gps"],
                    ))

        # Strings analysis
        strings_avail = await ctx.subprocess_mgr.is_available("strings")
        if strings_avail:
            result = await ctx.subprocess_mgr.run(
                f"strings -n 8 '{file_path}' | head -100", timeout=15,
            )
            if result.stdout:
                lines = result.stdout.strip().splitlines()
                data["strings_found"] = lines[:50]

                # Look for interesting strings
                interesting = [
                    line for line in lines
                    if any(kw in line.lower() for kw in [
                        "password", "secret", "flag", "key", "token",
                        "http://", "https://", "ftp://",
                    ])
                ]
                if interesting:
                    findings.append(Finding.medium(
                        f"Interesting strings: {len(interesting)}",
                        evidence="\n".join(interesting[:15]),
                        tags=["forensics", "file", "strings"],
                    ))

        # Check for embedded files with binwalk
        binwalk_avail = await ctx.subprocess_mgr.is_available("binwalk")
        if binwalk_avail:
            result = await ctx.subprocess_mgr.run(
                f"binwalk '{file_path}'", timeout=15,
            )
            if result.stdout:
                embedded = [
                    ln for ln in result.stdout.splitlines()
                    if ln.strip() and not ln.startswith("DECIMAL")
                    and not ln.startswith("-")
                ]
                data["embedded"] = embedded[:20]
                if len(embedded) > 1:
                    findings.append(Finding.medium(
                        f"Embedded data/files: {len(embedded)}",
                        evidence="\n".join(embedded[:10]),
                        description="Use binwalk -e to extract",
                        tags=["forensics", "file", "embedded"],
                    ))

        return PluginResult.success(
            self.meta.name, target.host, findings=findings, data=data,
        )
