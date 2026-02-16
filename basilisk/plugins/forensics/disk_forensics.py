"""Disk forensics — partitions, deleted files, timeline analysis."""

from __future__ import annotations

import logging
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)


class DiskForensicsPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="disk_forensics",
        display_name="Disk Forensics",
        category=PluginCategory.FORENSICS,
        description="Partition analysis, deleted files, file carving, timeline",
        produces=["extracted_files"],
        timeout=120.0,
        requires_http=False,
        risk_level="safe",
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        data: dict = {
            "partitions": [], "deleted_files": [],
            "carved_files": [], "timeline": [],
        }

        disk_image = target.meta.get("disk_image", "")
        if not disk_image:
            findings.append(Finding.info(
                "No disk image provided (set target.meta disk_image)",
                tags=["forensics", "disk"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        if not ctx.subprocess_mgr:
            findings.append(Finding.info(
                "SubprocessManager not available",
                tags=["forensics", "disk"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        # Partition table analysis
        mmls_avail = await ctx.subprocess_mgr.is_available("mmls")
        if mmls_avail:
            result = await ctx.subprocess_mgr.run(
                f"mmls '{disk_image}'", timeout=15,
            )
            if result.stdout:
                data["partitions"] = result.stdout.strip().splitlines()
                findings.append(Finding.info(
                    "Partition table analyzed",
                    evidence=result.stdout[:500],
                    tags=["forensics", "disk", "partition"],
                ))

        # File system analysis with fls (Sleuth Kit)
        fls_avail = await ctx.subprocess_mgr.is_available("fls")
        if fls_avail:
            offset = target.meta.get("partition_offset", "0")
            result = await ctx.subprocess_mgr.run(
                f"fls -r -d -o {offset} '{disk_image}' | head -50",
                timeout=30,
            )
            if result.stdout:
                deleted = result.stdout.strip().splitlines()
                data["deleted_files"] = deleted[:50]
                if deleted:
                    findings.append(Finding.medium(
                        f"Deleted files found: {len(deleted)}",
                        evidence="\n".join(deleted[:15]),
                        description="Recover with: icat -o <offset> image <inode>",
                        tags=["forensics", "disk", "deleted"],
                    ))

        # File carving with foremost/scalpel
        for carver in ("foremost", "scalpel"):
            carver_avail = await ctx.subprocess_mgr.is_available(carver)
            if carver_avail:
                result = await ctx.subprocess_mgr.run(
                    f"{carver} -i '{disk_image}' -o /tmp/carved_{carver} -T 2>&1",
                    timeout=60,
                )
                if result.returncode == 0:
                    # Check what was carved
                    ls_result = await ctx.subprocess_mgr.run(
                        f"find /tmp/carved_{carver} -type f | head -30",
                        timeout=10,
                    )
                    if ls_result.stdout:
                        carved = ls_result.stdout.strip().splitlines()
                        data["carved_files"] = carved[:30]
                        findings.append(Finding.medium(
                            f"Carved files ({carver}): {len(carved)}",
                            evidence="\n".join(carved[:10]),
                            tags=["forensics", "disk", "carving"],
                        ))
                break

        # Timeline with fls
        if fls_avail:
            offset = target.meta.get("partition_offset", "0")
            result = await ctx.subprocess_mgr.run(
                f"fls -r -m / -o {offset} '{disk_image}' | head -50",
                timeout=30,
            )
            if result.stdout:
                data["timeline"] = result.stdout.strip().splitlines()[:50]

        if not findings:
            findings.append(Finding.info(
                "Install Sleuth Kit (fls, mmls, icat) for full disk forensics",
                tags=["forensics", "disk"],
            ))

        return PluginResult.success(
            self.meta.name, target.host, findings=findings, data=data,
        )
