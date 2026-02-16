"""Memory analysis — process list, strings, passwords, registry from memory dumps."""

from __future__ import annotations

import logging
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)

# Volatility3 plugins to run
VOL3_PLUGINS = [
    {"name": "windows.info", "description": "OS version and profile"},
    {"name": "windows.pslist", "description": "Process list"},
    {"name": "windows.pstree", "description": "Process tree"},
    {"name": "windows.cmdline", "description": "Command line arguments"},
    {"name": "windows.netscan", "description": "Network connections"},
    {"name": "windows.hashdump", "description": "SAM password hashes"},
    {"name": "windows.lsadump", "description": "LSA secrets"},
    {"name": "windows.filescan", "description": "File objects in memory"},
    {"name": "windows.registry.hivelist", "description": "Registry hives"},
]


class MemoryAnalyzePlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="memory_analyze",
        display_name="Memory Dump Analysis",
        category=PluginCategory.FORENSICS,
        description="Process list, strings, passwords, registry from memory dumps",
        produces=["credentials", "processes"],
        timeout=300.0,
        requires_http=False,
        risk_level="safe",
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        data: dict = {
            "os_info": "", "processes": [], "connections": [],
            "hashes": [], "secrets": [],
        }

        dump_path = target.meta.get("memory_dump", "")
        if not dump_path:
            findings.append(Finding.info(
                "No memory dump provided (set target.meta memory_dump)",
                tags=["forensics", "memory"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        if not ctx.subprocess_mgr:
            findings.append(Finding.info(
                "SubprocessManager not available",
                tags=["forensics", "memory"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        # Check for volatility3
        vol_avail = await ctx.subprocess_mgr.is_available("vol")
        vol3_avail = await ctx.subprocess_mgr.is_available("vol3")
        vol_cmd = "vol3" if vol3_avail else "vol" if vol_avail else None

        if not vol_cmd:
            # Fallback: basic strings analysis
            strings_avail = await ctx.subprocess_mgr.is_available("strings")
            if strings_avail:
                result = await ctx.subprocess_mgr.run(
                    f"strings -n 8 '{dump_path}' | grep -iE "
                    "'password|passwd|secret|token|admin' | head -50",
                    timeout=60,
                )
                if result.stdout:
                    findings.append(Finding.medium(
                        "Interesting strings found in memory dump",
                        evidence=result.stdout[:500],
                        tags=["forensics", "memory", "strings"],
                    ))

            findings.append(Finding.info(
                "Volatility not available — install for full analysis",
                tags=["forensics", "memory"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        # Run volatility plugins
        for plugin in VOL3_PLUGINS:
            if ctx.should_stop:
                break

            cmd = f"{vol_cmd} -f '{dump_path}' {plugin['name']}"
            result = await ctx.subprocess_mgr.run(cmd, timeout=60)

            if result.returncode != 0 or not result.stdout:
                continue

            output = result.stdout

            if plugin["name"] == "windows.info":
                data["os_info"] = output[:500]
                findings.append(Finding.info(
                    "Memory dump OS identified",
                    evidence=output[:300],
                    tags=["forensics", "memory"],
                ))

            elif plugin["name"] == "windows.pslist":
                data["processes"] = output.strip().splitlines()[:50]
                findings.append(Finding.info(
                    f"Processes: {len(data['processes'])}",
                    evidence=output[:500],
                    tags=["forensics", "memory", "process"],
                ))

            elif plugin["name"] == "windows.netscan":
                data["connections"] = output.strip().splitlines()[:30]
                findings.append(Finding.info(
                    "Network connections from memory",
                    evidence=output[:500],
                    tags=["forensics", "memory", "network"],
                ))

            elif plugin["name"] == "windows.hashdump":
                if ":::" in output:
                    hashes = [
                        ln for ln in output.splitlines() if ":::" in ln
                    ]
                    data["hashes"] = hashes
                    findings.append(Finding.critical(
                        f"Password hashes from memory: {len(hashes)}",
                        evidence="\n".join(hashes[:10]),
                        tags=["forensics", "memory", "credential"],
                    ))
                    if ctx.creds:
                        for h in hashes:
                            parts = h.split(":")
                            if len(parts) >= 4:
                                ctx.creds.add(
                                    username=parts[0],
                                    secret=parts[3],
                                    secret_type="ntlm_hash",
                                    source="memory_dump",
                                    target=target.host,
                                )

            elif plugin["name"] == "windows.lsadump":
                data["secrets"] = output.strip().splitlines()[:20]
                findings.append(Finding.high(
                    "LSA secrets from memory",
                    evidence=output[:500],
                    tags=["forensics", "memory", "lsa"],
                ))

        return PluginResult.success(
            self.meta.name, target.host, findings=findings, data=data,
        )
