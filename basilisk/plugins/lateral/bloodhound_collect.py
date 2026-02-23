"""BloodHound data collection — users, groups, sessions, ACLs for graph analysis."""

from __future__ import annotations

import logging
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)


class BloodHoundCollectPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="bloodhound_collect",
        display_name="BloodHound Collection",
        category=PluginCategory.LATERAL,
        description="Collect AD objects: users, groups, sessions, ACLs for BloodHound",
        depends_on=["ldap_enum"],
        produces=["ad_graph"],
        timeout=120.0,
        requires_http=False,
        requires_credentials=True,
        risk_level="noisy",
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        data: dict = {
            "users": 0, "groups": 0, "computers": 0,
            "sessions": 0, "acls": 0, "collection_method": "",
        }

        domain = target.meta.get("ad_domain", "")
        dc_ip = target.meta.get("dc_ip", target.host)

        if not domain:
            findings.append(Finding.info(
                "No AD domain configured for BloodHound",
                tags=["lateral", "bloodhound"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        # Method 1: LDAP-based collection (lightweight)
        if ctx.ldap:
            try:
                users = await ctx.ldap.get_users()
                groups = await ctx.ldap.get_groups()
                computers = await ctx.ldap.get_computers()
                domain_admins = await ctx.ldap.get_domain_admins()

                data["users"] = len(users)
                data["groups"] = len(groups)
                data["computers"] = len(computers)
                data["collection_method"] = "ldap"

                findings.append(Finding.info(
                    f"AD enumerated: {len(users)} users, {len(groups)} groups, "
                    f"{len(computers)} computers",
                    evidence=(
                        f"Users: {len(users)}\n"
                        f"Groups: {len(groups)}\n"
                        f"Computers: {len(computers)}\n"
                        f"Domain Admins: {len(domain_admins)}"
                    ),
                    tags=["lateral", "bloodhound", "ad"],
                ))

                if domain_admins:
                    findings.append(Finding.high(
                        f"Domain Admins: {len(domain_admins)}",
                        evidence="\n".join(
                            str(da.get("sAMAccountName", ""))
                            for da in domain_admins[:20]
                        ),
                        tags=["lateral", "bloodhound", "domain-admin"],
                    ))

            except Exception as exc:
                logger.debug("LDAP collection failed: %s", exc)

        # Method 2: bloodhound-python (comprehensive)
        if ctx.subprocess_mgr and not data["collection_method"]:
            cred = None
            if ctx.creds:
                creds_list = ctx.creds.get_for_target(target.host)
                if creds_list:
                    cred = creds_list[0]

            if cred:
                cmd = (
                    f"bloodhound-python -u {cred.username} -p '{cred.secret}' "
                    f"-d {domain} -dc {dc_ip} -c All --zip"
                )
                result = await ctx.subprocess_mgr.run(cmd, timeout=60)
                if result.returncode == 0:
                    data["collection_method"] = "bloodhound-python"
                    findings.append(Finding.info(
                        "BloodHound data collected via bloodhound-python",
                        evidence=result.stdout[:500] if result.stdout else "",
                        description="Import ZIP into BloodHound for graph analysis",
                        tags=["lateral", "bloodhound"],
                    ))

        if not data["collection_method"]:
            findings.append(Finding.info(
                "BloodHound collection requires LDAP access or credentials",
                tags=["lateral", "bloodhound"],
            ))

        return PluginResult.success(
            self.meta.name, target.host, findings=findings, data=data,
        )
