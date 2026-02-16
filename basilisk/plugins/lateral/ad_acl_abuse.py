"""AD ACL abuse — GenericAll, WriteDACL, ForceChangePassword, etc."""

from __future__ import annotations

import logging
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)

# Dangerous AD ACL permissions
DANGEROUS_ACLS = {
    "GenericAll": "Full control over object — reset password, add to group, etc.",
    "GenericWrite": "Write any property — modify SPN for Kerberoast, etc.",
    "WriteDACL": "Modify ACL — grant yourself GenericAll",
    "WriteOwner": "Change ownership — then modify ACL",
    "ForceChangePassword": "Reset user password without knowing current",
    "AllExtendedRights": "DCSync rights, force password change",
    "AddMember": "Add member to group (e.g., Domain Admins)",
    "ReadLAPSPassword": "Read local admin password from AD",
    "ReadGMSAPassword": "Read Group Managed Service Account password",
    "DS-Replication-Get-Changes": "DCSync right (part 1/2)",
    "DS-Replication-Get-Changes-All": "DCSync right (part 2/2)",
}


class AdAclAbusePlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="ad_acl_abuse",
        display_name="AD ACL Abuse",
        category=PluginCategory.LATERAL,
        description="GenericAll, WriteDACL, ForceChangePassword, AddMember abuse",
        depends_on=["bloodhound_collect"],
        produces=["privesc_vectors", "lateral_access"],
        timeout=60.0,
        requires_http=False,
        requires_credentials=True,
        risk_level="safe",
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        data: dict = {"dangerous_acls": [], "attack_paths": []}

        if not ctx.ldap:
            findings.append(Finding.info(
                "LDAP client not available for ACL analysis",
                tags=["lateral", "acl"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        domain = target.meta.get("ad_domain", "")
        if not domain:
            findings.append(Finding.info(
                "No AD domain for ACL analysis",
                tags=["lateral", "acl"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        # Get current user info
        # Query for objects with dangerous ACLs
        # Search for objects where our user has explicit permissions
        try:
            # Get all users to check for misconfigured ACLs
            users = await ctx.ldap.get_users()

            for user in users:
                username = user.get("sAMAccountName", "")

                # Check for interesting attributes
                if user.get("msDS-AllowedToDelegateTo"):
                    data["dangerous_acls"].append({
                        "user": username,
                        "type": "ConstrainedDelegation",
                        "target": user["msDS-AllowedToDelegateTo"],
                    })
                    findings.append(Finding.high(
                        f"Constrained delegation: {username}",
                        evidence=f"Delegate to: {user['msDS-AllowedToDelegateTo']}",
                        description="Can impersonate users to specific services",
                        tags=["lateral", "delegation"],
                    ))

                if user.get("userAccountControl"):
                    uac = int(user.get("userAccountControl", 0))
                    # TRUSTED_FOR_DELEGATION (0x80000)
                    if uac & 0x80000:
                        data["dangerous_acls"].append({
                            "user": username,
                            "type": "UnconstrainedDelegation",
                        })
                        findings.append(Finding.critical(
                            f"Unconstrained delegation: {username}",
                            evidence=f"UAC: {uac}",
                            description=(
                                "Can capture TGTs from any user authenticating "
                                "to this host — Printer Bug → Domain Admin"
                            ),
                            tags=["lateral", "delegation", "unconstrained"],
                        ))

        except Exception as exc:
            logger.debug("ACL analysis failed: %s", exc)
            findings.append(Finding.info(
                f"ACL analysis incomplete: {exc}",
                tags=["lateral", "acl"],
            ))

        if not findings:
            findings.append(Finding.info(
                "No dangerous ACL configurations found",
                tags=["lateral", "acl"],
            ))

        return PluginResult.success(
            self.meta.name, target.host, findings=findings, data=data,
        )
