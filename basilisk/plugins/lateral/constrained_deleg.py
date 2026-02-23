"""Constrained/unconstrained delegation exploitation."""

from __future__ import annotations

import logging
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)


class ConstrainedDelegPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="constrained_deleg",
        display_name="Delegation Exploitation",
        category=PluginCategory.LATERAL,
        description="Constrained, unconstrained, resource-based delegation abuse",
        depends_on=["ldap_enum"],
        produces=["lateral_access"],
        timeout=60.0,
        requires_http=False,
        requires_credentials=True,
        risk_level="noisy",
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        data: dict = {
            "unconstrained": [], "constrained": [],
            "rbcd": [],
        }

        if not ctx.ldap:
            findings.append(Finding.info(
                "LDAP not available for delegation analysis",
                tags=["lateral", "delegation"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        try:
            # Find unconstrained delegation
            unconstrained = await ctx.ldap.search(
                search_filter=(
                    "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)"
                    "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
                ),
                attributes=["sAMAccountName", "dNSHostName", "userAccountControl"],
            )
            for obj in unconstrained:
                name = obj.get("sAMAccountName", "")
                # Skip domain controllers (expected to have unconstrained)
                if name.endswith("$"):
                    host = obj.get("dNSHostName", "")
                    data["unconstrained"].append({
                        "account": name, "host": host,
                    })

            if data["unconstrained"]:
                findings.append(Finding.critical(
                    f"Unconstrained delegation: {len(data['unconstrained'])} hosts",
                    evidence="\n".join(
                        f"{d['account']} ({d['host']})"
                        for d in data["unconstrained"][:10]
                    ),
                    description=(
                        "These hosts cache TGTs of authenticating users. "
                        "Compromise one + Printer Bug → capture DC TGT → "
                        "Domain Admin"
                    ),
                    remediation="Remove unconstrained delegation, use constrained or RBCD",
                    tags=["lateral", "delegation", "unconstrained"],
                ))

            # Find constrained delegation
            constrained = await ctx.ldap.search(
                search_filter="(msDS-AllowedToDelegateTo=*)",
                attributes=[
                    "sAMAccountName", "msDS-AllowedToDelegateTo",
                    "userAccountControl",
                ],
            )
            for obj in constrained:
                name = obj.get("sAMAccountName", "")
                targets = obj.get("msDS-AllowedToDelegateTo", [])
                if isinstance(targets, str):
                    targets = [targets]
                uac = int(obj.get("userAccountControl", 0))
                # Check TRUSTED_TO_AUTH_FOR_DELEGATION (protocol transition)
                protocol_transition = bool(uac & 0x1000000)

                data["constrained"].append({
                    "account": name,
                    "targets": targets,
                    "protocol_transition": protocol_transition,
                })

            if data["constrained"]:
                evidence_lines = []
                for d in data["constrained"][:10]:
                    pt = " [S4U2Self]" if d["protocol_transition"] else ""
                    targets_str = ", ".join(d["targets"][:3])
                    evidence_lines.append(
                        f"{d['account']}{pt} → {targets_str}"
                    )
                findings.append(Finding.high(
                    f"Constrained delegation: {len(data['constrained'])} accounts",
                    evidence="\n".join(evidence_lines),
                    description=(
                        "Accounts can impersonate users to specific services. "
                        "With protocol transition (S4U2Self), can impersonate "
                        "without user interaction."
                    ),
                    tags=["lateral", "delegation", "constrained"],
                ))

            # Find RBCD (resource-based constrained delegation)
            rbcd = await ctx.ldap.search(
                search_filter="(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
                attributes=[
                    "sAMAccountName",
                    "msDS-AllowedToActOnBehalfOfOtherIdentity",
                ],
            )
            for obj in rbcd:
                name = obj.get("sAMAccountName", "")
                data["rbcd"].append({"account": name})

            if data["rbcd"]:
                findings.append(Finding.high(
                    f"Resource-based constrained delegation: {len(data['rbcd'])}",
                    evidence="\n".join(
                        d["account"] for d in data["rbcd"][:10]
                    ),
                    description=(
                        "RBCD configured — if you can modify this attribute, "
                        "you can impersonate any user to these services"
                    ),
                    tags=["lateral", "delegation", "rbcd"],
                ))

        except Exception as exc:
            logger.debug("Delegation analysis failed: %s", exc)
            findings.append(Finding.info(
                f"Delegation analysis incomplete: {exc}",
                tags=["lateral", "delegation"],
            ))

        if not findings:
            findings.append(Finding.info(
                "No delegation vulnerabilities found",
                tags=["lateral", "delegation"],
            ))

        return PluginResult.success(
            self.meta.name, target.host, findings=findings, data=data,
        )
