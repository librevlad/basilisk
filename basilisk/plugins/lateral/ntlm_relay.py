"""NTLM relay — check for relay-vulnerable services and coerce authentication."""

from __future__ import annotations

import logging
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)

# Services that can be targets for NTLM relay
RELAY_TARGETS = [
    {"service": "LDAP", "port": 389, "signing": "optional_by_default"},
    {"service": "LDAPS", "port": 636, "signing": "channel_binding"},
    {"service": "SMB", "port": 445, "signing": "required_on_dc"},
    {"service": "HTTP", "port": 80, "signing": "none"},
    {"service": "HTTPS", "port": 443, "signing": "none"},
    {"service": "MSSQL", "port": 1433, "signing": "optional"},
    {"service": "WinRM", "port": 5985, "signing": "optional"},
]

# Coercion methods
COERCION_METHODS = [
    {
        "name": "PetitPotam",
        "tool": "PetitPotam.py",
        "description": "EFS RPC coercion (CVE-2021-36942)",
        "unauthenticated": True,
    },
    {
        "name": "PrinterBug",
        "tool": "printerbug.py",
        "description": "MS-RPRN SpoolService coercion",
        "unauthenticated": False,
    },
    {
        "name": "DFSCoerce",
        "tool": "dfscoerce.py",
        "description": "MS-DFSNM coercion",
        "unauthenticated": True,
    },
    {
        "name": "ShadowCoerce",
        "tool": "shadowcoerce.py",
        "description": "MS-FSRVP coercion",
        "unauthenticated": True,
    },
]


class NtlmRelayPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="ntlm_relay",
        display_name="NTLM Relay Analysis",
        category=PluginCategory.LATERAL,
        description="Check for relay-vulnerable services, SMB signing, coercion methods",
        produces=["lateral_access"],
        timeout=60.0,
        requires_http=False,
        risk_level="noisy",
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        data: dict = {
            "smb_signing": "", "relay_targets": [],
            "coercion_available": [],
        }

        # Check SMB signing
        if ctx.net:
            port_open = await ctx.net.check_port(target.host, 445, timeout=5.0)
            if port_open:
                # Try to detect SMB signing via banner
                await ctx.net.grab_banner(target.host, 445, timeout=5.0)
                data["smb_signing"] = "port_open"

                # Use nmap for signing detection if available
                if ctx.subprocess_mgr:
                    avail = await ctx.subprocess_mgr.is_available("nmap")
                    if avail:
                        result = await ctx.subprocess_mgr.run_nmap(
                            target.host,
                            ports="445",
                            scripts="smb2-security-mode",
                            timeout=15,
                        )
                        if result.stdout:
                            if "not required" in result.stdout.lower():
                                data["smb_signing"] = "not_required"
                                findings.append(Finding.high(
                                    "SMB signing not required — relay possible",
                                    evidence=result.stdout[:500],
                                    description=(
                                        "SMB signing is not enforced. This host can be a "
                                        "target for NTLM relay attacks via SMB."
                                    ),
                                    remediation="Enable SMB signing: RequireSecuritySignature=1",
                                    tags=["lateral", "ntlm-relay", "smb-signing"],
                                ))
                            elif "required" in result.stdout.lower():
                                data["smb_signing"] = "required"
                                findings.append(Finding.info(
                                    "SMB signing required — relay to SMB not possible",
                                    evidence=result.stdout[:300],
                                    tags=["lateral", "smb-signing"],
                                ))

        # Check other relay-target services
        if ctx.net:
            for svc in RELAY_TARGETS:
                if ctx.should_stop:
                    break
                if svc["port"] == 445:
                    continue  # Already checked
                port_open = await ctx.net.check_port(
                    target.host, svc["port"], timeout=3.0,
                )
                if port_open:
                    data["relay_targets"].append(svc)

            if data["relay_targets"]:
                svc_names = [s["service"] for s in data["relay_targets"]]
                findings.append(Finding.medium(
                    f"Potential NTLM relay targets: {', '.join(svc_names)}",
                    evidence="\n".join(
                        f"{s['service']}:{s['port']} (signing: {s['signing']})"
                        for s in data["relay_targets"]
                    ),
                    description="These services may accept relayed NTLM authentication",
                    tags=["lateral", "ntlm-relay"],
                ))

        # Check available coercion tools
        if ctx.subprocess_mgr:
            for method in COERCION_METHODS:
                avail = await ctx.subprocess_mgr.is_available(method["tool"])
                if avail:
                    data["coercion_available"].append(method["name"])

            if data["coercion_available"]:
                findings.append(Finding.info(
                    f"Coercion tools available: {', '.join(data['coercion_available'])}",
                    description="Can force target to authenticate back for relay",
                    tags=["lateral", "ntlm-relay", "coercion"],
                ))

        if not findings:
            findings.append(Finding.info(
                "No NTLM relay opportunities identified",
                tags=["lateral", "ntlm-relay"],
            ))

        return PluginResult.success(
            self.meta.name, target.host, findings=findings, data=data,
        )
