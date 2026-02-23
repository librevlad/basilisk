"""Hash cracking — identify and crack MD5, SHA, bcrypt, NTLM, NetNTLMv2."""

from __future__ import annotations

import logging
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)


class HashCrackPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="hash_crack",
        display_name="Hash Identification & Cracking",
        category=PluginCategory.CRYPTO,
        description="Identify and crack: MD5, SHA, bcrypt, NTLM, NetNTLMv2",
        produces=["credentials"],
        timeout=120.0,
        requires_http=False,
        risk_level="safe",
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        data: dict = {"hashes": [], "cracked": [], "identified": []}

        # Get hashes from credential store or target meta
        hashes_to_crack: list[str] = []

        if ctx.creds:
            for cred in ctx.creds.get_by_type("ntlm_hash"):
                hashes_to_crack.append(cred.secret)
            for cred in ctx.creds.get_by_type("password_hash"):
                hashes_to_crack.append(cred.secret)

        # Also check target meta for hashes
        if target.meta.get("hashes"):
            hashes_to_crack.extend(target.meta["hashes"])

        if not hashes_to_crack:
            findings.append(Finding.info(
                "No hashes available for cracking",
                tags=["crypto", "hash"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        data["hashes"] = hashes_to_crack[:100]

        # Identify hash types
        if ctx.crypto:
            for h in hashes_to_crack[:50]:
                hash_type = ctx.crypto.identify_hash(h)
                data["identified"].append({"hash": h[:20] + "...", "type": hash_type})

        # Try to crack with built-in engine
        if ctx.crypto:
            for h in hashes_to_crack[:20]:
                if ctx.should_stop:
                    break
                result = ctx.crypto.crack_hash(h)
                if result and result.cracked:
                    data["cracked"].append({
                        "hash": h[:20] + "...",
                        "password": result.password,
                        "type": result.hash_type,
                    })

                    # Store cracked password
                    if ctx.creds:
                        ctx.creds.add(
                            username="",
                            secret=result.password,
                            secret_type="password",
                            source="hash_crack",
                            target=target.host,
                        )

        # Try external tools (hashcat/john)
        if ctx.subprocess_mgr and not data["cracked"]:
            # Try john
            avail = await ctx.subprocess_mgr.is_available("john")
            if avail:
                result = await ctx.subprocess_mgr.run_john(
                    hashes_to_crack[:20], timeout=60,
                )
                if result.stdout:
                    for line in result.stdout.splitlines():
                        if ":" in line and "(" in line:
                            data["cracked"].append({"line": line.strip()})

        if data["cracked"]:
            findings.append(Finding.critical(
                f"Hashes cracked: {len(data['cracked'])}",
                evidence="\n".join(
                    f"{c.get('type', '?')}: {c.get('password', c.get('line', ''))}"
                    for c in data["cracked"][:10]
                ),
                description="Weak passwords found via hash cracking",
                remediation="Enforce strong password policy",
                tags=["crypto", "hash", "cracked"],
            ))
        else:
            findings.append(Finding.info(
                f"Identified {len(data['identified'])} hashes, none cracked",
                evidence="\n".join(
                    f"{i['type']}: {i['hash']}" for i in data["identified"][:10]
                ),
                tags=["crypto", "hash"],
            ))

        return PluginResult.success(
            self.meta.name, target.host, findings=findings, data=data,
        )
