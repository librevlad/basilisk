"""Hash length extension attack — MD5, SHA-1, SHA-256."""

from __future__ import annotations

import logging
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)


class HashExtensionPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="hash_extension",
        display_name="Hash Length Extension",
        category=PluginCategory.CRYPTO,
        description="Length extension attacks on MD5, SHA-1, SHA-256",
        produces=["forged_signature"],
        timeout=30.0,
        requires_http=False,
        risk_level="safe",
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        data: dict = {"vulnerable_hash": "", "forged": False}

        original_hash = target.meta.get("hash_value", "")
        original_data = target.meta.get("hash_data", "")
        append_data = target.meta.get("hash_append", "")
        key_length_range = target.meta.get("key_length_range", (8, 32))

        if not original_hash or not original_data:
            findings.append(Finding.info(
                "No hash parameters (set hash_value, hash_data, hash_append)",
                tags=["crypto", "hash-extension"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        # Identify hash type by length
        hash_type = ""
        if len(original_hash) == 32:
            hash_type = "MD5"
        elif len(original_hash) == 40:
            hash_type = "SHA-1"
        elif len(original_hash) == 64:
            hash_type = "SHA-256"
        else:
            findings.append(Finding.info(
                f"Unknown hash type (length {len(original_hash)})",
                tags=["crypto", "hash-extension"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        data["vulnerable_hash"] = hash_type

        # Hash length extension requires hlextend or manual implementation
        if ctx.subprocess_mgr:
            avail = await ctx.subprocess_mgr.is_available("hash_extender")
            if avail and append_data:
                min_len, max_len = key_length_range
                for key_len in range(min_len, max_len + 1):
                    if ctx.should_stop:
                        break
                    cmd = (
                        f"hash_extender --data '{original_data}' "
                        f"--secret {key_len} --append '{append_data}' "
                        f"--signature {original_hash} "
                        f"--format {hash_type.lower().replace('-', '')}"
                    )
                    result = await ctx.subprocess_mgr.run(cmd, timeout=5)
                    if result.returncode == 0 and result.stdout:
                        data["forged"] = True
                        findings.append(Finding.critical(
                            f"Hash length extension ({hash_type}, key_len={key_len})",
                            evidence=result.stdout[:500],
                            description=(
                                f"{hash_type} is vulnerable to length extension. "
                                "Use HMAC instead of hash(secret || message)."
                            ),
                            remediation=f"Use HMAC-{hash_type} instead of {hash_type}(secret+data)",
                            tags=["crypto", "hash-extension"],
                        ))
                        break

        if not data["forged"]:
            findings.append(Finding.medium(
                f"{hash_type} may be vulnerable to length extension",
                description=(
                    f"If the application uses {hash_type}(secret || data), "
                    "it's vulnerable to length extension attacks. "
                    "Install hash_extender for automated exploitation."
                ),
                tags=["crypto", "hash-extension"],
            ))

        return PluginResult.success(
            self.meta.name, target.host, findings=findings, data=data,
        )
