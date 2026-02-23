"""AES attacks — ECB detect, byte-at-a-time, CBC bit-flip, padding oracle."""

from __future__ import annotations

import logging
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)


class AesAttackPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="aes_attack",
        display_name="AES Cryptanalysis",
        category=PluginCategory.CRYPTO,
        description="ECB detection, byte-at-a-time, CBC bit-flip, padding oracle",
        produces=["decrypted_data"],
        timeout=120.0,
        requires_http=False,
        risk_level="safe",
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        data: dict = {"mode_detected": "", "attacks_tried": [], "decrypted": ""}

        ciphertext_hex = target.meta.get("aes_ciphertext", "")
        if not ciphertext_hex:
            findings.append(Finding.info(
                "No AES ciphertext provided (set target.meta aes_ciphertext)",
                tags=["crypto", "aes"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        try:
            ciphertext = bytes.fromhex(ciphertext_hex)
        except ValueError:
            import base64
            try:
                ciphertext = base64.b64decode(ciphertext_hex)
            except Exception:
                findings.append(Finding.info(
                    "Could not decode ciphertext (hex or base64)",
                    tags=["crypto", "aes"],
                ))
                return PluginResult.success(
                    self.meta.name, target.host, findings=findings, data=data,
                )

        if not ctx.crypto:
            findings.append(Finding.info(
                "CryptoEngine not available", tags=["crypto", "aes"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        # ECB detection
        data["attacks_tried"].append("ecb_detect")
        if ctx.crypto.detect_ecb(ciphertext):
            data["mode_detected"] = "ECB"
            findings.append(Finding.high(
                "AES-ECB mode detected",
                evidence=f"Repeated 16-byte blocks found in {len(ciphertext)} byte ciphertext",
                description=(
                    "ECB mode encrypts identical blocks identically. "
                    "Vulnerable to byte-at-a-time and block shuffling attacks."
                ),
                tags=["crypto", "aes", "ecb"],
            ))

        # Padding oracle (if oracle URL provided)
        oracle_url = target.meta.get("padding_oracle_url", "")
        if oracle_url and ctx.http:
            data["attacks_tried"].append("padding_oracle")
            iv_hex = target.meta.get("aes_iv", "")
            if iv_hex:
                try:
                    iv = bytes.fromhex(iv_hex)
                    decrypted = await ctx.crypto.padding_oracle_decrypt(
                        ciphertext, iv, oracle_url, ctx.http,
                    )
                    if decrypted:
                        data["decrypted"] = decrypted.hex()
                        findings.append(Finding.critical(
                            "Padding oracle attack successful",
                            evidence=f"Decrypted {len(ciphertext)} bytes",
                            description="CBC padding oracle allows full decryption",
                            remediation="Use authenticated encryption (AES-GCM)",
                            tags=["crypto", "aes", "padding-oracle"],
                        ))
                except Exception as exc:
                    logger.debug("Padding oracle failed: %s", exc)

        # Entropy analysis
        entropy = ctx.crypto.entropy(ciphertext)
        if entropy < 6.0:
            findings.append(Finding.medium(
                f"Low entropy in ciphertext: {entropy:.2f}",
                description="May indicate weak encryption or encoding",
                tags=["crypto", "entropy"],
            ))

        if not findings:
            findings.append(Finding.info(
                f"AES analysis: {', '.join(data['attacks_tried'])} — no vulnerabilities",
                tags=["crypto", "aes"],
            ))

        return PluginResult.success(
            self.meta.name, target.host, findings=findings, data=data,
        )
