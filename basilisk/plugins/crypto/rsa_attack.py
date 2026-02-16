"""RSA attacks — small e, Wiener, Fermat, Hastad, common factor, LSB oracle."""

from __future__ import annotations

import logging
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)


class RsaAttackPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="rsa_attack",
        display_name="RSA Cryptanalysis",
        category=PluginCategory.CRYPTO,
        description="Small e, Wiener, Fermat, common factor, Hastad broadcast",
        produces=["decrypted_data"],
        timeout=120.0,
        requires_http=False,
        risk_level="safe",
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        data: dict = {"attacks_tried": [], "successful": [], "decrypted": ""}

        # Get RSA parameters from target meta
        n = target.meta.get("rsa_n")
        e = target.meta.get("rsa_e")
        c = target.meta.get("rsa_c")

        if not n or not e:
            findings.append(Finding.info(
                "No RSA parameters provided (set target.meta rsa_n, rsa_e, rsa_c)",
                tags=["crypto", "rsa"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        n = int(n)
        e = int(e)
        if c:
            c = int(c)

        if not ctx.crypto:
            findings.append(Finding.info(
                "CryptoEngine not available",
                tags=["crypto", "rsa"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        # Attack 1: Small e (e=3 and small message)
        if e <= 17:
            data["attacks_tried"].append("small_e")
            result = ctx.crypto.small_e_attack(n, e, c)
            if result and result.decrypted:
                data["successful"].append("small_e")
                data["decrypted"] = result.decrypted
                findings.append(Finding.critical(
                    f"RSA broken via small e attack (e={e})",
                    evidence=f"Decrypted: {result.decrypted[:200]}",
                    tags=["crypto", "rsa", "small-e"],
                ))

        # Attack 2: Wiener (large e / small d)
        if not data["decrypted"]:
            data["attacks_tried"].append("wiener")
            result = ctx.crypto.wiener_attack(n, e)
            if result and result.d:
                data["successful"].append("wiener")
                findings.append(Finding.critical(
                    "RSA broken via Wiener's attack",
                    evidence=f"Private key d found (d has {result.d.bit_length()} bits)",
                    tags=["crypto", "rsa", "wiener"],
                ))
                if c:
                    plaintext = ctx.crypto.rsa_decrypt(c, result.d, n)
                    if plaintext:
                        data["decrypted"] = plaintext
                        findings.append(Finding.critical(
                            "Ciphertext decrypted",
                            evidence=f"Plaintext: {plaintext[:200]}",
                            tags=["crypto", "rsa"],
                        ))

        # Attack 3: Fermat factorization (p and q close together)
        if not data["decrypted"]:
            data["attacks_tried"].append("fermat")
            result = ctx.crypto.fermat_factor(n, max_iterations=100000)
            if result and result.p and result.q:
                data["successful"].append("fermat")
                findings.append(Finding.critical(
                    "RSA n factored via Fermat's method",
                    evidence=f"p = {str(result.p)[:50]}...\nq = {str(result.q)[:50]}...",
                    tags=["crypto", "rsa", "fermat"],
                ))
                if c:
                    d = ctx.crypto.rsa_private_key(result.p, result.q, e)
                    if d:
                        plaintext = ctx.crypto.rsa_decrypt(c, d, n)
                        if plaintext:
                            data["decrypted"] = plaintext

        # Attack 4: Common factor (multiple moduli)
        other_n_values = target.meta.get("rsa_other_n", [])
        if other_n_values and not data["decrypted"]:
            data["attacks_tried"].append("common_factor")
            for other_n in other_n_values:
                result = ctx.crypto.common_factor_attack(n, int(other_n))
                if result and result.p:
                    data["successful"].append("common_factor")
                    findings.append(Finding.critical(
                        "RSA broken via common factor",
                        evidence="Shared prime factor found between moduli",
                        tags=["crypto", "rsa", "common-factor"],
                    ))
                    break

        if not data["successful"]:
            findings.append(Finding.info(
                f"RSA attacks attempted: {', '.join(data['attacks_tried'])} — none successful",
                tags=["crypto", "rsa"],
            ))

        return PluginResult.success(
            self.meta.name, target.host, findings=findings, data=data,
        )
