"""Classical cipher analysis — Caesar, Vigenere, substitution, XOR."""

from __future__ import annotations

import logging
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)


class ClassicalCipherPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="classical_cipher",
        display_name="Classical Cipher Analysis",
        category=PluginCategory.CRYPTO,
        description="Caesar, Vigenere, substitution, XOR brute force",
        produces=["decrypted_data"],
        timeout=60.0,
        requires_http=False,
        risk_level="safe",
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        data: dict = {"attacks_tried": [], "results": []}

        ciphertext = target.meta.get("ciphertext", "")
        if not ciphertext:
            findings.append(Finding.info(
                "No ciphertext provided (set target.meta ciphertext)",
                tags=["crypto", "classical"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        if not ctx.crypto:
            findings.append(Finding.info(
                "CryptoEngine not available", tags=["crypto"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        # Frequency analysis
        freq = ctx.crypto.frequency_analysis(ciphertext)
        entropy = ctx.crypto.entropy(ciphertext.encode())
        findings.append(Finding.info(
            f"Text entropy: {entropy:.2f}, top chars: {dict(list(freq.items())[:5])}",
            tags=["crypto", "analysis"],
        ))

        # Caesar brute force
        data["attacks_tried"].append("caesar")
        caesar_results = ctx.crypto.caesar_brute(ciphertext)
        if caesar_results:
            data["results"].append({"type": "caesar", "results": caesar_results[:5]})
            best = caesar_results[0]
            findings.append(Finding.medium(
                f"Caesar shift {best.get('shift', '?')}: {best.get('text', '')[:60]}",
                evidence="\n".join(
                    f"shift={r.get('shift')}: {r.get('text', '')[:50]}"
                    for r in caesar_results[:5]
                ),
                description="Top Caesar decryption candidates by English frequency",
                tags=["crypto", "caesar"],
            ))

        # Vigenere analysis
        if len(ciphertext) > 20:
            data["attacks_tried"].append("vigenere")
            vig_result = ctx.crypto.vigenere_crack(ciphertext)
            if vig_result:
                data["results"].append({"type": "vigenere", "result": vig_result})
                findings.append(Finding.medium(
                    f"Vigenere key candidate: {vig_result.get('key', '?')}",
                    evidence=(
                        f"Key: {vig_result.get('key')}\n"
                        f"Text: {vig_result.get('text', '')[:100]}"
                    ),
                    tags=["crypto", "vigenere"],
                ))

        # XOR single-byte
        if all(c in "0123456789abcdefABCDEF" for c in ciphertext.replace(" ", "")):
            data["attacks_tried"].append("xor_single_byte")
            try:
                ct_bytes = bytes.fromhex(ciphertext.replace(" ", ""))
                xor_results = ctx.crypto.xor_single_byte_crack(ct_bytes)
                if xor_results:
                    data["results"].append({"type": "xor", "results": xor_results[:3]})
                    best = xor_results[0]
                    findings.append(Finding.medium(
                        f"XOR key 0x{best.get('key', 0):02x}: {best.get('text', '')[:60]}",
                        evidence="\n".join(
                            f"key=0x{r.get('key', 0):02x}: {r.get('text', '')[:50]}"
                            for r in xor_results[:3]
                        ),
                        tags=["crypto", "xor"],
                    ))
            except ValueError:
                pass

        return PluginResult.success(
            self.meta.name, target.host, findings=findings, data=data,
        )
