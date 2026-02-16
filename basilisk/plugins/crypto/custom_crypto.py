"""Custom crypto analysis — frequency, entropy, known-plaintext, encoding detection."""

from __future__ import annotations

import base64
import logging
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)

# Common encodings to try
ENCODINGS = [
    ("base64", lambda s: base64.b64decode(s).decode("utf-8", errors="replace")),
    ("base32", lambda s: base64.b32decode(s).decode("utf-8", errors="replace")),
    ("hex", lambda s: bytes.fromhex(s).decode("utf-8", errors="replace")),
    ("rot13", lambda s: s.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
    ))),
    ("base85", lambda s: base64.b85decode(s).decode("utf-8", errors="replace")),
]


class CustomCryptoPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="custom_crypto",
        display_name="Custom Crypto Analysis",
        category=PluginCategory.CRYPTO,
        description="Frequency analysis, entropy, encoding detection, known-plaintext",
        produces=["decrypted_data"],
        timeout=30.0,
        requires_http=False,
        risk_level="safe",
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        data: dict = {"encodings_found": [], "entropy": 0.0, "frequency": {}}

        text = target.meta.get("ciphertext", "") or target.meta.get("encoded_text", "")
        if not text:
            findings.append(Finding.info(
                "No text provided (set target.meta ciphertext or encoded_text)",
                tags=["crypto", "analysis"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        # Entropy analysis
        if ctx.crypto:
            entropy = ctx.crypto.entropy(text.encode())
            data["entropy"] = round(entropy, 3)
            freq = ctx.crypto.frequency_analysis(text)
            data["frequency"] = dict(list(freq.items())[:10])

            findings.append(Finding.info(
                f"Entropy: {entropy:.3f} bits/byte",
                evidence=(
                    f"Entropy: {entropy:.3f}\n"
                    f"Length: {len(text)}\n"
                    f"Top chars: {dict(list(freq.items())[:5])}"
                ),
                description=(
                    "7.5-8.0 = encrypted/compressed, "
                    "4.0-6.0 = English text, "
                    "<4.0 = repetitive/simple encoding"
                ),
                tags=["crypto", "entropy"],
            ))

        # Try common encodings
        for enc_name, decode_fn in ENCODINGS:
            try:
                decoded = decode_fn(text.strip())
                if decoded and len(decoded) > 3 and decoded.isprintable():
                    data["encodings_found"].append({
                        "encoding": enc_name,
                        "decoded": decoded[:200],
                    })
                    findings.append(Finding.medium(
                        f"Encoding detected: {enc_name}",
                        evidence=f"Decoded: {decoded[:200]}",
                        tags=["crypto", "encoding", enc_name],
                    ))
            except Exception:
                continue

        # Multi-layer decoding
        current = text.strip()
        layers = []
        for _ in range(5):  # Max 5 layers
            decoded = False
            for enc_name, decode_fn in ENCODINGS:
                try:
                    result = decode_fn(current)
                    if (
                        result
                        and result != current
                        and len(result) > 3
                        and result.isprintable()
                    ):
                        layers.append(enc_name)
                        current = result
                        decoded = True
                        break
                except Exception:
                    continue
            if not decoded:
                break

        if len(layers) > 1:
            findings.append(Finding.high(
                f"Multi-layer encoding: {' → '.join(layers)}",
                evidence=f"Final decoded: {current[:200]}",
                tags=["crypto", "encoding", "multi-layer"],
            ))

        return PluginResult.success(
            self.meta.name, target.host, findings=findings, data=data,
        )
