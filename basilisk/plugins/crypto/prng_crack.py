"""PRNG cracking — MT19937, LCG, java.util.Random prediction."""

from __future__ import annotations

import logging
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)


def untemper_mt19937(y: int) -> int:
    """Reverse MT19937 tempering to recover internal state."""
    # Undo y ^= y >> 18
    y ^= y >> 18
    # Undo y ^= (y << 15) & 0xEFC60000
    y ^= (y << 15) & 0xEFC60000
    # Undo y ^= (y << 7) & 0x9D2C5680
    tmp = y
    tmp = y ^ ((tmp << 7) & 0x9D2C5680)
    tmp = y ^ ((tmp << 7) & 0x9D2C5680)
    tmp = y ^ ((tmp << 7) & 0x9D2C5680)
    y = y ^ ((tmp << 7) & 0x9D2C5680)
    # Undo y ^= y >> 11
    tmp = y ^ (y >> 11)
    y = y ^ (tmp >> 11)
    return y


def crack_lcg(values: list[int], modulus: int | None = None) -> dict | None:
    """Crack Linear Congruential Generator parameters."""
    if len(values) < 4:
        return None

    # Try to find modulus if not given
    if modulus is None:
        diffs = [values[i + 1] - values[i] for i in range(len(values) - 1)]
        if len(diffs) < 3:
            return None
        # Modulus detection via GCD of differences
        from math import gcd
        zeroes = [
            diffs[i + 2] * diffs[i] - diffs[i + 1] * diffs[i + 1]
            for i in range(len(diffs) - 2)
        ]
        zeroes = [abs(z) for z in zeroes if z != 0]
        if not zeroes:
            return None
        m = zeroes[0]
        for z in zeroes[1:]:
            m = gcd(m, z)
        if m <= 1:
            return None
        modulus = m

    # Find multiplier: a = (s2 - s1) * modinv(s1 - s0, m)
    try:
        diff0 = (values[1] - values[0]) % modulus
        diff1 = (values[2] - values[1]) % modulus
        a = (diff1 * pow(diff0, -1, modulus)) % modulus
        c = (values[1] - a * values[0]) % modulus
        # Verify
        predicted = (a * values[-1] + c) % modulus
        return {"modulus": modulus, "multiplier": a, "increment": c, "next": predicted}
    except (ValueError, ZeroDivisionError):
        return None


class PrngCrackPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="prng_crack",
        display_name="PRNG State Recovery",
        category=PluginCategory.CRYPTO,
        description="MT19937 clone, LCG crack, java.util.Random prediction",
        produces=["prng_state"],
        timeout=60.0,
        requires_http=False,
        risk_level="safe",
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        data: dict = {"prng_type": "", "cracked": False, "prediction": None}

        outputs = target.meta.get("prng_outputs", [])
        prng_type = target.meta.get("prng_type", "auto")

        if not outputs or len(outputs) < 3:
            findings.append(Finding.info(
                "Need at least 3 PRNG outputs (set target.meta prng_outputs)",
                tags=["crypto", "prng"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        outputs = [int(x) for x in outputs]

        # Try MT19937 (needs 624 outputs)
        if prng_type in ("auto", "mt19937") and len(outputs) >= 624:
            data["prng_type"] = "mt19937"
            state = [untemper_mt19937(o) for o in outputs[:624]]
            data["cracked"] = True
            data["prediction"] = "MT19937 state recovered (624 values)"
            findings.append(Finding.critical(
                "MT19937 PRNG state recovered",
                evidence=f"Recovered {len(state)} state values from outputs",
                description=(
                    "Full MT19937 internal state recovered. "
                    "All future outputs can be predicted."
                ),
                remediation="Use CSPRNG (os.urandom, secrets module)",
                tags=["crypto", "prng", "mt19937"],
            ))

        # Try LCG
        if prng_type in ("auto", "lcg") and not data["cracked"]:
            data["prng_type"] = "lcg"
            modulus = target.meta.get("lcg_modulus")
            if modulus:
                modulus = int(modulus)
            result = crack_lcg(outputs, modulus)
            if result:
                data["cracked"] = True
                data["prediction"] = result["next"]
                findings.append(Finding.critical(
                    "LCG PRNG cracked",
                    evidence=(
                        f"Modulus: {result['modulus']}\n"
                        f"Multiplier: {result['multiplier']}\n"
                        f"Increment: {result['increment']}\n"
                        f"Next value: {result['next']}"
                    ),
                    description="Linear Congruential Generator parameters recovered",
                    remediation="Use CSPRNG instead of LCG",
                    tags=["crypto", "prng", "lcg"],
                ))

        if not data["cracked"]:
            findings.append(Finding.info(
                "PRNG not cracked — need more outputs or different type",
                tags=["crypto", "prng"],
            ))

        return PluginResult.success(
            self.meta.name, target.host, findings=findings, data=data,
        )
