"""WAF vendor fingerprint database — profiles with known bypass strategies.

Each WafProfile describes a WAF vendor's known weaknesses: which encoding
techniques tend to bypass its rules, which headers may skip inspection, etc.

Used by :class:`basilisk.utils.waf_bypass.WafBypassEngine` to select
encoding strategies based on detected WAF type.

Profile data is loaded from ``basilisk/data/waf_profiles.yaml``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from basilisk.data.loader import load_waf_profiles


@dataclass(frozen=True)
class WafProfile:
    """WAF vendor profile with known bypass strategies."""
    name: str
    # Encoding techniques that tend to work against this WAF
    effective_encodings: tuple[str, ...] = ()
    # Headers that might bypass inspection
    bypass_headers: dict[str, str] = field(default_factory=dict)
    # Content-types that avoid body inspection
    safe_content_types: tuple[str, ...] = ()
    # Methods that bypass inspection
    safe_methods: tuple[str, ...] = ()
    # Known weaknesses
    notes: str = ""


def _build_waf_profiles() -> dict[str, WafProfile]:
    """Load WAF profiles from YAML and construct dict[str, WafProfile]."""
    raw = load_waf_profiles()
    profiles: dict[str, WafProfile] = {}
    for name, data in raw.items():
        profiles[name] = WafProfile(
            name=name,
            effective_encodings=tuple(data.get("effective_encodings", ())),
            bypass_headers=dict(data.get("bypass_headers", {})),
            safe_content_types=tuple(data.get("safe_content_types", ())),
            safe_methods=tuple(data.get("safe_methods", ())),
            notes=data.get("notes", ""),
        )
    return profiles


WAF_PROFILES: dict[str, WafProfile] = _build_waf_profiles()
