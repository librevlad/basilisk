#!/usr/bin/env python3
"""One-time export: dump current Python payload/WAF data to YAML files.

Usage::

    .venv/Scripts/python.exe scripts/export_payloads.py

Creates:
    basilisk/data/payloads/<category>.yaml  (13 files)
    basilisk/data/waf_profiles.yaml
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure project root is on sys.path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import yaml  # noqa: E402

from basilisk.utils.payloads import (  # noqa: E402
    InjectionContext,
    PayloadCategory,
    _get_payload_db,
)
from basilisk.utils.waf_profiles import WAF_PROFILES  # noqa: E402

PAYLOADS_DIR = ROOT / "basilisk" / "data" / "payloads"
WAF_FILE = ROOT / "basilisk" / "data" / "waf_profiles.yaml"


def _category_filename(cat: PayloadCategory) -> str:
    """Map PayloadCategory enum value to YAML filename stem."""
    return cat.value  # e.g. "sqli", "xss", "redirect", "pp", "header"


def _default_context(cat: PayloadCategory) -> str:
    """Infer the most common default context for a category."""
    # Count contexts across payloads in this category
    payloads = _get_payload_db().get(cat, [])
    if not payloads:
        return InjectionContext.QUERY_PARAM.value
    from collections import Counter
    ctx_counts = Counter(p.context.value for p in payloads)
    return ctx_counts.most_common(1)[0][0]


def _default_dbms(cat: PayloadCategory) -> str:
    """Infer the most common default dbms for a category."""
    payloads = _get_payload_db().get(cat, [])
    if not payloads:
        return "generic"
    from collections import Counter
    dbms_counts = Counter(p.dbms.value for p in payloads)
    return dbms_counts.most_common(1)[0][0]


def export_payloads() -> None:
    PAYLOADS_DIR.mkdir(parents=True, exist_ok=True)

    for cat, payloads in _get_payload_db().items():
        if not payloads:
            continue

        fname = _category_filename(cat)
        default_context = _default_context(cat)
        default_dbms = _default_dbms(cat)

        defaults: dict = {
            "context": default_context,
            "dbms": default_dbms,
            "waf_level": 0,
            "blind": False,
            "time_delay": 0.0,
        }

        payload_dicts: list[dict] = []
        for p in payloads:
            d: dict = {"value": p.value}
            # Only include fields that differ from defaults
            if p.context.value != default_context:
                d["context"] = p.context.value
            if p.dbms.value != default_dbms:
                d["dbms"] = p.dbms.value
            if p.waf_level != 0:
                d["waf_level"] = p.waf_level
            if p.blind:
                d["blind"] = True
            if p.time_delay != 0.0:
                d["time_delay"] = p.time_delay
            if p.description:
                d["description"] = p.description
            if p.tags:
                d["tags"] = list(p.tags)
            payload_dicts.append(d)

        data = {"defaults": defaults, "payloads": payload_dicts}

        out_path = PAYLOADS_DIR / f"{fname}.yaml"
        with out_path.open("w", encoding="utf-8") as fh:
            yaml.dump(data, fh, default_flow_style=False, allow_unicode=True,
                      sort_keys=False, width=120)
        print(f"  {out_path.name}: {len(payloads)} payloads")


def export_waf_profiles() -> None:
    profiles: dict[str, dict] = {}
    for name, wp in WAF_PROFILES.items():
        d: dict = {}
        if wp.effective_encodings:
            d["effective_encodings"] = list(wp.effective_encodings)
        if wp.bypass_headers:
            d["bypass_headers"] = dict(wp.bypass_headers)
        if wp.safe_content_types:
            d["safe_content_types"] = list(wp.safe_content_types)
        if wp.safe_methods:
            d["safe_methods"] = list(wp.safe_methods)
        if wp.notes:
            d["notes"] = wp.notes
        profiles[name] = d

    data = {"profiles": profiles}
    with WAF_FILE.open("w", encoding="utf-8") as fh:
        yaml.dump(data, fh, default_flow_style=False, allow_unicode=True,
                  sort_keys=False, width=120)
    print(f"  waf_profiles.yaml: {len(profiles)} profiles")


def main() -> None:
    print("Exporting payloads to YAML...")
    export_payloads()
    print("\nExporting WAF profiles to YAML...")
    export_waf_profiles()
    print("\nDone!")


if __name__ == "__main__":
    main()
