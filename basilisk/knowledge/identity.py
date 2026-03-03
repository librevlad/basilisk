"""Canonical vulnerability identity — standalone SHA256[:16] hash."""

from __future__ import annotations

import hashlib

from basilisk.knowledge.normalize import normalize_host, normalize_path


def vulnerability_id(target: str, surface: str, vuln_type: str, proof_key: str) -> str:
    """Canonical SHA256[:16] vulnerability identity.

    Normalizes target as hostname, surface as path (if contains /) or
    lowercased string, then hashes the pipe-delimited canonical form.
    """
    norm_target = normalize_host(target)
    norm_surface = normalize_path(surface) if "/" in surface else surface.lower()
    raw = f"{norm_target}|{norm_surface}|{vuln_type}|{proof_key}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]
