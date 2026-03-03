"""Centralized normalization for entity identity — ensures same real-world
object always maps to the same deterministic ID regardless of input format."""

from __future__ import annotations

import re

_PROTOCOL_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://")


def normalize_host(hostname: str) -> str:
    """Lowercase, strip protocol/trailing slashes/dots/whitespace."""
    h = hostname.strip()
    h = _PROTOCOL_RE.sub("", h)
    h = h.split("/", 1)[0]  # drop path after host
    h = h.rstrip(".")
    return h.lower()


def normalize_path(path: str) -> str:
    """Lowercase, collapse double slashes, strip trailing slash, remove query string."""
    p = path.split("?", 1)[0]
    p = p.split("#", 1)[0]
    while "//" in p:
        p = p.replace("//", "/")
    p = p.rstrip("/") if p != "/" else p
    return p.lower()


def normalize_port(port: int | str) -> int:
    """Ensure int, clamp to valid range."""
    p = int(port)
    return max(1, min(p, 65535))


def normalize_tech_name(name: str) -> str:
    """Lowercase, strip whitespace."""
    return name.strip().lower()
