"""Noise filtering and URL helpers for report generation."""

from __future__ import annotations

import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Noise filtering
# ---------------------------------------------------------------------------
NOISE_PATTERNS = (
    "no ", "not detected", "not found", "not vulnerable",
    "not reachable", "host not", "no issues",
    "connection refused", "timed out", "no response",
    "host unreachable", "dns resolution failed",
    "paths checked", "hosts checked",
)


def is_noise(finding: dict) -> bool:
    """Check if a finding is informational noise."""
    if finding["severity"] != "INFO":
        return False
    title = finding["title"].lower()
    return any(p in title for p in NOISE_PATTERNS)


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------
def url_to_path(url: str, host: str) -> str | None:
    """Extract the path component from a URL, ignoring external hosts."""
    if url.startswith("/"):
        return url.split("?")[0].split("#")[0]
    try:
        parsed = urlparse(url)
        if parsed.hostname and parsed.hostname != host and not parsed.hostname.endswith(
            f".{host}",
        ):
            return None
        return parsed.path or "/"
    except Exception as e:
        logger.debug("url_to_path failed for %r: %s", url, e)
        return None
