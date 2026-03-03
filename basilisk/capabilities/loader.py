"""Load capability definitions from YAML data files."""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).parent / "data"

_REQUIRED_KEYS = {"requires", "produces", "cost", "noise"}

_cache: dict[str, dict] | None = None


def load_capability_map() -> dict[str, dict]:
    """Load all capability YAML files from data/ directory.

    Results are cached after the first call. Each entry is validated
    to contain required keys (requires, produces, cost, noise).
    """
    global _cache  # noqa: PLW0603
    if _cache is not None:
        return _cache

    result: dict[str, dict] = {}
    if not _DATA_DIR.is_dir():
        logger.warning("Capability data directory not found: %s", _DATA_DIR)
        return result

    for yaml_path in sorted(_DATA_DIR.glob("*.yaml")):
        with open(yaml_path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            logger.warning("Skipping non-dict YAML file: %s", yaml_path.name)
            continue
        for name, entry in data.items():
            missing = _REQUIRED_KEYS - set(entry)
            if missing:
                msg = f"Capability '{name}' in {yaml_path.name} missing keys: {missing}"
                raise ValueError(msg)
            result[name] = entry

    _cache = result
    return result


def reset_cache() -> None:
    """Clear the cached capability map (for testing)."""
    global _cache  # noqa: PLW0603
    _cache = None
