"""Vulnerability registry — typed definitions with detection and verification strategies."""

from __future__ import annotations

import logging
import re
from importlib import resources
from typing import Any

import yaml
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class ConfidenceThresholds(BaseModel):
    """Per-category confidence tuning knobs."""

    detection_floor: float = 0.4
    verification_bonus: float = 0.3
    multi_source_bonus: float = 0.15
    false_positive_cap: float = 0.3


class VulnDefinition(BaseModel):
    """A single vulnerability type definition."""

    id: str                                          # "sqli_error", "xss_reflected"
    name: str                                        # "SQL Injection (Error-based)"
    category: str                                    # "sqli", "xss", "ssti", etc.
    cwe_ids: list[str] = Field(default_factory=list)
    owasp_ids: list[str] = Field(default_factory=list)
    severity_range: list[str] = Field(default_factory=list)
    detection_plugins: list[str] = Field(default_factory=list)
    verification_plugins: list[str] = Field(default_factory=list)
    verification_techniques: list[str] = Field(default_factory=list)
    false_positive_indicators: list[str] = Field(default_factory=list)
    confidence_thresholds: ConfidenceThresholds = Field(
        default_factory=ConfidenceThresholds,
    )


class VulnRegistry:
    """Registry of known vulnerability types with detection/verification metadata."""

    def __init__(self, vulns: list[VulnDefinition] | None = None) -> None:
        self._vulns: dict[str, VulnDefinition] = {}
        for v in vulns or []:
            self._vulns[v.id] = v

    @classmethod
    def load_bundled(cls) -> VulnRegistry:
        """Load from definitions.yaml bundled next to this module."""
        pkg = resources.files("basilisk.knowledge.vulns")
        yaml_path = pkg / "definitions.yaml"
        text = yaml_path.read_text(encoding="utf-8")
        raw: list[dict[str, Any]] = yaml.safe_load(text) or []
        vulns = [VulnDefinition(**entry) for entry in raw]
        logger.debug("Loaded %d vulnerability definitions", len(vulns))
        return cls(vulns)

    def __len__(self) -> int:
        return len(self._vulns)

    def get(self, vuln_id: str) -> VulnDefinition | None:
        """Get a vulnerability definition by ID."""
        return self._vulns.get(vuln_id)

    def all(self) -> list[VulnDefinition]:
        """Return all definitions."""
        return list(self._vulns.values())

    def by_category(self, category: str) -> list[VulnDefinition]:
        """Get all definitions for a category (e.g. 'sqli')."""
        return [v for v in self._vulns.values() if v.category == category]

    def detection_plugins_for(self, category: str) -> list[str]:
        """All detection plugins for a given category."""
        plugins: list[str] = []
        seen: set[str] = set()
        for v in self.by_category(category):
            for p in v.detection_plugins:
                if p not in seen:
                    plugins.append(p)
                    seen.add(p)
        return plugins

    def verification_plugins_for(self, category: str) -> list[str]:
        """All verification plugins for a given category."""
        plugins: list[str] = []
        seen: set[str] = set()
        for v in self.by_category(category):
            for p in v.verification_plugins:
                if p not in seen:
                    plugins.append(p)
                    seen.add(p)
        return plugins

    def confidence_thresholds_for(self, category: str) -> ConfidenceThresholds:
        """Aggregate confidence thresholds for a category (first match wins)."""
        for v in self.by_category(category):
            return v.confidence_thresholds
        return ConfidenceThresholds()

    def match_finding(self, title: str, category: str = "") -> VulnDefinition | None:
        """Try to match a finding title/category to a VulnDefinition.

        Matching strategy:
        1. Exact category match — return first definition in that category
        2. Title keyword match — search for category keywords in title
        """
        title_lower = title.lower()

        # Direct category match
        if category:
            matches = self.by_category(category)
            if matches:
                return matches[0]

        # Keyword match: try each vuln definition's category as a keyword
        for v in self._vulns.values():
            cat = v.category.lower()
            # Match category name or common abbreviation in title
            if cat in title_lower or re.search(rf"\b{re.escape(cat)}\b", title_lower):
                return v

        return None

    def categories(self) -> list[str]:
        """All unique categories in the registry."""
        seen: set[str] = set()
        result: list[str] = []
        for v in self._vulns.values():
            if v.category not in seen:
                result.append(v.category)
                seen.add(v.category)
        return result
