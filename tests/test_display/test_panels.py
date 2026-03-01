"""Tests for panel renderers."""

from __future__ import annotations

import time

from rich.panel import Panel

from basilisk.display.panels import (
    activity_panel,
    findings_panel,
    header_panel,
    hypothesis_panel,
    knowledge_panel,
)
from basilisk.display.state import DisplayState, FindingEntry, PluginActivity


class TestHeaderPanel:
    def test_returns_panel(self):
        state = DisplayState(step=5, max_steps=50)
        result = header_panel(state)
        assert isinstance(result, Panel)

    def test_title_contains_basilisk(self):
        state = DisplayState()
        result = header_panel(state)
        assert "Basilisk" in str(result.title)


class TestActivityPanel:
    def test_empty_state(self):
        state = DisplayState()
        result = activity_panel(state)
        assert isinstance(result, Panel)

    def test_with_active_plugins(self):
        state = DisplayState(active_plugins=[
            PluginActivity(name="sqli_basic", target="10.10.10.5", started_at=time.monotonic()),
        ])
        result = activity_panel(state)
        assert isinstance(result, Panel)

    def test_with_recent_plugins(self):
        state = DisplayState(recent_plugins=[
            PluginActivity(
                name="tech_detect", target="10.10.10.5",
                started_at=time.monotonic() - 1.2, finished=True,
                duration=1.2, findings_count=2,
            ),
        ])
        result = activity_panel(state)
        assert isinstance(result, Panel)


class TestFindingsPanel:
    def test_empty(self):
        state = DisplayState()
        result = findings_panel(state)
        assert isinstance(result, Panel)

    def test_with_findings(self):
        state = DisplayState(findings=[
            FindingEntry(title="SQL Injection", severity="high", host="10.10.10.5"),
            FindingEntry(title="Missing HSTS", severity="medium", host="10.10.10.5"),
        ])
        result = findings_panel(state)
        assert isinstance(result, Panel)


class TestKnowledgePanel:
    def test_returns_panel(self):
        state = DisplayState(
            total_entities=42,
            total_relations=15,
            entity_counts={"host": 2, "service": 5, "endpoint": 10,
                           "technology": 3, "credential": 0, "finding": 4,
                           "vulnerability": 1, "container": 0, "image": 0},
        )
        result = knowledge_panel(state)
        assert isinstance(result, Panel)


class TestHypothesisPanel:
    def test_returns_panel(self):
        state = DisplayState(
            hypotheses_active=3, hypotheses_confirmed=1, hypotheses_rejected=2,
            beliefs_strengthened=5, beliefs_weakened=1,
        )
        result = hypothesis_panel(state)
        assert isinstance(result, Panel)
