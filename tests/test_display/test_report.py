"""Tests for report output."""

from __future__ import annotations

from io import StringIO

from rich.console import Console

from basilisk.display.report import print_auto_report, print_training_report
from basilisk.display.state import DisplayState, FindingEntry


class TestPrintAutoReport:
    def test_empty_state(self):
        state = DisplayState(step=10, max_steps=100, total_entities=42, total_relations=15)
        state.termination_reason = "no_gaps"
        out = StringIO()
        console = Console(file=out, force_terminal=True, width=120)
        print_auto_report(state, console)
        output = out.getvalue()
        assert "Audit complete" in output
        assert "no_gaps" in output

    def test_with_findings(self):
        state = DisplayState(
            step=20, max_steps=100,
            total_entities=100, total_relations=50,
            findings=[
                FindingEntry(title="SQL Injection", severity="high", host="10.10.10.5"),
                FindingEntry(title="Missing HSTS", severity="medium", host="10.10.10.5"),
            ],
        )
        out = StringIO()
        console = Console(file=out, force_terminal=True, width=120)
        print_auto_report(state, console)
        output = out.getvalue()
        assert "SQL Injection" in output
        assert "Missing HSTS" in output
        assert "HIGH" in output
        assert "MEDIUM" in output

    def test_more_than_20_findings(self):
        findings = [
            FindingEntry(title=f"Finding {i}", severity="low", host="x")
            for i in range(25)
        ]
        state = DisplayState(findings=findings)
        out = StringIO()
        console = Console(file=out, no_color=True, width=120)
        print_auto_report(state, console)
        output = out.getvalue()
        assert "5 more" in output


class TestPrintTrainingReport:
    def test_passed_report(self):
        from unittest.mock import MagicMock

        report = MagicMock()
        report.profile_name = "dvwa"
        report.coverage = 0.8
        report.verification_rate = 0.6
        report.discovered = 4
        report.total_expected = 5
        report.steps_taken = 30
        report.passed = True
        report.findings_detail = [
            {
                "expected_title": "SQL Injection",
                "expected_severity": "high",
                "category": "injection",
                "discovered": True,
                "verified": True,
                "discovery_step": 5,
            },
            {
                "expected_title": "XSS",
                "expected_severity": "medium",
                "category": "xss",
                "discovered": True,
                "verified": False,
                "discovery_step": 10,
            },
        ]

        out = StringIO()
        console = Console(file=out, force_terminal=True, width=120)
        print_training_report(report, console)
        output = out.getvalue()
        assert "dvwa" in output
        assert "SQL Injection" in output
        assert "PASSED" in output

    def test_failed_report(self):
        from unittest.mock import MagicMock

        report = MagicMock()
        report.profile_name = "test"
        report.coverage = 0.3
        report.verification_rate = 0.0
        report.discovered = 1
        report.total_expected = 5
        report.steps_taken = 50
        report.passed = False
        report.findings_detail = []

        out = StringIO()
        console = Console(file=out, force_terminal=True, width=120)
        print_training_report(report, console)
        output = out.getvalue()
        assert "FAILED" in output
