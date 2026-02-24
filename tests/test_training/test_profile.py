"""Tests for training profile models."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest

from basilisk.training.profile import ExpectedFinding, TrainingProfile


class TestExpectedFinding:
    def test_defaults(self):
        ef = ExpectedFinding(title="SQLi", severity="critical")
        assert ef.title == "SQLi"
        assert ef.severity == "critical"
        assert ef.category == ""
        assert ef.plugin_hints == []
        assert ef.verification_required is True

    def test_all_fields(self):
        ef = ExpectedFinding(
            title="XSS Reflected",
            severity="high",
            category="xss",
            plugin_hints=["xss_basic", "xss_advanced"],
            verification_required=False,
        )
        assert ef.category == "xss"
        assert ef.plugin_hints == ["xss_basic", "xss_advanced"]
        assert ef.verification_required is False


class TestTrainingProfile:
    def test_minimal_profile(self):
        tp = TrainingProfile(
            name="test",
            target="localhost:80",
            expected_findings=[
                ExpectedFinding(title="SQLi", severity="critical"),
            ],
        )
        assert tp.name == "test"
        assert tp.target == "localhost:80"
        assert tp.max_steps == 200
        assert tp.required_coverage == 1.0
        assert tp.target_ports == []
        assert len(tp.expected_findings) == 1

    def test_load_from_yaml(self, tmp_path: Path):
        yaml_content = dedent("""\
            name: test_app
            description: "Test application"
            target: "localhost:8080"
            target_ports: [8080]
            max_steps: 100
            required_coverage: 0.9
            expected_findings:
              - title: "SQL Injection"
                severity: "critical"
                category: "sqli"
                plugin_hints: ["sqli_basic"]
              - title: "XSS Reflected"
                severity: "high"
                category: "xss"
        """)
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text(yaml_content, encoding="utf-8")

        tp = TrainingProfile.load(yaml_file)
        assert tp.name == "test_app"
        assert tp.description == "Test application"
        assert tp.target == "localhost:8080"
        assert tp.target_ports == [8080]
        assert tp.max_steps == 100
        assert tp.required_coverage == 0.9
        assert len(tp.expected_findings) == 2
        assert tp.expected_findings[0].title == "SQL Injection"
        assert tp.expected_findings[0].plugin_hints == ["sqli_basic"]
        assert tp.expected_findings[1].category == "xss"

    def test_load_invalid_yaml_raises(self, tmp_path: Path):
        yaml_file = tmp_path / "bad.yaml"
        yaml_file.write_text("name: 123\ntarget: 456\n", encoding="utf-8")
        with pytest.raises((ValueError, TypeError)):
            TrainingProfile.load(yaml_file)

    def test_load_missing_file_raises(self, tmp_path: Path):
        with pytest.raises((FileNotFoundError, OSError)):
            TrainingProfile.load(tmp_path / "nonexistent.yaml")
