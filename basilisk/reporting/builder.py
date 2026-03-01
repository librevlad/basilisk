"""ReportBuilder — constructs canonical ReportModel from collector state."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from basilisk.reporting.aggregator import VulnerabilityAggregator
from basilisk.reporting.model import (
    ReportModel,
    ReportStatistics,
    TimelineEvent,
    TrainingSection,
)

if TYPE_CHECKING:
    from basilisk.reporting.collector import ReportCollector
    from basilisk.training.validator import FindingTracker, ValidationReport

# Kill chain phases — single source of truth (moved from renderer)
KILL_CHAIN_PHASES: list[tuple[str, list[str]]] = [
    ("Recon", [
        "dns_enum", "subdomain_enum", "whois_lookup", "port_scan",
        "ssl_check", "certificate_transparency", "dns_zone_transfer",
        "cloud_enum",
    ]),
    ("Mapping", [
        "web_crawler", "sitemap_parser", "tech_fingerprint",
        "cms_detection", "waf_detection", "api_discovery",
        "form_analyzer", "directory_bruteforce", "vhost_discovery",
        "container_discovery", "container_enumeration",
    ]),
    ("Exploit", [
        "sqli_basic", "xss_scanner", "command_injection", "lfi_rfi",
        "ssrf_scanner", "xxe_scanner", "ssti_scanner",
        "nosqli_scanner", "ldap_injection", "csrf_scanner",
        "cors_check", "open_redirect", "parameter_pollution",
        "http_method_test", "crlf_injection",
        "deserialization_scanner", "graphql_scanner",
        "prototype_pollution", "web_cache_poisoning",
    ]),
    ("Privesc", [
        "container_escape_probe", "privilege_escalation",
        "lateral_movement", "credential_bruteforce",
        "session_analysis", "jwt_analyzer",
    ]),
    ("Verify", [
        "finding_confirmer", "finding_revalidator",
        "container_verification",
    ]),
]

# Risk score weights by severity
_SEVERITY_WEIGHTS: dict[str, float] = {
    "CRITICAL": 4.0,
    "HIGH": 2.5,
    "MEDIUM": 1.0,
    "LOW": 0.3,
    "INFO": 0.0,
}


class ReportBuilder:
    """Build frozen ReportModel from mutable collector state.

    All business logic lives here. Renderers receive a fully-computed model.
    """

    @classmethod
    def from_collector(
        cls, collector: ReportCollector, *, scan_id: str = "",
    ) -> ReportModel:
        """Build frozen ReportModel from mutable collector state."""
        if not scan_id:
            scan_id = cls._make_scan_id(collector.target, collector.started_at)

        statistics = cls._compute_statistics(collector)
        vulnerabilities = VulnerabilityAggregator.aggregate(
            cls._findings_as_dicts(collector), collector.target,
        )
        timeline = cls._build_timeline(collector)
        findings_raw = cls._findings_as_dicts(collector)
        decisions = cls._decisions_as_dicts(collector)
        plugins_raw = cls._plugins_as_dicts(collector)
        step_history = cls._step_history_as_dicts(collector)
        reasoning = cls._reasoning_as_dict(collector)

        # Handle legacy training dict from collector
        training = cls._build_training_from_collector(collector)

        now = datetime.now(UTC)
        return ReportModel(
            scan_id=scan_id,
            target=collector.target,
            mode=collector.mode,
            status=collector.status,
            started_at=now,
            finished_at=now if collector.status == "completed" else None,
            termination_reason=collector.termination_reason,
            statistics=statistics,
            vulnerabilities=vulnerabilities,
            execution_timeline=timeline,
            training=training,
            findings_raw=findings_raw,
            decisions=decisions,
            plugins_raw=plugins_raw,
            step_history=step_history,
            reasoning=reasoning,
        )

    @staticmethod
    def _make_scan_id(target: str, started_at: float) -> str:
        """Deterministic scan ID from target + start time."""
        raw = f"{target}:{started_at}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @staticmethod
    def _compute_statistics(collector: ReportCollector) -> ReportStatistics:
        """All stats computed ONCE here. Renderers never recompute."""
        severity_counts = collector.severity_counts
        risk_score = _compute_risk_score_from_findings(collector.findings)
        kill_chain = _compute_kill_chain({p.name for p in collector.plugins})

        return ReportStatistics(
            scenarios_executed=len(collector.plugins),
            requests_sent=0,
            findings_total=len(collector.findings),
            steps_completed=collector.step,
            max_steps=collector.max_steps,
            duration_seconds=round(collector.elapsed, 1),
            severity_counts=severity_counts,
            risk_score=round(risk_score, 1),
            total_entities=collector.total_entities,
            total_relations=collector.total_relations,
            total_gaps=collector.gap_count,
            entity_counts=dict(collector.entity_counts),
            kill_chain_coverage=kill_chain,
        )

    @staticmethod
    def _build_timeline(collector: ReportCollector) -> list[TimelineEvent]:
        """Build timeline from collector's accumulated events."""
        events: list[TimelineEvent] = []
        for te in collector.timeline_events:
            events.append(TimelineEvent(
                timestamp=datetime.fromisoformat(te["timestamp"]),
                scenario=te.get("scenario", ""),
                action=te.get("action", ""),
                result=te.get("result", {}),
            ))
        return events

    @staticmethod
    def _findings_as_dicts(collector: ReportCollector) -> list[dict[str, Any]]:
        """Convert findings to dicts for aggregator and raw output."""
        return [
            {
                "title": f.title,
                "severity": f.severity.upper(),
                "host": f.host,
                "evidence": f.evidence,
                "description": f.description,
                "tags": f.tags,
                "confidence": f.confidence,
                "verified": f.verified,
                "step": f.step,
            }
            for f in collector.findings
        ]

    @staticmethod
    def _decisions_as_dicts(collector: ReportCollector) -> list[dict[str, Any]]:
        """Convert decisions to serializable dicts."""
        return [
            {
                "step": d.step,
                "plugin": d.plugin,
                "target": d.target,
                "score": round(d.score, 3),
                "reasoning": d.reasoning,
                "productive": d.productive,
                "duration": round(d.duration, 2),
                "new_entities": d.new_entities,
            }
            for d in collector.decisions
        ]

    @staticmethod
    def _step_history_as_dicts(collector: ReportCollector) -> list[dict[str, Any]]:
        """Convert step history to serializable dicts."""
        return [
            {
                "step": s.step,
                "entities": s.entities,
                "relations": s.relations,
                "gaps": s.gaps,
                "entities_gained": s.entities_gained,
            }
            for s in collector.step_history
        ]

    @staticmethod
    def _plugins_as_dicts(collector: ReportCollector) -> list[dict[str, Any]]:
        """Convert plugins to serializable dicts."""
        return [
            {
                "name": p.name,
                "target": p.target,
                "duration": round(p.duration, 2),
                "findings_count": p.findings_count,
                "step": p.step,
            }
            for p in collector.plugins
        ]

    @staticmethod
    def _build_training_from_collector(
        collector: ReportCollector,
    ) -> TrainingSection | None:
        """Build training section from collector's legacy training dict."""
        if collector.training is None:
            return None
        t = collector.training
        expected = t.get("expected_findings", [])
        missed = [
            {"title": ef["title"], "severity": ef["severity"]}
            for ef in expected if not ef.get("discovered", False)
        ]
        # Preserve full expected_findings for renderer reconstruction
        all_expected = [dict(ef) for ef in expected]
        detected = sum(1 for ef in expected if ef.get("discovered", False))
        return TrainingSection(
            profile_name=t.get("profile_name", ""),
            expected_total=len(expected),
            detected=detected,
            missed=missed,
            false_positives=all_expected,  # Reuse for full detail pass-through
            coverage_percent=round(t.get("coverage", 0.0) * 100, 1),
            verification_rate=round(t.get("verification_rate", 0.0) * 100, 1),
            passed=t.get("passed", False),
        )

    @staticmethod
    def _reasoning_as_dict(collector: ReportCollector) -> dict[str, Any]:
        """Build reasoning summary dict."""
        return {
            "hypotheses_confirmed": collector.hypotheses_confirmed,
            "hypotheses_rejected": collector.hypotheses_rejected,
            "beliefs_strengthened": collector.beliefs_strengthened,
            "beliefs_weakened": collector.beliefs_weakened,
            "events": [
                {
                    "type": r.event_type,
                    "data": r.data,
                    "step": r.step,
                }
                for r in collector.reasoning_events
            ],
        }


class TrainingReportBuilder(ReportBuilder):
    """Build ReportModel with training section."""

    @classmethod
    def from_training(
        cls,
        collector: ReportCollector,
        report: ValidationReport,
        tracker: FindingTracker,
        *,
        scan_id: str = "",
    ) -> ReportModel:
        """Build ReportModel with training section.

        Training comparison happens HERE, not in renderer.
        """
        base = cls.from_collector(collector, scan_id=scan_id)

        missed = [
            {"title": t.expected.title, "severity": t.expected.severity}
            for t in tracker.tracked if not t.discovered
        ]
        # Build full expected_findings for renderer reconstruction
        all_expected: list[dict[str, Any]] = []
        for t in tracker.tracked:
            all_expected.append({
                "title": t.expected.title,
                "severity": t.expected.severity,
                "discovered": t.discovered,
                "verified": getattr(t, "verified", False),
                "discovery_step": getattr(t, "discovery_step", None),
            })

        training_section = TrainingSection(
            profile_name=report.profile_name,
            expected_total=len(tracker.tracked),
            detected=sum(1 for t in tracker.tracked if t.discovered),
            missed=missed,
            false_positives=all_expected,
            coverage_percent=round(report.coverage * 100, 1),
            verification_rate=round(report.verification_rate * 100, 1),
            passed=report.passed,
        )

        return base.model_copy(update={"training": training_section})


def _compute_risk_score_from_findings(findings: list) -> float:
    """Weighted severity sum, capped at 10."""
    total = sum(
        _SEVERITY_WEIGHTS.get(f.severity.upper(), 0.0)
        for f in findings
    )
    return min(total, 10.0)


def _compute_kill_chain(plugin_names: set[str]) -> dict[str, int]:
    """Classify plugins into kill chain phases."""
    coverage: dict[str, int] = {}
    for phase_name, phase_plugins in KILL_CHAIN_PHASES:
        count = sum(1 for p in phase_plugins if p in plugin_names)
        coverage[phase_name] = count
    return coverage
