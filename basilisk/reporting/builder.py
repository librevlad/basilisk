"""ReportBuilder — constructs canonical ReportModel from ScanSession.

Entity data (findings, topology, counts) comes from the KnowledgeGraph.
Execution metadata (decisions, plugins, steps, reasoning) comes from the session.
"""

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
    from basilisk.core.session import ScanSession
    from basilisk.knowledge.graph import KnowledgeGraph

# Kill chain phases — single source of truth
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

# Deterministic severity sort order
_SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4,
}


class ReportBuilder:
    """Build frozen ReportModel from ScanSession.

    Entity data from KnowledgeGraph (source of truth).
    Execution metadata from ScanSession.
    All collections sorted for deterministic output.
    """

    @classmethod
    def from_session(
        cls, session: ScanSession, *, scan_id: str = "",
    ) -> ReportModel:
        """Build frozen ReportModel from ScanSession."""
        scan_id = scan_id or session.scan_id

        # KG-derived data
        findings_raw = cls._findings_from_graph(session.graph)
        topology = cls._topology_from_graph(session.graph)
        entity_counts = cls._entity_counts_from_graph(session.graph)

        # Session-derived data
        decisions = cls._decisions_from_session(session)
        plugins_raw = cls._plugins_from_session(session)
        step_history = cls._steps_from_session(session)
        reasoning = cls._reasoning_from_session(session)
        timeline = cls._timeline_from_session(session)
        training = cls._training_from_session(session)

        # Aggregation
        vulnerabilities = VulnerabilityAggregator.aggregate(findings_raw, session.target)

        # Statistics
        statistics = cls._compute_statistics(
            session, entity_counts, findings_raw, plugins_raw,
        )

        # Deterministic sorting
        vulnerabilities = sorted(vulnerabilities, key=lambda v: v.vulnerability_id)
        findings_raw = sorted(findings_raw, key=lambda f: (
            _SEVERITY_ORDER.get(f.get("severity", "INFO"), 99),
            f.get("title", ""),
            f.get("host", ""),
        ))
        topology = dict(sorted(topology.items()))
        decisions = sorted(decisions, key=lambda d: (d.get("step", 0), d.get("plugin", "")))
        plugins_raw = sorted(plugins_raw, key=lambda p: (p.get("step", 0), p.get("name", "")))
        timeline = sorted(timeline, key=lambda t: t.timestamp)

        now = datetime.now(UTC)
        return ReportModel(
            scan_id=scan_id,
            target=session.target,
            mode=session.mode,
            status=session.status,
            started_at=session.started_at,
            finished_at=now if session.status == "completed" else None,
            termination_reason=session.termination_reason,
            statistics=statistics,
            vulnerabilities=vulnerabilities,
            execution_timeline=timeline,
            training=training,
            findings_raw=findings_raw,
            decisions=decisions,
            plugins_raw=plugins_raw,
            step_history=step_history,
            reasoning=reasoning,
            topology=topology,
        )

    # ------------------------------------------------------------------
    # KG-derived helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _findings_from_graph(graph: KnowledgeGraph) -> list[dict[str, Any]]:
        """Extract findings from KG entities. Uses entity.confidence (merged)."""
        return [
            {
                "title": e.data.get("title", ""),
                "severity": e.data.get("severity", "info").upper(),
                "host": e.data.get("host", ""),
                "evidence": (
                    e.data.get("evidence", "")
                    or (e.evidence[0] if e.evidence else "")
                ),
                "description": e.data.get("description", ""),
                "tags": e.data.get("tags", []),
                "confidence": e.confidence,
                "verified": e.data.get("verified", False),
                "false_positive_risk": e.data.get("false_positive_risk", "low"),
                "remediation": e.data.get("remediation", ""),
                "step": e.data.get("step", 0),
            }
            for e in graph.findings()
        ]

    @staticmethod
    def _topology_from_graph(graph: KnowledgeGraph) -> dict[str, Any]:
        """Traverse KG relations to build per-host topology."""
        from basilisk.knowledge.relations import RelationType

        result: dict[str, Any] = {}
        for host_entity in graph.hosts():
            host = host_entity.data.get("host", host_entity.id)
            services: list[dict[str, Any]] = []
            endpoints: list[str] = []
            technologies: list[dict[str, str]] = []

            for svc in graph.neighbors(host_entity.id, RelationType.EXPOSES):
                services.append({
                    "port": svc.data.get("port", 0),
                    "protocol": svc.data.get("protocol", "tcp"),
                    "service": svc.data.get("service", ""),
                })
                for ep in graph.neighbors(svc.id, RelationType.HAS_ENDPOINT):
                    path = ep.data.get("path", "")
                    if path and path not in endpoints:
                        endpoints.append(path)
                for tech in graph.neighbors(svc.id, RelationType.RUNS):
                    technologies.append({
                        "name": tech.data.get("name", ""),
                        "version": tech.data.get("version", ""),
                    })

            result[host] = {
                "services": sorted(services, key=lambda s: s.get("port", 0)),
                "endpoints": sorted(endpoints),
                "technologies": technologies,
                "is_subdomain": host_entity.data.get("type") == "subdomain",
                "parent": host_entity.data.get("parent", ""),
            }
        return result

    @staticmethod
    def _entity_counts_from_graph(graph: KnowledgeGraph) -> dict[str, int]:
        """Count entities by type from the graph."""
        from basilisk.knowledge.entities import EntityType

        return {
            etype.value: len(graph.query(etype))
            for etype in EntityType
        }

    # ------------------------------------------------------------------
    # Session-derived helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _decisions_from_session(session: ScanSession) -> list[dict[str, Any]]:
        """Convert session decisions to serializable dicts."""
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
            for d in session.decisions
        ]

    @staticmethod
    def _plugins_from_session(session: ScanSession) -> list[dict[str, Any]]:
        """Convert session plugin records to serializable dicts."""
        return [
            {
                "name": p.name,
                "target": p.target,
                "duration": round(p.duration, 2),
                "findings_count": p.findings_count,
                "step": p.step,
            }
            for p in session.plugins
        ]

    @staticmethod
    def _steps_from_session(session: ScanSession) -> list[dict[str, Any]]:
        """Convert step history to serializable dicts."""
        return [
            {
                "step": s.step,
                "entities": s.entities,
                "relations": s.relations,
                "gaps": s.gaps,
                "entities_gained": s.entities_gained,
            }
            for s in session.step_history
        ]

    @staticmethod
    def _reasoning_from_session(session: ScanSession) -> dict[str, Any]:
        """Build reasoning summary dict."""
        return {
            "hypotheses_confirmed": session.hypotheses_confirmed,
            "hypotheses_rejected": session.hypotheses_rejected,
            "beliefs_strengthened": session.beliefs_strengthened,
            "beliefs_weakened": session.beliefs_weakened,
            "events": [
                {
                    "type": r.event_type,
                    "data": r.data,
                    "step": r.step,
                }
                for r in session.reasoning_events
            ],
        }

    @staticmethod
    def _timeline_from_session(session: ScanSession) -> list[TimelineEvent]:
        """Convert session timeline events to TimelineEvent models."""
        return [
            TimelineEvent(
                timestamp=te.timestamp,
                scenario=te.scenario,
                action=te.event_type.value,
                result=dict(te.data),
                step=te.step,
            )
            for te in session.timeline_events
        ]

    @staticmethod
    def _training_from_session(session: ScanSession) -> TrainingSection | None:
        """Build training section from session's training data."""
        if session.training_data is None:
            return None
        t = session.training_data
        expected = t.get("expected_findings", [])
        missed = [
            {"title": ef["title"], "severity": ef["severity"]}
            for ef in expected if not ef.get("discovered", False)
        ]
        all_expected = [dict(ef) for ef in expected]
        detected = sum(1 for ef in expected if ef.get("discovered", False))
        return TrainingSection(
            profile_name=t.get("profile_name", ""),
            expected_total=len(expected),
            detected=detected,
            missed=missed,
            false_positives=all_expected,
            coverage_percent=round(t.get("coverage", 0.0) * 100, 1),
            verification_rate=round(t.get("verification_rate", 0.0) * 100, 1),
            passed=t.get("passed", False),
        )

    @staticmethod
    def _compute_statistics(
        session: ScanSession,
        entity_counts: dict[str, int],
        findings_raw: list[dict[str, Any]],
        plugins_raw: list[dict[str, Any]],
    ) -> ReportStatistics:
        """Compute all statistics once. Renderers never recompute."""
        severity_counts: dict[str, int] = {}
        for f in findings_raw:
            sev = f.get("severity", "INFO")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        risk_score = _compute_risk_score(findings_raw)
        kill_chain = _compute_kill_chain({p.get("name", "") for p in plugins_raw})

        return ReportStatistics(
            scenarios_executed=len(plugins_raw),
            requests_sent=0,
            findings_total=len(findings_raw),
            steps_completed=session.step,
            max_steps=session.max_steps,
            duration_seconds=round(session.elapsed, 1),
            severity_counts=severity_counts,
            risk_score=round(risk_score, 1),
            total_entities=session.graph.entity_count,
            total_relations=session.graph.relation_count,
            total_gaps=session.gap_count,
            entity_counts=entity_counts,
            kill_chain_coverage=kill_chain,
        )

    @staticmethod
    def _make_scan_id(target: str, started_at: float) -> str:
        """Deterministic scan ID from target + start time."""
        raw = f"{target}:{started_at}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _compute_risk_score(findings: list[dict[str, Any]]) -> float:
    """Weighted severity sum, capped at 10."""
    total = sum(
        _SEVERITY_WEIGHTS.get(f.get("severity", "INFO"), 0.0)
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
