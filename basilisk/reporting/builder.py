"""ReportBuilder — constructs canonical ReportModel from ScanSession.

Entity data (findings, topology, counts) comes from the KnowledgeGraph.
Execution metadata (decisions, plugins, steps, reasoning) comes from the session.
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from basilisk.reporting.aggregator import VulnerabilityAggregator
from basilisk.reporting.model import (
    ReasoningSection,
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

        # Visualization hints — pre-computed aggregates for renderer purity
        viz_hints = cls._compute_viz_hints(
            findings_raw, topology, plugins_raw, decisions, step_history,
        )

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
            viz_hints=viz_hints,
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
                "technologies": sorted(
                    technologies, key=lambda t: (t.get("name", ""), t.get("version", "")),
                ),
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
        """Serialize full Decision objects when available, else summary."""
        if session.full_decisions:
            result = []
            for d in session.full_decisions:
                entry: dict[str, Any] = {
                    "id": d.id,
                    "step": d.step,
                    "goal": d.goal,
                    "goal_description": d.goal_description,
                    "goal_priority": round(d.goal_priority, 3),
                    "chosen_plugin": d.chosen_plugin,
                    "chosen_target": d.chosen_target,
                    "chosen_score": round(d.chosen_score, 3),
                    "reasoning_trace": d.reasoning_trace,
                    "action_type": d.action_type,
                    "context": d.context.model_dump(),
                    "evaluated_options": [
                        opt.model_dump() for opt in d.evaluated_options
                    ],
                    "hypothesis_text": d.hypothesis_text,
                    "expected_entity_types": d.expected_entity_types,
                    "observed_entity_types": d.observed_entity_types,
                    "outcome_observations": d.outcome_observations,
                    "outcome_new_entities": d.outcome_new_entities,
                    "outcome_confidence_delta": round(d.outcome_confidence_delta, 4),
                    "outcome_duration": round(d.outcome_duration, 2),
                    "was_productive": d.was_productive,
                }
                result.append(entry)
            return result
        # Fallback: summary decisions from events
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
    def _reasoning_from_session(session: ScanSession) -> ReasoningSection:
        """Build structured ReasoningSection from session."""
        from basilisk.reporting.model import ReportReasoningEvent

        return ReasoningSection(
            hypotheses_confirmed=session.hypotheses_confirmed,
            hypotheses_rejected=session.hypotheses_rejected,
            beliefs_strengthened=session.beliefs_strengthened,
            beliefs_weakened=session.beliefs_weakened,
            events=[
                ReportReasoningEvent(
                    event_type=r.event_type, step=r.step, data=r.data,
                )
                for r in session.reasoning_events
            ],
        )

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
    def _compute_viz_hints(
        findings_raw: list[dict[str, Any]],
        topology: dict[str, Any],
        plugins_raw: list[dict[str, Any]],
        decisions: list[dict[str, Any]],
        step_history: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Pre-compute all aggregates that renderers need. Pure function."""
        sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

        # --- findings ---
        host_counts: dict[str, int] = {}
        for f in findings_raw:
            h = f.get("host", "unknown")
            host_counts[h] = host_counts.get(h, 0) + 1
        top_hosts = sorted(host_counts.items(), key=lambda x: x[1], reverse=True)[:5]

        step_sevs: dict[int, list[str]] = {}
        for f in findings_raw:
            fs = f.get("step", 0)
            step_sevs.setdefault(fs, []).append(f.get("severity", "INFO").upper())
        cum_count = 0
        cumulative_by_step: list[dict[str, Any]] = []
        for st in sorted(step_sevs.keys()):
            sevs = step_sevs[st]
            cum_count += len(sevs)
            dom = max(sevs, key=lambda s: sev_rank.get(s, 0))
            cumulative_by_step.append({"step": st, "cum_count": cum_count, "severity": dom})

        # --- kg_growth ---
        gains = [s.get("entities_gained", 0) for s in step_history]
        peak_gain = max(gains) if gains else 0
        peak_step = gains.index(peak_gain) if gains else 0
        sat_step: int | None = None
        if peak_gain > 0:
            threshold = peak_gain * 0.05
            for si in range(peak_step + 1, len(gains)):
                if gains[si] < threshold:
                    sat_step = si
                    break

        # --- attack_surface ---
        findings_hosts = {f.get("host", "") for f in findings_raw}
        root_count = 0
        subdomain_count = 0
        examined_count = 0
        for host_name, topo in topology.items():
            if topo.get("is_subdomain", False):
                subdomain_count += 1
            else:
                root_count += 1
            if bool(topo.get("services")) or host_name in findings_hosts:
                examined_count += 1
        total_hosts = root_count + subdomain_count
        examined_pct = round(examined_count / total_hosts * 100, 1) if total_hosts > 0 else 0.0

        # --- network_map ---
        total_services = sum(len(t.get("services", [])) for t in topology.values())
        total_endpoints = sum(len(t.get("endpoints", [])) for t in topology.values())
        total_techs = sum(len(t.get("technologies", [])) for t in topology.values())

        proto_groups_map: dict[str, int] = {}
        _pg = {
            "http": "HTTP", "https": "HTTPS",
            "ssh": "SSH", "ftp": "FTP",
            "mysql": "DB", "postgres": "DB", "postgresql": "DB", "redis": "DB",
        }
        for topo_entry in topology.values():
            for svc in topo_entry.get("services", []):
                svc_name = str(svc.get("service", "")).lower().strip()
                group = _pg.get(svc_name, "Other")
                proto_groups_map[group] = proto_groups_map.get(group, 0) + 1
        protocol_groups = sorted(proto_groups_map.items(), key=lambda x: -x[1])

        findings_by_host: dict[str, int] = {}
        severity_by_host: dict[str, str] = {}
        for f in findings_raw:
            h = f.get("host", "")
            if h:
                findings_by_host[h] = findings_by_host.get(h, 0) + 1
                cur = severity_by_host.get(h, "INFO")
                new = f.get("severity", "INFO").upper()
                if sev_rank.get(new, 0) > sev_rank.get(cur, 0):
                    severity_by_host[h] = new

        # --- plugin_perf ---
        step_plugin: dict[int, str] = {}
        for p in plugins_raw:
            step_plugin[p.get("step", -1)] = p.get("name", "")
        severity_by_plugin: dict[str, dict[str, int]] = {}
        for f in findings_raw:
            fstep = f.get("step", -1)
            pname = step_plugin.get(fstep, "")
            if pname:
                if pname not in severity_by_plugin:
                    severity_by_plugin[pname] = {}
                fs = f.get("severity", "INFO").upper()
                severity_by_plugin[pname][fs] = severity_by_plugin[pname].get(fs, 0) + 1

        max_findings = max((p.get("findings_count", 0) for p in plugins_raw), default=0)
        total_findings = sum(p.get("findings_count", 0) for p in plugins_raw)
        total_duration = sum(p.get("duration", 0) for p in plugins_raw)

        plugin_durations: dict[str, float] = {}
        for p in plugins_raw:
            pn = p.get("name", "unknown")
            plugin_durations[pn] = plugin_durations.get(pn, 0) + p.get("duration", 0)
        top_cost_plugins = sorted(
            plugin_durations.items(), key=lambda x: x[1], reverse=True,
        )[:10]

        # --- decisions ---
        prod_count = sum(1 for d in decisions if d.get("productive", False))
        scores = [d.get("score", 0) for d in decisions]
        avg_score = round(sum(scores) / len(scores), 3) if scores else 0.0
        total_ent_gained = sum(d.get("new_entities", 0) for d in decisions)

        plugin_prod: dict[str, int] = {}
        for d in decisions:
            if d.get("productive", False):
                p = d.get("plugin", "unknown")
                plugin_prod[p] = plugin_prod.get(p, 0) + 1
        top_plugin = max(plugin_prod, key=plugin_prod.get) if plugin_prod else ""

        gap_pattern = re.compile(r"^Gap:\s*(.+?)\.\s+Selected")
        _gap_kw = [
            (["no known services", "services"], "No Services"),
            (["no dns", "dns records"], "No DNS"),
            (["no technology", "technology"], "No Technology"),
            (["no endpoints", "endpoints"], "No Endpoints"),
            (["vulnerability", "vuln testing", "vuln_test"], "Vuln Testing"),
            (["verification", "verify", "confirm"], "Verification"),
            (["container", "docker"], "Containers"),
            (["credential", "cred"], "Credentials"),
            (["forms", "form detection"], "Form Detection"),
            (["version", "fingerprint"], "Version Detection"),
        ]
        gap_types: dict[str, int] = {}
        for d in decisions:
            reason = d.get("reasoning", "")
            m = gap_pattern.match(reason)
            if m:
                gap_desc = m.group(1).lower()
                categorized = False
                for keywords, cat_name in _gap_kw:
                    if any(kw in gap_desc for kw in keywords):
                        gap_types[cat_name] = gap_types.get(cat_name, 0) + 1
                        categorized = True
                        break
                if not categorized:
                    gap_types["Other"] = gap_types.get("Other", 0) + 1
        gap_type_counts = sorted(gap_types.items(), key=lambda x: -x[1])[:8]

        return {
            "findings": {
                "top_hosts": top_hosts,
                "cumulative_by_step": cumulative_by_step,
            },
            "kg_growth": {
                "peak_gain": peak_gain,
                "peak_step": peak_step,
                "saturation_step": sat_step,
            },
            "attack_surface": {
                "root_count": root_count,
                "subdomain_count": subdomain_count,
                "examined_count": examined_count,
                "examined_pct": examined_pct,
            },
            "network_map": {
                "total_services": total_services,
                "total_endpoints": total_endpoints,
                "total_techs": total_techs,
                "protocol_groups": protocol_groups,
                "findings_by_host": findings_by_host,
                "severity_by_host": severity_by_host,
            },
            "plugin_perf": {
                "max_findings": max_findings,
                "severity_by_plugin": severity_by_plugin,
                "total_findings": total_findings,
                "total_duration": total_duration,
                "top_cost_plugins": top_cost_plugins,
            },
            "decisions": {
                "productive_count": prod_count,
                "avg_score": avg_score,
                "total_entities_gained": total_ent_gained,
                "top_plugin": top_plugin,
                "gap_type_counts": gap_type_counts,
            },
        }

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
