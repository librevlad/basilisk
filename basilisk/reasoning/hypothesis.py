"""Hypothesis engine — form testable beliefs from knowledge graph patterns."""

from __future__ import annotations

import hashlib
import logging
from collections import defaultdict
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from basilisk.knowledge.graph import KnowledgeGraph

logger = logging.getLogger(__name__)


class HypothesisStatus(StrEnum):
    ACTIVE = "active"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


class HypothesisType(StrEnum):
    SHARED_STACK = "shared_stack"
    SERVICE_IDENTITY = "service_identity"
    SYSTEMATIC_VULN = "systematic_vuln"
    UNVERIFIED_FINDING = "unverified_finding"
    FRAMEWORK_PATTERN = "framework_pattern"


class EvidenceItem(BaseModel):
    """A piece of evidence supporting or contradicting a hypothesis."""

    entity_id: str
    source_plugin: str
    description: str
    source_family: str = "general"
    weight: float = 1.0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    supports: bool = True


class Hypothesis(BaseModel):
    """A testable belief derived from knowledge graph patterns.

    Confidence is recalculated on every evidence addition using weighted
    aggregation with source-family independence bonus.
    """

    id: str
    type: HypothesisType
    statement: str
    related_entity_ids: list[str] = Field(default_factory=list)
    confidence: float = 0.5
    supporting_evidence: list[EvidenceItem] = Field(default_factory=list)
    contradicting_evidence: list[EvidenceItem] = Field(default_factory=list)
    status: HypothesisStatus = HypothesisStatus.ACTIVE
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    resolved_at: datetime | None = None
    validation_plugins: list[str] = Field(default_factory=list)
    target_entity_ids: list[str] = Field(default_factory=list)

    @staticmethod
    def make_id(hypothesis_type: HypothesisType, **key_fields: str) -> str:
        """Deterministic ID from type + sorted key fields."""
        raw = f"hyp:{hypothesis_type}:" + "&".join(
            f"{k}={v}" for k, v in sorted(key_fields.items())
        )
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def add_supporting(self, item: EvidenceItem) -> None:
        """Add supporting evidence and recalculate confidence."""
        self.supporting_evidence.append(item)
        self._recalculate()

    def add_contradicting(self, item: EvidenceItem) -> None:
        """Add contradicting evidence and recalculate confidence."""
        self.contradicting_evidence.append(item)
        self._recalculate()

    def _recalculate(self) -> None:
        """Recalculate confidence from all evidence.

        Groups by source_family for independence weighting:
        - First evidence in a family gets full weight
        - Each additional gets weight * 0.7^i (diminishing returns)
        - Contradictions apply weight * 0.5 as negative signal
        - Normalize to [0, 1], then apply status transitions
        """
        if not self.supporting_evidence and not self.contradicting_evidence:
            return

        # Group supporting evidence by family
        support_by_family: dict[str, list[float]] = defaultdict(list)
        for ev in self.supporting_evidence:
            support_by_family[ev.source_family].append(ev.weight)

        # Group contradicting evidence by family
        contra_by_family: dict[str, list[float]] = defaultdict(list)
        for ev in self.contradicting_evidence:
            contra_by_family[ev.source_family].append(ev.weight)

        # Weighted support score
        support_score = 0.0
        for family_weights in support_by_family.values():
            for i, w in enumerate(family_weights):
                support_score += w * (0.7 ** i)

        # Weighted contradiction score
        contra_score = 0.0
        for family_weights in contra_by_family.values():
            for i, w in enumerate(family_weights):
                contra_score += w * 0.5 * (0.7 ** i)

        total = support_score + contra_score
        if total > 0:
            self.confidence = support_score / total
        else:
            self.confidence = 0.5

        self.confidence = max(0.0, min(1.0, self.confidence))

        # Status transitions
        if self.status == HypothesisStatus.ACTIVE:
            if self.confidence >= 0.85:
                self.status = HypothesisStatus.CONFIRMED
                self.resolved_at = datetime.now(UTC)
            elif self.confidence <= 0.15:
                self.status = HypothesisStatus.REJECTED
                self.resolved_at = datetime.now(UTC)


# ---------------------------------------------------------------------------
# Pattern detectors
# ---------------------------------------------------------------------------

_FRAMEWORK_PATTERNS: dict[str, list[str]] = {
    "wordpress": ["/wp-content", "/wp-admin", "/wp-login", "/wp-includes", "/xmlrpc.php"],
    "laravel": ["/_debugbar", "/storage", "/vendor", "/nova", "/.env"],
    "django": ["/admin", "/static", "/media", "/__debug__"],
    "rails": ["/rails", "/assets", "/packs"],
    "spring": ["/actuator", "/swagger", "/api-docs", "/h2-console"],
    "express": ["/api/", "/graphql", "/socket.io"],
    "nextjs": ["/_next", "/api/"],
    "aspnet": ["/api/", "/.well-known", "/swagger"],
}

_COMMON_PORT_SERVICES: dict[int, str] = {
    21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 110: "pop3",
    143: "imap", 3306: "mysql", 5432: "postgres", 6379: "redis",
    27017: "mongodb", 11211: "memcached", 9200: "elasticsearch",
    5672: "rabbitmq", 8161: "activemq",
}


def _detect_shared_stack(graph: KnowledgeGraph) -> list[Hypothesis]:
    """Detect when 2+ hosts share the same technology → organizational standard."""
    from basilisk.knowledge.entities import EntityType
    from basilisk.knowledge.relations import RelationType

    tech_hosts: dict[str, list[str]] = defaultdict(list)
    for host in graph.hosts():
        techs = graph.neighbors(host.id, RelationType.RUNS)
        for tech in techs:
            name = tech.data.get("name", "")
            if name:
                tech_hosts[name].append(host.data.get("host", host.id))

    hypotheses = []
    for tech_name, hosts in tech_hosts.items():
        if len(hosts) < 2:
            continue
        hyp_id = Hypothesis.make_id(HypothesisType.SHARED_STACK, tech=tech_name)
        host_list = ", ".join(hosts[:5])
        hyp = Hypothesis(
            id=hyp_id,
            type=HypothesisType.SHARED_STACK,
            statement=f"Organization standardizes on {tech_name} ({len(hosts)} hosts: {host_list})",
            related_entity_ids=[
                Entity.make_id(EntityType.HOST, host=h) for h in hosts[:10]
            ],
            confidence=min(0.4 + len(hosts) * 0.1, 0.8),
            validation_plugins=["tech_detect", "version_detect"],
            target_entity_ids=[
                Entity.make_id(EntityType.HOST, host=h) for h in hosts[:10]
            ],
        )
        for h in hosts:
            hyp.supporting_evidence.append(EvidenceItem(
                entity_id=Entity.make_id(EntityType.HOST, host=h),
                source_plugin="tech_detect",
                description=f"{tech_name} detected on {h}",
                source_family="http_probe",
            ))
        hypotheses.append(hyp)
    return hypotheses


def _detect_service_identity(graph: KnowledgeGraph) -> list[Hypothesis]:
    """Detect unknown services on non-standard ports → likely specific service."""
    from basilisk.knowledge.relations import RelationType

    hypotheses = []
    for host in graph.hosts():
        services = graph.neighbors(host.id, RelationType.EXPOSES)
        for svc in services:
            port = svc.data.get("port")
            service_name = svc.data.get("service", "")
            if not port or service_name:
                continue

            # Check technology attached to service
            techs = graph.neighbors(svc.id, RelationType.RUNS)
            if techs:
                continue

            # Unknown service on unusual port
            expected = _COMMON_PORT_SERVICES.get(port)
            if expected:
                hostname = host.data.get("host", host.id)
                hyp_id = Hypothesis.make_id(
                    HypothesisType.SERVICE_IDENTITY,
                    host=hostname, port=str(port),
                )
                hyp = Hypothesis(
                    id=hyp_id,
                    type=HypothesisType.SERVICE_IDENTITY,
                    statement=f"Port {port} on {hostname} likely runs {expected}",
                    related_entity_ids=[svc.id, host.id],
                    confidence=0.5,
                    validation_plugins=["service_detect", "tech_detect"],
                    target_entity_ids=[host.id],
                )
                hyp.supporting_evidence.append(EvidenceItem(
                    entity_id=svc.id,
                    source_plugin="port_scan",
                    description=f"Open port {port} commonly associated with {expected}",
                    source_family="network_scan",
                ))
                hypotheses.append(hyp)
    return hypotheses


def _detect_systematic_vuln(graph: KnowledgeGraph) -> list[Hypothesis]:
    """Detect recurring finding types across hosts → systematic vulnerability."""
    from basilisk.knowledge.entities import EntityType

    # Count finding titles/categories across hosts
    finding_hosts: dict[str, list[str]] = defaultdict(list)
    for finding in graph.findings():
        # Normalize title to category
        title = finding.data.get("title", "")
        host = finding.data.get("host", "")
        if not title or not host:
            continue
        # Extract category from title (e.g. "XSS in /search" → "XSS")
        category = title.split(" ")[0].upper() if title else ""
        if category:
            finding_hosts[category].append(host)

    hypotheses = []
    for category, hosts in finding_hosts.items():
        if len(hosts) < 3:
            continue
        unique_hosts = set(hosts)
        hyp_id = Hypothesis.make_id(HypothesisType.SYSTEMATIC_VULN, category=category)
        hyp = Hypothesis(
            id=hyp_id,
            type=HypothesisType.SYSTEMATIC_VULN,
            statement=(
                f"Systematic {category} vulnerability across {len(unique_hosts)} hosts"
            ),
            related_entity_ids=[
                Entity.make_id(EntityType.HOST, host=h) for h in list(unique_hosts)[:10]
            ],
            confidence=min(0.3 + len(hosts) * 0.05, 0.7),
            validation_plugins=[],
            target_entity_ids=[
                Entity.make_id(EntityType.HOST, host=h) for h in list(unique_hosts)[:10]
            ],
        )
        for h in hosts:
            hyp.supporting_evidence.append(EvidenceItem(
                entity_id=Entity.make_id(EntityType.HOST, host=h),
                source_plugin="various",
                description=f"{category} finding on {h}",
                source_family="exploit",
            ))
        hypotheses.append(hyp)
    return hypotheses


def _detect_unverified_findings(graph: KnowledgeGraph) -> list[Hypothesis]:
    """High/critical findings with low confidence need confirmation."""
    from basilisk.knowledge.entities import EntityType

    hypotheses = []
    for finding in graph.findings():
        severity = finding.data.get("severity", "info")
        if severity not in ("high", "critical"):
            continue
        if finding.confidence >= 0.7:
            continue
        if finding.data.get("verified"):
            continue

        title = finding.data.get("title", "unknown")
        host = finding.data.get("host", "unknown")
        hyp_id = Hypothesis.make_id(
            HypothesisType.UNVERIFIED_FINDING, host=host, title=title,
        )
        hyp = Hypothesis(
            id=hyp_id,
            type=HypothesisType.UNVERIFIED_FINDING,
            statement=f"Vulnerability '{title}' may exist on {host} (unverified)",
            related_entity_ids=[finding.id],
            confidence=finding.confidence,
            validation_plugins=[],
            target_entity_ids=[
                Entity.make_id(EntityType.HOST, host=host),
            ],
        )
        hyp.supporting_evidence.append(EvidenceItem(
            entity_id=finding.id,
            source_plugin=finding.evidence[0] if finding.evidence else "unknown",
            description=f"{severity} finding: {title}",
            source_family="exploit",
            weight=1.0 if severity == "critical" else 0.8,
        ))
        hypotheses.append(hyp)
    return hypotheses


def _detect_framework_pattern(graph: KnowledgeGraph) -> list[Hypothesis]:
    """Endpoint paths suggest a specific framework."""
    from basilisk.knowledge.relations import RelationType

    hypotheses = []
    for host in graph.hosts():
        endpoints = graph.neighbors(host.id, RelationType.HAS_ENDPOINT)
        if not endpoints:
            continue

        paths = [ep.data.get("path", "") for ep in endpoints]

        for framework, indicators in _FRAMEWORK_PATTERNS.items():
            matches = [p for p in paths if any(ind in p for ind in indicators)]
            if len(matches) < 2:
                continue

            hostname = host.data.get("host", host.id)
            hyp_id = Hypothesis.make_id(
                HypothesisType.FRAMEWORK_PATTERN,
                host=hostname, framework=framework,
            )
            hyp = Hypothesis(
                id=hyp_id,
                type=HypothesisType.FRAMEWORK_PATTERN,
                statement=f"Target {hostname} likely uses {framework} "
                f"({len(matches)} matching paths)",
                related_entity_ids=[host.id],
                confidence=min(0.3 + len(matches) * 0.1, 0.75),
                validation_plugins=["tech_detect"],
                target_entity_ids=[host.id],
            )
            for m in matches[:5]:
                hyp.supporting_evidence.append(EvidenceItem(
                    entity_id=host.id,
                    source_plugin="web_crawler",
                    description=f"Path '{m}' matches {framework} pattern",
                    source_family="http_probe",
                ))
            hypotheses.append(hyp)
    return hypotheses


# Import Entity at module level for detectors
from basilisk.knowledge.entities import Entity  # noqa: E402

_DETECTORS = [
    _detect_shared_stack,
    _detect_service_identity,
    _detect_systematic_vuln,
    _detect_unverified_findings,
    _detect_framework_pattern,
]


class HypothesisEngine:
    """Generate and manage hypotheses from knowledge graph patterns.

    Runs pattern detectors against the graph, tracks hypothesis lifecycle,
    and provides resolution_gain scores for the scorer.
    """

    MAX_ACTIVE = 50

    def __init__(self) -> None:
        self._hypotheses: dict[str, Hypothesis] = {}

    def generate_hypotheses(self, graph: KnowledgeGraph) -> list[Hypothesis]:
        """Run all detectors and return newly generated hypotheses."""
        new_hypotheses: list[Hypothesis] = []
        for detector in _DETECTORS:
            try:
                candidates = detector(graph)
            except Exception:
                logger.exception("Hypothesis detector %s failed", detector.__name__)
                continue

            for hyp in candidates:
                if hyp.id in self._hypotheses:
                    continue
                # Enforce active limit
                active_count = sum(
                    1 for h in self._hypotheses.values()
                    if h.status == HypothesisStatus.ACTIVE
                )
                if active_count >= self.MAX_ACTIVE:
                    break
                self._hypotheses[hyp.id] = hyp
                new_hypotheses.append(hyp)

        return new_hypotheses

    def update_from_observation(
        self,
        entity_id: str,
        source_plugin: str,
        source_family: str,
        was_new: bool,
        confidence_delta: float,
    ) -> list[Hypothesis]:
        """Update hypotheses when a new observation arrives.

        Returns hypotheses whose status changed (confirmed/rejected).
        """
        changed: list[Hypothesis] = []
        for hyp in self._hypotheses.values():
            if hyp.status != HypothesisStatus.ACTIVE:
                continue

            # Check if this observation relates to the hypothesis
            is_related = (
                entity_id in hyp.related_entity_ids
                or entity_id in hyp.target_entity_ids
            )
            if not is_related:
                continue

            old_status = hyp.status
            if was_new or confidence_delta > 0.01:
                hyp.add_supporting(EvidenceItem(
                    entity_id=entity_id,
                    source_plugin=source_plugin,
                    description=f"Observation from {source_plugin} (delta={confidence_delta:.3f})",
                    source_family=source_family,
                    weight=min(abs(confidence_delta) * 5 + 0.3, 1.0),
                ))
            elif confidence_delta < -0.01:
                hyp.add_contradicting(EvidenceItem(
                    entity_id=entity_id,
                    source_plugin=source_plugin,
                    description=f"Contradicting from {source_plugin} (d={confidence_delta:.3f})",
                    source_family=source_family,
                    weight=min(abs(confidence_delta) * 5 + 0.3, 1.0),
                ))

            if hyp.status != old_status:
                changed.append(hyp)

        return changed

    def hypotheses_for_entity(self, entity_id: str) -> list[Hypothesis]:
        """Get all hypotheses related to a specific entity."""
        return [
            h for h in self._hypotheses.values()
            if entity_id in h.related_entity_ids or entity_id in h.target_entity_ids
        ]

    def resolution_gain(self, plugin_name: str, target_entity_id: str) -> float:
        """Estimate how much running this plugin resolves active hypotheses.

        Returns 0.0-1.0. Higher when:
        - Plugin is in hypothesis.validation_plugins
        - Target entity is in hypothesis.target_entity_ids
        - Hypothesis confidence is near 0.5 (most uncertain)
        """
        total_gain = 0.0
        for hyp in self._hypotheses.values():
            if hyp.status != HypothesisStatus.ACTIVE:
                continue

            gain = 0.0
            if plugin_name in hyp.validation_plugins:
                gain += 0.3
            if target_entity_id in hyp.target_entity_ids:
                gain += 0.15

            if gain > 0:
                # Uncertainty bonus: highest when confidence ~0.5
                uncertainty = 1.0 - abs(hyp.confidence - 0.5) * 2
                gain *= uncertainty
                total_gain += gain

        return min(total_gain, 1.0)

    @property
    def active_hypotheses(self) -> list[Hypothesis]:
        """All hypotheses with ACTIVE status."""
        return [
            h for h in self._hypotheses.values()
            if h.status == HypothesisStatus.ACTIVE
        ]

    @property
    def all_hypotheses(self) -> list[Hypothesis]:
        """All hypotheses regardless of status."""
        return list(self._hypotheses.values())
