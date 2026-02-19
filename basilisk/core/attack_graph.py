"""Attack Graph — automatic attack path synthesis from pipeline results.

Builds a directed graph of attacker-state transitions from plugin findings,
then uses BFS to discover concrete attack paths from UNAUTHENTICATED to
high-impact goal states (CODE_EXECUTION, DATA_BREACH, FULL_COMPROMISE, etc.).

Pure post-processing: no changes to pipeline or plugins required.
"""

from __future__ import annotations

import enum
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any

from basilisk.models.result import PluginResult, Severity


# ---------------------------------------------------------------------------
# Attacker state model
# ---------------------------------------------------------------------------
class AttackerState(enum.Enum):
    """What the attacker has gained at a given point in the chain."""

    UNAUTHENTICATED = "unauthenticated"
    INFO_DISCLOSURE = "info_disclosure"
    CREDENTIAL_ACCESS = "credential_access"
    AUTHENTICATED = "authenticated"
    ADMIN_ACCESS = "admin_access"
    FILE_READ = "file_read"
    SSRF = "ssrf"
    CODE_EXECUTION = "code_execution"
    DATA_BREACH = "data_breach"
    CLOUD_COMPROMISE = "cloud_compromise"
    INTERNAL_NETWORK = "internal_network"
    FULL_COMPROMISE = "full_compromise"


# ---------------------------------------------------------------------------
# Graph primitives
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Edge:
    """A single transition in the attack graph."""

    source: AttackerState
    target: AttackerState
    finding_title: str
    plugin: str
    severity: str
    evidence: str


@dataclass
class AttackPath:
    """A concrete path from UNAUTHENTICATED to a goal state."""

    edges: list[Edge]
    goal: AttackerState
    max_severity: str = ""
    risk_score: float = 0.0

    def __post_init__(self) -> None:
        if self.edges and not self.max_severity:
            sev_order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            self.max_severity = max(
                (e.severity for e in self.edges), key=lambda s: sev_order.get(s, 0)
            )
        if self.edges and self.risk_score == 0.0:
            self.risk_score = _score_path(self)


# ---------------------------------------------------------------------------
# Transition rules
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class TransitionRule:
    """Declarative rule: when a plugin produces certain findings, an edge exists."""

    plugin: str
    source: AttackerState
    target: AttackerState
    severity_ge: Severity | None = None
    tag: str | None = None
    has_data_key: str | None = None

    def matches(self, result: PluginResult) -> tuple[bool, str]:
        """Check if *result* satisfies this rule.

        Returns ``(matched, finding_title)`` where *finding_title* is the
        title of the first finding that triggered the match (or ``""``).
        """
        if result.plugin != self.plugin:
            return False, ""

        if not result.ok:
            return False, ""

        # Filter findings that pass severity + tag checks
        candidates = result.findings
        if self.severity_ge is not None:
            candidates = [f for f in candidates if f.severity >= self.severity_ge]
        if self.tag is not None:
            candidates = [f for f in candidates if self.tag in f.tags]

        if (self.severity_ge is not None or self.tag is not None) and not candidates:
            return False, ""

        if self.has_data_key is not None and not result.data.get(self.has_data_key):
            return False, ""

        title = candidates[0].title if candidates else (
            result.findings[0].title if result.findings else result.plugin
        )
        return True, title


# ---------------------------------------------------------------------------
# Transition table — the *only* configuration needed per plugin
# ---------------------------------------------------------------------------
_U = AttackerState.UNAUTHENTICATED
_INFO = AttackerState.INFO_DISCLOSURE
_CRED = AttackerState.CREDENTIAL_ACCESS
_AUTH = AttackerState.AUTHENTICATED
_ADMIN = AttackerState.ADMIN_ACCESS
_FREAD = AttackerState.FILE_READ
_SSRF = AttackerState.SSRF
_RCE = AttackerState.CODE_EXECUTION
_DATA = AttackerState.DATA_BREACH
_CLOUD = AttackerState.CLOUD_COMPROMISE
_INTNET = AttackerState.INTERNAL_NETWORK
_FULL = AttackerState.FULL_COMPROMISE

PLUGIN_TRANSITIONS: list[TransitionRule] = [
    # --- SQL Injection ---
    TransitionRule("sqli_basic", _U, _DATA, severity_ge=Severity.HIGH),
    TransitionRule("sqli_advanced", _U, _DATA, severity_ge=Severity.HIGH),

    # --- LFI / Path Traversal ---
    TransitionRule("lfi_check", _U, _FREAD, severity_ge=Severity.HIGH),
    TransitionRule("path_traversal", _U, _FREAD, severity_ge=Severity.HIGH),
    TransitionRule("lfi_check", _FREAD, _CRED, has_data_key="credentials"),
    TransitionRule("path_traversal", _FREAD, _CRED, has_data_key="credentials"),

    # --- SSRF ---
    TransitionRule("ssrf_check", _U, _SSRF, severity_ge=Severity.HIGH),
    TransitionRule("ssrf_advanced", _U, _SSRF, severity_ge=Severity.HIGH),
    TransitionRule("ssrf_check", _SSRF, _CLOUD, tag="cloud-metadata"),
    TransitionRule("ssrf_advanced", _SSRF, _CLOUD, tag="cloud-metadata"),
    TransitionRule("ssrf_advanced", _SSRF, _INTNET, has_data_key="internal_ports"),
    TransitionRule("cloud_metadata_ssrf", _U, _SSRF, severity_ge=Severity.HIGH),
    TransitionRule("cloud_metadata_ssrf", _SSRF, _CLOUD, tag="cloud-metadata"),

    # --- SSTI / Command Injection → RCE ---
    TransitionRule("ssti_check", _U, _RCE, severity_ge=Severity.HIGH),
    TransitionRule("ssti_verify", _U, _RCE, severity_ge=Severity.HIGH),
    TransitionRule("command_injection", _U, _RCE, severity_ge=Severity.HIGH),
    TransitionRule("deserialization_check", _U, _RCE, severity_ge=Severity.HIGH),

    # --- XXE ---
    TransitionRule("xxe_check", _U, _FREAD, severity_ge=Severity.HIGH),
    TransitionRule("xxe_check", _FREAD, _SSRF, tag="ssrf"),

    # --- XSS + Cookie theft ---
    TransitionRule("xss_basic", _U, _INFO, severity_ge=Severity.HIGH),
    TransitionRule("xss_advanced", _U, _INFO, severity_ge=Severity.HIGH),
    TransitionRule("cookie_scan", _INFO, _CRED, tag="no-httponly"),

    # --- Credential / secret exposure ---
    TransitionRule("js_secret_scan", _U, _CRED, severity_ge=Severity.MEDIUM),
    TransitionRule("git_exposure", _U, _CRED, severity_ge=Severity.HIGH),
    TransitionRule("default_creds", _U, _CRED, severity_ge=Severity.HIGH),
    TransitionRule("sensitive_files", _U, _CRED, severity_ge=Severity.HIGH),
    TransitionRule("error_disclosure", _U, _INFO, severity_ge=Severity.MEDIUM),
    TransitionRule("debug_endpoints", _U, _INFO, severity_ge=Severity.MEDIUM),
    TransitionRule("prometheus_scrape", _U, _INFO, severity_ge=Severity.MEDIUM),

    # --- Info disclosure → credential access (generic) ---
    TransitionRule("credential_spray", _CRED, _AUTH, severity_ge=Severity.HIGH),
    TransitionRule("admin_brute", _CRED, _ADMIN, severity_ge=Severity.HIGH),
    TransitionRule("wp_brute", _CRED, _ADMIN, severity_ge=Severity.HIGH),
    TransitionRule("ssh_brute", _CRED, _AUTH, severity_ge=Severity.HIGH),
    TransitionRule("service_brute", _CRED, _AUTH, severity_ge=Severity.HIGH),

    # --- Authentication bypass ---
    TransitionRule("jwt_attack", _U, _AUTH, severity_ge=Severity.HIGH),
    TransitionRule("oauth_attack", _U, _AUTH, severity_ge=Severity.HIGH),
    TransitionRule("idor_check", _AUTH, _DATA, severity_ge=Severity.HIGH),
    TransitionRule("idor_exploit", _AUTH, _DATA, severity_ge=Severity.HIGH),

    # --- Admin access ---
    TransitionRule("admin_finder", _AUTH, _ADMIN, severity_ge=Severity.MEDIUM),
    TransitionRule("default_creds", _U, _ADMIN, tag="admin"),

    # --- Privilege escalation: admin → RCE ---
    TransitionRule("wordpress_scan", _ADMIN, _RCE, severity_ge=Severity.HIGH),
    TransitionRule("wp_deep_scan", _ADMIN, _RCE, severity_ge=Severity.HIGH),
    TransitionRule("actuator_exploit", _U, _RCE, severity_ge=Severity.CRITICAL),
    TransitionRule("actuator_exploit", _U, _INFO, severity_ge=Severity.MEDIUM),

    # --- HTTP Smuggling / CRLF ---
    TransitionRule("http_smuggling", _U, _AUTH, severity_ge=Severity.HIGH),
    TransitionRule("crlf_injection", _U, _INFO, severity_ge=Severity.MEDIUM),
    TransitionRule("host_header_inject", _U, _INFO, severity_ge=Severity.MEDIUM),

    # --- Prototype Pollution ---
    TransitionRule("prototype_pollution", _U, _RCE, severity_ge=Severity.CRITICAL),
    TransitionRule("pp_exploit", _U, _RCE, severity_ge=Severity.CRITICAL),

    # --- Cache Poisoning ---
    TransitionRule("cache_poison", _U, _INFO, severity_ge=Severity.HIGH),

    # --- Open Redirect (stepping stone) ---
    TransitionRule("open_redirect", _U, _INFO, severity_ge=Severity.MEDIUM),

    # --- NoSQL Injection ---
    TransitionRule("nosqli_check", _U, _DATA, severity_ge=Severity.HIGH),
    TransitionRule("nosqli_verify", _U, _DATA, severity_ge=Severity.HIGH),

    # --- Race Condition ---
    TransitionRule("race_condition", _AUTH, _DATA, severity_ge=Severity.HIGH),

    # --- GraphQL ---
    TransitionRule("graphql_exploit", _U, _DATA, severity_ge=Severity.HIGH),
    TransitionRule("graphql_exploit", _U, _INFO, severity_ge=Severity.MEDIUM),

    # --- Cross-state transitions (generic) ---
    # Credential access → authenticated (any plugin that yields creds)
    TransitionRule("credential_spray", _CRED, _AUTH, has_data_key="successful_logins"),
    # File read → credential access (config files with passwords)
    TransitionRule("backup_finder", _U, _FREAD, severity_ge=Severity.HIGH),
    # Subdomain takeover
    TransitionRule("subdomain_takeover_active", _U, _INFO, severity_ge=Severity.HIGH),

    # --- CSRF (stepping stone to authenticated actions) ---
    TransitionRule("csrf_check", _AUTH, _ADMIN, severity_ge=Severity.HIGH),

    # --- Email spoofing ---
    TransitionRule("email_spoofing", _U, _INFO, severity_ge=Severity.MEDIUM),
]


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------
_GOAL_WEIGHT: dict[AttackerState, float] = {
    _FULL: 1.0,
    _RCE: 0.95,
    _DATA: 0.90,
    _CLOUD: 0.85,
    _INTNET: 0.80,
    _ADMIN: 0.70,
    _CRED: 0.60,
    _AUTH: 0.55,
    _FREAD: 0.50,
    _SSRF: 0.45,
    _INFO: 0.30,
    _U: 0.0,
}

_SEV_VALUE: dict[str, int] = {
    "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4,
}


def _score_path(path: AttackPath) -> float:
    """Score an attack path from 0-100."""
    if not path.edges:
        return 0.0

    max_sev = max(_SEV_VALUE.get(e.severity, 0) for e in path.edges)
    severity_score = max_sev / 4 * 60  # 0-60

    goal_weight = _GOAL_WEIGHT.get(path.goal, 0.3)
    goal_score = goal_weight * 30  # 0-30

    brevity_bonus = max(0, (6 - len(path.edges)) * 2)  # 0-10

    return round(min(100.0, severity_score + goal_score + brevity_bonus), 1)


# ---------------------------------------------------------------------------
# Attack Graph
# ---------------------------------------------------------------------------
class AttackGraph:
    """Directed graph of attacker-state transitions built from plugin results."""

    def __init__(self, edges: list[Edge]) -> None:
        self.edges = edges
        self.adjacency: dict[AttackerState, list[Edge]] = defaultdict(list)
        for edge in edges:
            self.adjacency[edge.source].append(edge)
        self.paths: list[AttackPath] = []

    @classmethod
    def from_results(cls, results: list[PluginResult]) -> AttackGraph:
        """Build an attack graph from pipeline results."""
        edges: list[Edge] = []
        seen: set[tuple[AttackerState, AttackerState, str]] = set()

        for result in results:
            for rule in PLUGIN_TRANSITIONS:
                matched, title = rule.matches(result)
                if not matched:
                    continue

                dedup_key = (rule.source, rule.target, result.plugin)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                # Pick the best evidence from matching findings
                evidence = ""
                best_sev = Severity.INFO
                for f in result.findings:
                    if f.severity >= best_sev:
                        best_sev = f.severity
                        if f.evidence:
                            evidence = f.evidence[:200]

                edges.append(Edge(
                    source=rule.source,
                    target=rule.target,
                    finding_title=title,
                    plugin=result.plugin,
                    severity=best_sev.label,
                    evidence=evidence,
                ))

        graph = cls(edges)
        graph.paths = graph._find_all_paths()
        return graph

    def find_paths(
        self, goal: AttackerState, max_depth: int = 6,
    ) -> list[AttackPath]:
        """BFS from UNAUTHENTICATED to *goal*."""
        if not self.adjacency:
            return []

        paths: list[AttackPath] = []
        # BFS: queue of (current_state, edges_so_far, visited_states)
        queue: deque[tuple[AttackerState, list[Edge], set[AttackerState]]] = deque()
        queue.append((_U, [], {_U}))

        while queue:
            state, path_edges, visited = queue.popleft()

            if state == goal and path_edges:
                paths.append(AttackPath(
                    edges=list(path_edges),
                    goal=goal,
                ))
                continue

            if len(path_edges) >= max_depth:
                continue

            for edge in self.adjacency.get(state, []):
                if edge.target not in visited:
                    new_visited = visited | {edge.target}
                    queue.append((edge.target, path_edges + [edge], new_visited))

        paths.sort(key=lambda p: p.risk_score, reverse=True)
        return paths

    def _find_all_paths(self, max_depth: int = 6) -> list[AttackPath]:
        """Find paths to all high-impact goal states."""
        goals = [
            _FULL, _RCE, _DATA, _CLOUD, _INTNET, _ADMIN, _CRED, _AUTH,
        ]
        all_paths: list[AttackPath] = []
        seen_goals: set[tuple[AttackerState, tuple[str, ...]]] = set()

        for goal in goals:
            for path in self.find_paths(goal, max_depth=max_depth):
                key = (path.goal, tuple(e.plugin for e in path.edges))
                if key not in seen_goals:
                    seen_goals.add(key)
                    all_paths.append(path)

        all_paths.sort(key=lambda p: p.risk_score, reverse=True)
        return all_paths

    def to_report_chains(self) -> list[dict[str, Any]]:
        """Convert paths to the dict format expected by report templates.

        Returns list of ``{"name", "risk", "score", "path_text", "steps": [...]}``.
        """
        chains: list[dict[str, Any]] = []
        for path in self.paths:
            # Build the arrow-separated text: UNAUTH → SQLi → Data Breach
            nodes = [path.edges[0].source.value.replace("_", " ").title()]
            for edge in path.edges:
                nodes.append(edge.target.value.replace("_", " ").title())
            path_text = " \u2192 ".join(nodes)

            # Determine risk level from max severity
            risk = path.max_severity
            if risk not in ("CRITICAL", "HIGH"):
                risk = "HIGH"

            steps: list[dict[str, Any]] = []
            for edge in path.edges:
                steps.append({
                    "label": edge.target.value.replace("_", " ").title(),
                    "count": 1,
                    "detail": f"{edge.finding_title} ({edge.plugin})",
                })

            src = path.edges[0].source.value.replace("_", " ").title()
            dst = path.goal.value.replace("_", " ").title()
            name = f"{src} \u2192 {dst}"

            chains.append({
                "name": name,
                "risk": risk,
                "score": path.risk_score,
                "path_text": path_text,
                "steps": steps,
            })

        return chains
