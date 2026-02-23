"""Attack path registry — state-transition graph for multi-step attacks."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from basilisk.knowledge.entities import EntityType

if TYPE_CHECKING:
    from basilisk.knowledge.graph import KnowledgeGraph


@dataclass
class AttackPath:
    """A transition between attack graph states.

    Represents a multi-step attack opportunity:
    preconditions describe the knowledge graph state required,
    actions list plugins that execute the transition,
    expected_gain is what new knowledge is produced,
    unlock lists paths that become available after this one succeeds.
    """

    name: str
    preconditions: list[str]  # e.g. ["Service:http", "Endpoint:login"]
    actions: list[str]        # plugin names
    expected_gain: list[str]  # e.g. ["Credential"]
    risk: float = 1.0        # 1-10
    unlock: list[str] = field(default_factory=list)


# Registry of known attack paths
ATTACK_PATHS: list[AttackPath] = [
    AttackPath(
        name="credential_attack",
        preconditions=["Service:http", "Endpoint:params"],
        actions=["default_creds", "service_brute", "credential_spray"],
        expected_gain=["Credential"],
        risk=4.0,
        unlock=["lateral_movement", "privilege_escalation"],
    ),
    AttackPath(
        name="lateral_movement",
        preconditions=["Credential"],
        actions=["credential_reuse", "credential_spray", "ssh_brute"],
        expected_gain=["Host", "Service", "Finding"],
        risk=6.0,
        unlock=["privilege_escalation", "data_exfiltration"],
    ),
    AttackPath(
        name="privilege_escalation",
        preconditions=["Credential", "Service:ssh"],
        actions=["suid_finder", "kernel_suggest", "sudo_misconfig"],
        expected_gain=["Finding", "Vulnerability"],
        risk=7.0,
        unlock=["data_exfiltration"],
    ),
    AttackPath(
        name="injection_attack",
        preconditions=["Service:http", "Endpoint:params"],
        actions=["sqli_check", "sqli_advanced", "xss_check", "xss_advanced",
                 "ssti_check", "command_injection", "nosqli_check"],
        expected_gain=["Finding", "Vulnerability"],
        risk=5.0,
        unlock=["credential_attack", "data_exfiltration"],
    ),
    AttackPath(
        name="api_exploitation",
        preconditions=["Service:http", "Endpoint:api"],
        actions=["graphql_detect", "graphql_exploit", "api_abuse"],
        expected_gain=["Finding", "Vulnerability", "Endpoint"],
        risk=4.0,
        unlock=["injection_attack", "credential_attack"],
    ),
    AttackPath(
        name="service_exploitation",
        preconditions=["Service"],
        actions=["redis_exploit", "mysql_exploit", "ftp_anon", "smb_enum"],
        expected_gain=["Finding", "Credential", "Vulnerability"],
        risk=5.0,
        unlock=["lateral_movement", "data_exfiltration"],
    ),
    AttackPath(
        name="admin_access",
        preconditions=["Service:http", "Endpoint:admin"],
        actions=["default_creds", "admin_panel_brute"],
        expected_gain=["Credential", "Finding"],
        risk=3.0,
        unlock=["privilege_escalation", "data_exfiltration"],
    ),
    AttackPath(
        name="data_exfiltration",
        preconditions=["Credential", "Service"],
        actions=["data_exfil", "sensitive_files", "backup_finder"],
        expected_gain=["Finding"],
        risk=8.0,
        unlock=[],
    ),
    AttackPath(
        name="web_vuln_discovery",
        preconditions=["Service:http"],
        actions=["cors_scan", "cors_exploit", "cache_poison", "http_smuggling",
                 "jwt_attack", "ssrf_check"],
        expected_gain=["Finding", "Vulnerability"],
        risk=3.0,
        unlock=["injection_attack", "credential_attack"],
    ),
    AttackPath(
        name="sensitive_exposure",
        preconditions=["Service:http"],
        actions=["git_exposure", "sensitive_files", "dir_brute", "js_secret_scan"],
        expected_gain=["Finding", "Credential", "Endpoint"],
        risk=2.0,
        unlock=["credential_attack", "api_exploitation"],
    ),
]


def _precondition_met(precondition: str, graph: KnowledgeGraph) -> bool:
    """Check if a single precondition is satisfied by the current graph state."""
    if ":" in precondition:
        base_type, subtype = precondition.split(":", 1)
    else:
        base_type, subtype = precondition, None

    if base_type == "Host":
        return len(graph.hosts()) > 0
    if base_type == "Service":
        services = graph.services()
        if not services:
            return False
        if subtype == "http":
            return any(
                s.data.get("port") in (80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9090)
                or "http" in str(s.data.get("service", "")).lower()
                for s in services
            )
        if subtype == "ssh":
            return any(
                s.data.get("port") == 22 or "ssh" in str(s.data.get("service", "")).lower()
                for s in services
            )
        return True
    if base_type == "Endpoint":
        endpoints = graph.endpoints()
        if not endpoints:
            return False
        if subtype == "params":
            return any(
                e.data.get("has_params") or e.data.get("scan_path") or e.data.get("is_api")
                for e in endpoints
            )
        if subtype == "admin":
            return any(e.data.get("is_admin") for e in endpoints)
        if subtype == "api":
            return any(e.data.get("is_api") or e.data.get("is_graphql") for e in endpoints)
        if subtype == "login":
            return any(
                "login" in str(e.data.get("path", "")).lower()
                or "auth" in str(e.data.get("path", "")).lower()
                for e in endpoints
            )
        return True
    if base_type == "Credential":
        return len(graph.query(EntityType.CREDENTIAL)) > 0
    if base_type == "Technology":
        techs = graph.technologies()
        if not techs:
            return False
        if subtype == "waf":
            return any(t.data.get("is_waf") for t in techs)
        if subtype == "cms":
            return any(t.data.get("is_cms") for t in techs)
        return True

    return False


def find_available_paths(graph: KnowledgeGraph) -> list[AttackPath]:
    """Return attack paths whose preconditions are met by the current graph state."""
    available = []
    for path in ATTACK_PATHS:
        if all(_precondition_met(p, graph) for p in path.preconditions):
            available.append(path)
    return available


def count_unlockable_paths(
    capability_produces: list[str], graph: KnowledgeGraph,
) -> int:
    """Count how many currently-unavailable attack paths would become available
    if the given capability produces are added to the graph.

    Used by the scorer to compute future unlock value.
    """
    currently_available = {p.name for p in find_available_paths(graph)}
    unlock_count = 0

    for path in ATTACK_PATHS:
        if path.name in currently_available:
            continue
        # Check if adding the produced knowledge types would satisfy missing preconditions
        unmet = [p for p in path.preconditions if not _precondition_met(p, graph)]
        if not unmet:
            continue
        # Check if capability produces can satisfy any unmet preconditions
        for unmet_pre in unmet:
            base_type = unmet_pre.split(":")[0]
            if base_type in capability_produces or any(
                p.startswith(base_type) for p in capability_produces
            ):
                unlock_count += 1
                break

    return unlock_count
