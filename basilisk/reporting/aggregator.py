"""VulnerabilityAggregator — collapse findings into deduplicated vulnerabilities."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from typing import Any

from basilisk.reporting.model import VulnerabilityInstance

# Known vuln type patterns for classification
_VULN_TYPE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("sqli", re.compile(r"sql.?inject|sqli", re.IGNORECASE)),
    ("xss", re.compile(r"cross.?site.?script|xss", re.IGNORECASE)),
    ("open_redirect", re.compile(r"open.?redirect", re.IGNORECASE)),
    ("ssrf", re.compile(r"server.?side.?request|ssrf", re.IGNORECASE)),
    ("lfi", re.compile(r"local.?file.?incl|lfi|path.?traversal", re.IGNORECASE)),
    ("rfi", re.compile(r"remote.?file.?incl|rfi", re.IGNORECASE)),
    ("csrf", re.compile(r"cross.?site.?request.?forg|csrf", re.IGNORECASE)),
    ("xxe", re.compile(r"xml.?external|xxe", re.IGNORECASE)),
    ("ssti", re.compile(r"server.?side.?template|ssti", re.IGNORECASE)),
    ("command_injection", re.compile(r"command.?inject|os.?inject|rce", re.IGNORECASE)),
    ("cors", re.compile(r"cors|cross.?origin", re.IGNORECASE)),
    ("crlf", re.compile(r"crlf|header.?inject", re.IGNORECASE)),
    ("nosqli", re.compile(r"nosql.?inject|nosqli", re.IGNORECASE)),
    ("deserialization", re.compile(r"deserializ", re.IGNORECASE)),
    ("jwt", re.compile(r"jwt|json.?web.?token", re.IGNORECASE)),
    ("prototype_pollution", re.compile(r"prototype.?pollut", re.IGNORECASE)),
    ("info_disclosure", re.compile(r"information.?disclos|sensitive.?data", re.IGNORECASE)),
    ("missing_header", re.compile(r"missing.*(header|hsts|csp)", re.IGNORECASE)),
]

# Patterns to strip for stable proof hashing
_UNSTABLE_PATTERNS = re.compile(
    r"(session[_-]?id|sid|token|csrf[_-]?token|nonce|timestamp|ts)"
    r"\s*[=:]\s*['\"]?[\w\-]+['\"]?",
    re.IGNORECASE,
)


class VulnerabilityAggregator:
    """Collapse raw findings into deduplicated VulnerabilityInstance list."""

    @staticmethod
    def aggregate(
        findings: list[dict[str, Any]], target: str,
    ) -> list[VulnerabilityInstance]:
        """Collapse findings by identity hash.

        Groups findings with same (target, surface, vuln_type, proof_key) and
        merges confidence via probabilistic OR.
        """
        if not findings:
            return []

        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for finding in findings:
            vuln_type = VulnerabilityAggregator._extract_vuln_type(finding)
            surface = VulnerabilityAggregator._extract_surface(finding)
            proof_key = VulnerabilityAggregator._normalize_proof(
                finding.get("evidence", ""),
            )
            vid = VulnerabilityAggregator._identity_hash(
                target, surface, vuln_type, proof_key,
            )
            groups[vid].append(finding)

        result: list[VulnerabilityInstance] = []
        for vid, group in groups.items():
            # Probabilistic OR for confidence: 1 - product(1 - conf_i)
            confidence = 0.0
            for f in group:
                c = f.get("confidence", 0.0)
                confidence = 1.0 - (1.0 - confidence) * (1.0 - c)
            confidence = min(confidence, 1.0)

            # Collect unique proofs, scenarios, surfaces
            proofs: list[str] = []
            scenarios: list[str] = []
            surfaces: list[str] = []
            for f in group:
                ev = f.get("evidence", "")
                if ev and ev not in proofs:
                    proofs.append(ev)
                for tag in f.get("tags", []):
                    if tag not in scenarios:
                        scenarios.append(tag)
                s = VulnerabilityAggregator._extract_surface(f)
                if s and s not in surfaces:
                    surfaces.append(s)

            # Use highest severity in the group
            severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
            best_severity = max(
                group,
                key=lambda f: severity_order.get(f.get("severity", "INFO").upper(), 0),
            )

            vuln_type = VulnerabilityAggregator._extract_vuln_type(group[0])

            # Synthesize reproduction steps from group findings
            repro_steps = VulnerabilityAggregator._build_reproduction_steps(
                surfaces, proofs, group,
            )

            result.append(VulnerabilityInstance(
                vulnerability_id=vid,
                vuln_type=vuln_type,
                severity=best_severity.get("severity", "INFO").upper(),
                affected_surfaces=surfaces,
                scenarios=scenarios,
                confidence_aggregate=round(confidence, 4),
                proofs=proofs,
                reproduction_steps=repro_steps,
            ))

        return result

    @staticmethod
    def _identity_hash(
        target: str, surface: str, vuln_type: str, proof_key: str,
    ) -> str:
        """SHA256[:16] deterministic hash."""
        raw = f"{target}|{surface}|{vuln_type}|{proof_key}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @staticmethod
    def _extract_vuln_type(finding: dict[str, Any]) -> str:
        """Derive type from tags/title."""
        tags = finding.get("tags", [])
        title = finding.get("title", "")
        combined = " ".join(tags) + " " + title

        for vuln_type, pattern in _VULN_TYPE_PATTERNS:
            if pattern.search(combined):
                return vuln_type

        return "unknown"

    @staticmethod
    def _extract_surface(finding: dict[str, Any]) -> str:
        """Derive affected surface: host + path or title context."""
        host = finding.get("host", "")
        # Try to extract path from evidence or description
        evidence = finding.get("evidence", "")
        description = finding.get("description", "")
        for text in [evidence, description, finding.get("title", "")]:
            match = re.search(r"(/[\w/.\-?&=%]+)", text)
            if match:
                return f"{host}{match.group(1)}"
        return host

    @staticmethod
    def _build_reproduction_steps(
        surfaces: list[str],
        proofs: list[str],
        group: list[dict[str, Any]],
    ) -> list[str]:
        """Synthesize reproduction steps from finding group data."""
        steps: list[str] = []

        # Step 1: Navigate to surface
        if surfaces:
            steps.append(f"Navigate to {surfaces[0]}")

        # Step 2: Observe evidence (best proof) or fallback to description
        best_evidence = next((p for p in proofs if p), "")
        if best_evidence:
            steps.append(f"Observe: {best_evidence[:200]}")
        else:
            # Fallback to description from first finding with one
            for f in group:
                desc = f.get("description", "")
                if desc:
                    steps.append(f"Observe: {desc[:200]}")
                    break

        return steps

    @staticmethod
    def _normalize_proof(evidence: str) -> str:
        """Strip timestamps, session IDs for stable hashing."""
        if not evidence:
            return ""
        return _UNSTABLE_PATTERNS.sub("", evidence).strip()
