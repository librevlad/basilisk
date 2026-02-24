"""Port scan scenario — native v4 implementation."""

from __future__ import annotations

import contextlib
from typing import Any, ClassVar

from basilisk.domain.finding import Finding, Proof
from basilisk.domain.scenario import Scenario, ScenarioMeta, ScenarioResult
from basilisk.domain.surface import Surface
from basilisk.domain.target import BaseTarget
from basilisk.models.result import Severity

# Top ports for quick scan
_TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 2375, 2376, 3306, 3389, 5432, 5900, 6379, 6443, 8080, 8443,
    8888, 9090, 9200, 9300, 10250, 27017,
]

# Port → service name
_PORT_SERVICES: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 2375: "Docker API", 2376: "Docker TLS",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 6443: "K8s API", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "HTTP-Alt", 9090: "HTTP-Alt", 9200: "Elasticsearch",
    9300: "ES Transport", 10250: "Kubelet", 27017: "MongoDB",
}

# High-risk ports and their severity
_RISKY_PORTS: dict[int, tuple[Severity, str]] = {
    2375: (Severity.CRITICAL, "Docker API (no TLS) exposed"),
    6443: (Severity.HIGH, "Kubernetes API exposed"),
    3389: (Severity.HIGH, "RDP exposed"),
    6379: (Severity.HIGH, "Redis exposed (no auth by default)"),
    27017: (Severity.HIGH, "MongoDB exposed"),
    9200: (Severity.HIGH, "Elasticsearch exposed"),
    445: (Severity.MEDIUM, "SMB exposed"),
    3306: (Severity.MEDIUM, "MySQL exposed"),
    5432: (Severity.MEDIUM, "PostgreSQL exposed"),
    23: (Severity.MEDIUM, "Telnet exposed"),
    5900: (Severity.MEDIUM, "VNC exposed"),
    10250: (Severity.HIGH, "Kubelet API exposed"),
}


class PortScenario(Scenario):
    """Async TCP port scanner with service detection."""

    meta: ClassVar[ScenarioMeta] = ScenarioMeta(
        name="port_scenario",
        display_name="Port Scanner (v4)",
        category="scanning",
        description="Async TCP port scanner with service mapping and risk assessment",
        produces=["open_ports"],
        timeout=90.0,
        risk_level="safe",
        requires_knowledge=["Host"],
        produces_knowledge=["Service"],
        cost_score=2.0,
        noise_score=2.0,
    )

    async def run(
        self,
        target: BaseTarget,
        actor: Any,
        surfaces: list[Surface],
        tools: dict[str, Any],
    ) -> ScenarioResult:
        findings: list[Finding] = []
        open_ports: list[dict[str, Any]] = []
        host = target.host

        # Phase 1: Scan top ports
        for port in _TOP_PORTS:
            if actor.should_stop:
                break

            try:
                is_open = await actor.tcp_connect(host, port, timeout=3.0)
            except Exception:
                is_open = False

            if not is_open:
                continue

            service = _PORT_SERVICES.get(port, "unknown")

            # Phase 2: Banner grab
            banner = ""
            if not actor.should_stop:
                with contextlib.suppress(Exception):
                    banner = await actor.tcp_banner(host, port, timeout=3.0)

            port_info = {
                "port": port,
                "protocol": "tcp",
                "service": service,
                "banner": banner,
                "state": "open",
            }
            open_ports.append(port_info)

            # Phase 3: Risk assessment
            if port in _RISKY_PORTS:
                severity, desc = _RISKY_PORTS[port]
                proof = Proof(
                    description=f"{desc} on {host}:{port}",
                    raw_response=banner[:200] if banner else "",
                )
                if severity >= Severity.HIGH:
                    findings.append(Finding(
                        title=f"{desc}",
                        severity=severity,
                        proof=proof,
                        host=host,
                        endpoint=f"{host}:{port}",
                        scenario_name=self.meta.name,
                        confidence=0.9,
                        tags=frozenset({"port", service.lower().replace(" ", "_")}),
                    ))
                else:
                    findings.append(Finding(
                        title=f"{desc}",
                        severity=severity,
                        description=f"Service: {service}, Banner: {banner[:100]}",
                        host=host,
                        endpoint=f"{host}:{port}",
                        scenario_name=self.meta.name,
                        confidence=0.85,
                        tags=frozenset({"port", service.lower().replace(" ", "_")}),
                    ))

        # Add INFO finding for all open ports
        if open_ports:
            port_list = ", ".join(f"{p['port']}/{p['service']}" for p in open_ports)
            findings.append(Finding.info(
                f"{len(open_ports)} open port(s) found",
                description=f"Open ports: {port_list}",
                host=host,
                scenario_name=self.meta.name,
            ))

        return ScenarioResult(
            scenario=self.meta.name,
            target=host,
            findings=findings,
            data={"open_ports": open_ports, "scan_ports_count": len(_TOP_PORTS)},
            status="success",
        )
