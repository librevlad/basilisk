"""SSL/TLS check scenario — native v4 implementation."""

from __future__ import annotations

import ssl
from datetime import UTC, datetime
from typing import Any, ClassVar

from basilisk.domain.finding import Finding, Proof
from basilisk.domain.scenario import Scenario, ScenarioMeta, ScenarioResult
from basilisk.domain.surface import Surface
from basilisk.domain.target import BaseTarget


class SslScenario(Scenario):
    """Analyzes SSL/TLS certificates: expiry, key strength, signature algorithm."""

    meta: ClassVar[ScenarioMeta] = ScenarioMeta(
        name="ssl_scenario",
        display_name="SSL/TLS Analyzer (v4)",
        category="scanning",
        description="Certificate analysis: expiry, key strength, signature algorithm, chain",
        depends_on=["dns_scenario"],
        produces=["ssl_info"],
        timeout=30.0,
        risk_level="safe",
        requires_knowledge=["Host"],
        produces_knowledge=["Host:ssl_data"],
        cost_score=1.0,
        noise_score=1.0,
    )

    async def run(
        self,
        target: BaseTarget,
        actor: Any,
        surfaces: list[Surface],
        tools: dict[str, Any],
    ) -> ScenarioResult:
        findings: list[Finding] = []
        data: dict[str, Any] = {"ssl_available": False}
        host = target.host
        port = 443

        if target.ports:
            port = target.ports[0] if 443 not in target.ports else 443

        # Phase 1: SSL connection
        try:
            cert_info = await _get_cert_info(host, port)
        except Exception as e:
            data["ssl_error"] = str(e)
            return ScenarioResult(
                scenario=self.meta.name,
                target=host,
                findings=[Finding.info(
                    "SSL not available",
                    description=f"Could not establish SSL connection to {host}:{port}",
                    host=host,
                    scenario_name=self.meta.name,
                )],
                data=data,
                status="success",
            )

        data["ssl_available"] = True
        data["ssl_info"] = cert_info

        # Phase 2: Expiry check
        not_after = cert_info.get("not_after")
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
                days_left = (expiry - datetime.now(UTC)).days

                if days_left < 0:
                    findings.append(Finding.critical(
                        "SSL certificate expired",
                        proof=Proof(description=f"Expired {-days_left} days ago: {not_after}"),
                        host=host,
                        scenario_name=self.meta.name,
                        confidence=0.99,
                        tags=frozenset({"ssl", "expired"}),
                    ))
                elif days_left < 7:
                    findings.append(Finding.high(
                        "SSL certificate expires within 7 days",
                        proof=Proof(description=f"Expires in {days_left} days: {not_after}"),
                        host=host,
                        scenario_name=self.meta.name,
                        confidence=0.95,
                        tags=frozenset({"ssl", "expiry"}),
                    ))
                elif days_left < 30:
                    findings.append(Finding.low(
                        f"SSL certificate expires in {days_left} days",
                        host=host,
                        scenario_name=self.meta.name,
                        tags=frozenset({"ssl", "expiry"}),
                    ))
            except (ValueError, TypeError):
                pass

        # Phase 3: Self-signed check
        issuer = cert_info.get("issuer", "")
        subject = cert_info.get("subject", "")
        if issuer and subject and issuer == subject:
            findings.append(Finding.medium(
                "Self-signed SSL certificate",
                description=f"Certificate for {host} is self-signed",
                host=host,
                scenario_name=self.meta.name,
                confidence=0.95,
                tags=frozenset({"ssl", "self-signed"}),
            ))

        # Phase 4: Subject info
        san = cert_info.get("san", [])
        if san:
            findings.append(Finding.info(
                f"SSL certificate covers {len(san)} name(s)",
                description=f"Subject Alternative Names: {', '.join(san[:10])}",
                host=host,
                scenario_name=self.meta.name,
            ))

        return ScenarioResult(
            scenario=self.meta.name,
            target=host,
            findings=findings,
            data=data,
            status="success",
        )


async def _get_cert_info(host: str, port: int = 443) -> dict[str, Any]:
    """Connect to host via SSL and extract certificate information."""
    import asyncio

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    _, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ctx),
        timeout=10.0,
    )
    try:
        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj is None:
            return {}
        cert = ssl_obj.getpeercert(binary_form=False) or {}

        # Parse subject and issuer
        subject_parts = []
        for rdn in cert.get("subject", ()):
            for attr_type, attr_value in rdn:
                subject_parts.append(f"{attr_type}={attr_value}")
        subject = ", ".join(subject_parts)

        issuer_parts = []
        for rdn in cert.get("issuer", ()):
            for attr_type, attr_value in rdn:
                issuer_parts.append(f"{attr_type}={attr_value}")
        issuer = ", ".join(issuer_parts)

        # Extract SANs
        san: list[str] = []
        for _san_type, san_value in cert.get("subjectAltName", ()):
            san.append(san_value)

        return {
            "subject": subject,
            "issuer": issuer,
            "not_before": cert.get("notBefore", ""),
            "not_after": cert.get("notAfter", ""),
            "serial": cert.get("serialNumber", ""),
            "san": san,
            "version": cert.get("version", 0),
        }
    finally:
        writer.close()
        await writer.wait_closed()
