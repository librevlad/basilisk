"""DNS enumeration scenario — native v4 implementation."""

from __future__ import annotations

from typing import Any, ClassVar

from basilisk.domain.finding import Finding, Proof
from basilisk.domain.scenario import Scenario, ScenarioMeta, ScenarioResult
from basilisk.domain.surface import Surface
from basilisk.domain.target import BaseTarget

_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


class DnsScenario(Scenario):
    """Comprehensive DNS enumeration: standard records + email security analysis."""

    meta: ClassVar[ScenarioMeta] = ScenarioMeta(
        name="dns_scenario",
        display_name="DNS Enumeration (v4)",
        category="recon",
        description="DNS recon: A/AAAA/MX/NS/TXT/SOA/CNAME, SPF/DMARC analysis",
        produces=["dns_records", "ips"],
        timeout=30.0,
        risk_level="safe",
        requires_knowledge=["Host"],
        produces_knowledge=["Host:dns_data"],
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
        records: list[dict[str, str]] = []
        ips: list[str] = []

        host = target.host

        # Phase 1: Standard records
        for rdtype in _RECORD_TYPES:
            if actor.should_stop:
                break
            try:
                results = await actor.dns_resolve(host, rdtype)
                for r in results:
                    records.append({"type": rdtype, "name": host, "value": str(r)})
                    if rdtype in ("A", "AAAA"):
                        ips.append(str(r))
            except Exception:
                continue

        # Phase 2: SPF analysis
        txt_records = [r["value"] for r in records if r["type"] == "TXT"]
        spf_records = [t for t in txt_records if "v=spf1" in t.lower()]

        if not spf_records:
            findings.append(Finding.medium(
                "Missing SPF record",
                description=f"No SPF record found for {host}",
                host=host,
                scenario_name=self.meta.name,
                confidence=0.9,
                tags=frozenset({"dns", "email", "spf"}),
            ))
        else:
            for spf in spf_records:
                if "+all" in spf.lower():
                    findings.append(Finding.high(
                        "Permissive SPF record (+all)",
                        proof=Proof(
                            description=f"SPF record allows any server to send email: {spf}",
                        ),
                        host=host,
                        scenario_name=self.meta.name,
                        confidence=0.95,
                        tags=frozenset({"dns", "email", "spf"}),
                    ))

        # Phase 3: DMARC analysis
        if not actor.should_stop:
            try:
                dmarc_results = await actor.dns_resolve(f"_dmarc.{host}", "TXT")
                dmarc_found = any("v=dmarc1" in str(r).lower() for r in dmarc_results)
            except Exception:
                dmarc_found = False

            if not dmarc_found:
                findings.append(Finding.medium(
                    "Missing DMARC record",
                    description=f"No DMARC record found for {host}",
                    host=host,
                    scenario_name=self.meta.name,
                    confidence=0.9,
                    tags=frozenset({"dns", "email", "dmarc"}),
                ))

        return ScenarioResult(
            scenario=self.meta.name,
            target=host,
            findings=findings,
            data={"dns_records": records, "ips": ips},
            status="success",
        )
