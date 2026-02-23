"""PCAP analysis — extract credentials, files, DNS, HTTP from packet captures."""

from __future__ import annotations

import logging
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)


class PcapAnalyzePlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="pcap_analyze",
        display_name="PCAP Analysis",
        category=PluginCategory.FORENSICS,
        description="Extract credentials, files, DNS, HTTP from packet captures",
        produces=["credentials", "extracted_files"],
        timeout=120.0,
        requires_http=False,
        risk_level="safe",
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        data: dict = {
            "http_requests": [], "credentials": [],
            "dns_queries": [], "files": [], "anomalies": [],
        }

        pcap_path = target.meta.get("pcap_path", "")
        if not pcap_path:
            findings.append(Finding.info(
                "No PCAP file provided (set target.meta pcap_path)",
                tags=["forensics", "pcap"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        if not ctx.pcap:
            findings.append(Finding.info(
                "PcapAnalyzer not available (install scapy)",
                tags=["forensics", "pcap"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        # Load PCAP
        try:
            await ctx.pcap.load(pcap_path)
        except Exception as exc:
            return PluginResult.fail(
                self.meta.name, target.host, error=f"PCAP load failed: {exc}",
            )

        # Extract HTTP requests
        http_reqs = await ctx.pcap.extract_http_requests()
        data["http_requests"] = [
            {"method": r.method, "url": r.url, "host": r.host}
            for r in http_reqs[:50]
        ]
        if http_reqs:
            findings.append(Finding.info(
                f"HTTP requests: {len(http_reqs)}",
                evidence="\n".join(
                    f"{r.method} {r.url}" for r in http_reqs[:10]
                ),
                tags=["forensics", "pcap", "http"],
            ))

        # Extract credentials
        creds = await ctx.pcap.extract_credentials()
        data["credentials"] = [
            {"protocol": c.protocol, "username": c.username, "target": c.target}
            for c in creds[:20]
        ]
        if creds:
            findings.append(Finding.critical(
                f"Credentials found in PCAP: {len(creds)}",
                evidence="\n".join(
                    f"{c.protocol}: {c.username}@{c.target}" for c in creds[:10]
                ),
                description="Cleartext or captured credentials from network traffic",
                tags=["forensics", "pcap", "credential"],
            ))
            if ctx.creds:
                for c in creds:
                    ctx.creds.add(
                        username=c.username,
                        secret=c.password,
                        secret_type="password",
                        source="pcap",
                        target=c.target,
                    )

        # Extract DNS queries
        dns_queries = await ctx.pcap.extract_dns_queries()
        data["dns_queries"] = [
            {"name": q.name, "type": q.qtype, "response": q.response}
            for q in dns_queries[:50]
        ]
        if dns_queries:
            findings.append(Finding.info(
                f"DNS queries: {len(dns_queries)}",
                evidence="\n".join(
                    f"{q.name} ({q.qtype}) → {q.response}" for q in dns_queries[:10]
                ),
                tags=["forensics", "pcap", "dns"],
            ))

        # Extract files
        files = await ctx.pcap.extract_files()
        data["files"] = [
            {"filename": f.filename, "content_type": f.content_type, "size": f.size}
            for f in files[:20]
        ]
        if files:
            findings.append(Finding.medium(
                f"Files extracted from PCAP: {len(files)}",
                evidence="\n".join(
                    f"{f.filename} ({f.content_type}, {f.size} bytes)"
                    for f in files[:10]
                ),
                tags=["forensics", "pcap", "file"],
            ))

        # Find anomalies
        anomalies = await ctx.pcap.find_anomalies()
        data["anomalies"] = [
            {"type": a.anomaly_type, "description": a.description}
            for a in anomalies[:10]
        ]
        if anomalies:
            findings.append(Finding.high(
                f"Network anomalies: {len(anomalies)}",
                evidence="\n".join(
                    f"{a.anomaly_type}: {a.description}" for a in anomalies[:5]
                ),
                tags=["forensics", "pcap", "anomaly"],
            ))

        return PluginResult.success(
            self.meta.name, target.host, findings=findings, data=data,
        )
