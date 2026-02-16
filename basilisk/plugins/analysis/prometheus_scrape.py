"""Prometheus metrics intelligence — extract internal info from exposed /metrics."""

from __future__ import annotations

import logging
import re
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)

# Regex for Prometheus text format: metric_name{labels} value
_METRIC_RE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)\{([^}]*)\}\s+(\S+)', re.MULTILINE)
_LABEL_RE = re.compile(r'(\w+)="([^"]*)"')

# Patterns indicating internal infrastructure
_INTERNAL_IP_RE = re.compile(
    r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
    r'|192\.168\.\d{1,3}\.\d{1,3})'
)
_HOSTNAME_RE = re.compile(r'[a-z][a-z0-9-]+\.(?:internal|local|corp|svc\.cluster\.local)')


class PrometheusScrapePlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="prometheus_scrape",
        display_name="Prometheus Metrics Intelligence",
        category=PluginCategory.ANALYSIS,
        description="Extracts internal infrastructure info from exposed Prometheus /metrics",
        depends_on=["debug_endpoints"],
        produces=["prometheus_intel"],
        timeout=30.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        # Check if debug_endpoints found /metrics
        dep_key = f"debug_endpoints:{target.host}"
        dep_result = ctx.pipeline.get(dep_key)

        metrics_url = ""
        if dep_result and dep_result.ok:
            for ep in dep_result.data.get("exposed_endpoints", []):
                path = ep.get("path", "") if isinstance(ep, dict) else str(ep)
                if "/metrics" in path:
                    metrics_url = ep.get("url", "") if isinstance(ep, dict) else ""
                    break

        if not metrics_url:
            # Try common metrics paths directly
            for scheme in ("https", "http"):
                test_url = f"{scheme}://{target.host}/metrics"
                try:
                    async with ctx.rate:
                        resp = await ctx.http.get(test_url, timeout=5.0)
                        if resp.status == 200:
                            ct = resp.headers.get("content-type", "")
                            if "text/plain" in ct or "openmetrics" in ct:
                                metrics_url = test_url
                                break
                except Exception as e:
                    logger.debug("prometheus_scrape: %s probe failed: %s", scheme, e)
                    continue

        if not metrics_url:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info("No Prometheus /metrics endpoint found")],
                data={},
            )

        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        # Fetch metrics
        try:
            async with ctx.rate:
                resp = await ctx.http.get(metrics_url, timeout=10.0)
                if resp.status != 200:
                    return PluginResult.success(
                        self.meta.name, target.host,
                        findings=[Finding.info(
                            f"/metrics returned HTTP {resp.status}"
                        )],
                        data={},
                    )
                body = await resp.text(encoding="utf-8", errors="replace")
        except Exception as e:
            return PluginResult.fail(
                self.meta.name, target.host, error=str(e)
            )

        findings: list[Finding] = []
        intel: dict = {
            "metrics_url": metrics_url,
            "internal_ips": [],
            "internal_hostnames": [],
            "api_endpoints": [],
            "databases": [],
            "build_info": {},
            "metric_count": 0,
        }

        # Parse metrics
        metrics = _METRIC_RE.findall(body)
        intel["metric_count"] = len(metrics)

        internal_ips: set[str] = set()
        internal_hosts: set[str] = set()
        api_paths: set[str] = set()
        databases: set[str] = set()

        for metric_name, labels_str, _value in metrics:
            if ctx.should_stop:
                break
            labels = dict(_LABEL_RE.findall(labels_str))

            # Extract internal IPs
            for v in labels.values():
                for ip in _INTERNAL_IP_RE.findall(v):
                    internal_ips.add(ip)
                for host in _HOSTNAME_RE.findall(v):
                    internal_hosts.add(host)

            # Extract API paths from HTTP metrics
            if "path" in labels:
                path = labels["path"]
                if path.startswith("/") and not path.startswith("/metrics"):
                    api_paths.add(path)

            if "handler" in labels:
                handler = labels["handler"]
                if handler.startswith("/"):
                    api_paths.add(handler)

            # Extract database info
            if "database" in labels:
                databases.add(labels["database"])
            if "db" in labels:
                databases.add(labels["db"])

            # Extract build info
            if metric_name == "build_info" or metric_name.endswith("_build_info"):
                intel["build_info"].update(labels)

        intel["internal_ips"] = sorted(internal_ips)
        intel["internal_hostnames"] = sorted(internal_hosts)
        intel["api_endpoints"] = sorted(api_paths)[:50]
        intel["databases"] = sorted(databases)

        # Generate findings
        if internal_ips:
            findings.append(Finding.high(
                f"Internal IPs leaked via /metrics ({len(internal_ips)} found)",
                description="Prometheus metrics expose internal network addresses",
                evidence=", ".join(sorted(internal_ips)[:10]),
                remediation="Restrict /metrics endpoint to internal networks only",
                tags=["analysis", "prometheus", "info-leak"],
            ))

        if internal_hosts:
            findings.append(Finding.high(
                f"Internal hostnames leaked via /metrics ({len(internal_hosts)} found)",
                description="Internal hostnames visible in metric labels",
                evidence=", ".join(sorted(internal_hosts)[:10]),
                remediation="Restrict /metrics endpoint to internal networks only",
                tags=["analysis", "prometheus", "info-leak"],
            ))

        if api_paths:
            findings.append(Finding.medium(
                f"API endpoints discovered via /metrics ({len(api_paths)} paths)",
                description="HTTP metric labels reveal API routing structure",
                evidence=", ".join(sorted(api_paths)[:10]),
                remediation="Restrict /metrics endpoint to internal networks only",
                tags=["analysis", "prometheus", "api-discovery"],
            ))

        if databases:
            findings.append(Finding.medium(
                f"Database names leaked via /metrics ({len(databases)} found)",
                description="Database connection pool metrics reveal DB names",
                evidence=", ".join(sorted(databases)),
                remediation="Restrict /metrics endpoint to internal networks only",
                tags=["analysis", "prometheus", "info-leak"],
            ))

        if intel["build_info"]:
            findings.append(Finding.low(
                "Build info leaked via /metrics",
                evidence=str(intel["build_info"])[:200],
                tags=["analysis", "prometheus"],
            ))

        if not findings:
            findings.append(Finding.medium(
                f"Prometheus /metrics exposed ({len(metrics)} metrics)",
                description="Metrics endpoint is publicly accessible",
                evidence=metrics_url,
                remediation="Restrict /metrics endpoint to internal networks only",
                tags=["analysis", "prometheus"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data=intel,
        )
