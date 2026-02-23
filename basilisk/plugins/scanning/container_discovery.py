"""Container runtime discovery — probe Docker/Kubernetes/containerd APIs."""

from __future__ import annotations

import json
import logging
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)

DOCKER_API_PORTS = [2375, 2376]
K8S_API_PORTS = [6443, 10250]


class ContainerDiscoveryPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="container_discovery",
        display_name="Container Runtime Discovery",
        category=PluginCategory.SCANNING,
        description="Probe Docker/Kubernetes/containerd API endpoints",
        produces=["container_runtimes"],
        timeout=30.0,
        requires_http=False,
        risk_level="safe",
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available",
            )

        findings: list[Finding] = []
        runtimes: list[dict] = []

        # Check existing pipeline data
        docker_key = f"docker_exploit:{target.host}"
        docker_result = ctx.pipeline.get(docker_key)

        # If docker_exploit already found Docker API, reuse data
        if docker_result and docker_result.ok and docker_result.data.get("accessible"):
            api_url = docker_result.data.get("api_url", "")
            runtimes.append({"name": "docker", "version": "", "api_url": api_url})
            findings.append(Finding.info(
                "Docker runtime detected (from docker_exploit)",
                tags=["container", "docker"],
            ))
        else:
            # Probe Docker API ports
            for port in DOCKER_API_PORTS:
                if ctx.should_stop:
                    break
                runtime = await self._probe_docker(ctx, target.host, port)
                if runtime:
                    runtimes.append(runtime)
                    if runtime.get("unauthenticated"):
                        findings.append(Finding.high(
                            f"Unauthenticated Docker API on port {port}",
                            evidence=f"URL: {runtime['api_url']}/version",
                            description="Docker API accessible without authentication",
                            tags=["container", "docker", "api"],
                        ))
                    else:
                        findings.append(Finding.info(
                            f"Docker runtime detected on port {port}",
                            tags=["container", "docker"],
                        ))
                    break  # Found Docker, no need to check more ports

        # Probe Kubernetes API
        for port in K8S_API_PORTS:
            if ctx.should_stop:
                break
            runtime = await self._probe_k8s(ctx, target.host, port)
            if runtime:
                runtimes.append(runtime)
                findings.append(Finding.info(
                    f"Kubernetes API detected on port {port}",
                    tags=["container", "kubernetes"],
                ))

        if not findings:
            findings.append(Finding.info(
                "No container runtimes detected", tags=["container"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"container_runtimes": runtimes},
        )

    async def _probe_docker(self, ctx, host: str, port: int) -> dict | None:
        """Probe Docker API on a given port."""
        scheme = "https" if port == 2376 else "http"
        base = f"{scheme}://{host}:{port}"
        try:
            async with ctx.rate:
                resp = await ctx.http.get(base + "/version", timeout=5.0)
                if resp.status == 200:
                    body = await resp.text(encoding="utf-8", errors="replace")
                    if "ApiVersion" in body or "Version" in body:
                        version = ""
                        try:
                            data = json.loads(body)
                            version = data.get("Version", "")
                        except (json.JSONDecodeError, ValueError):
                            pass
                        return {
                            "name": "docker",
                            "version": version,
                            "api_url": base,
                            "unauthenticated": True,
                        }
        except Exception:
            logger.debug("Docker probe failed on %s:%d", host, port)
        return None

    async def _probe_k8s(self, ctx, host: str, port: int) -> dict | None:
        """Probe Kubernetes API on a given port."""
        base = f"https://{host}:{port}"
        try:
            async with ctx.rate:
                resp = await ctx.http.get(base + "/version", timeout=5.0)
                if resp.status in (200, 401, 403):
                    body = await resp.text(encoding="utf-8", errors="replace")
                    if "major" in body or "kubernetes" in body.lower():
                        version = ""
                        try:
                            data = json.loads(body)
                            version = f"{data.get('major', '')}.{data.get('minor', '')}"
                        except (json.JSONDecodeError, ValueError):
                            pass
                        return {
                            "name": "kubernetes",
                            "version": version,
                            "api_url": base,
                        }
        except Exception:
            logger.debug("K8s probe failed on %s:%d", host, port)
        return None
