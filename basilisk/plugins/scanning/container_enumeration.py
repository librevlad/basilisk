"""Container enumeration — list containers and images via Docker API."""

from __future__ import annotations

import json
import logging
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)


class ContainerEnumerationPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="container_enumeration",
        display_name="Container Enumeration",
        category=PluginCategory.SCANNING,
        description="Enumerate containers and images via Docker API",
        depends_on=["container_discovery"],
        produces=["containers", "images"],
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
        containers: list[dict] = []
        images: list[dict] = []

        api_url = self._get_api_url(target.host, ctx)
        if not api_url:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info("No Docker API URL available", tags=["container"])],
                data={"containers": [], "images": []},
            )

        # Enumerate containers
        containers = await self._enum_containers(ctx, api_url, findings)

        # Enumerate images
        images = await self._enum_images(ctx, api_url)

        if not findings:
            findings.append(Finding.info(
                "Container enumeration complete", tags=["container"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"containers": containers, "images": images},
        )

    def _get_api_url(self, host: str, ctx) -> str:
        """Find Docker API URL from state or pipeline."""
        # From container_discovery state
        runtimes = ctx.state.get("container_runtimes", {}).get(host, [])
        for rt in runtimes:
            if isinstance(rt, dict) and rt.get("api_url"):
                return rt["api_url"]

        # From docker_exploit pipeline
        docker_key = f"docker_exploit:{host}"
        docker_result = ctx.pipeline.get(docker_key)
        if docker_result and docker_result.ok and docker_result.data.get("api_url"):
            return docker_result.data["api_url"]

        # From container_discovery pipeline
        disc_key = f"container_discovery:{host}"
        disc_result = ctx.pipeline.get(disc_key)
        if disc_result and disc_result.ok:
            for rt in disc_result.data.get("container_runtimes", []):
                if isinstance(rt, dict) and rt.get("api_url"):
                    return rt["api_url"]

        return ""

    async def _enum_containers(
        self, ctx, api_url: str, findings: list[Finding],
    ) -> list[dict]:
        """Enumerate containers via Docker API."""
        containers = []
        try:
            async with ctx.rate:
                resp = await ctx.http.get(
                    api_url + "/containers/json?all=true", timeout=10.0,
                )
                if resp.status != 200:
                    return containers
                body = await resp.text(encoding="utf-8", errors="replace")
                if not body.startswith("["):
                    return containers

                raw = json.loads(body)
                for c in raw[:50]:  # Cap at 50 containers
                    container = self._parse_container(c)
                    containers.append(container)

                    # Flag privileged containers
                    if container.get("privileged"):
                        findings.append(Finding.high(
                            f"Privileged container: {container.get('names', ['?'])[0]}",
                            evidence=f"Container {container['id']} runs in privileged mode",
                            description="Privileged containers can escape to the host",
                            tags=["container", "privileged"],
                            confidence=0.65,
                        ))

                    # Flag host network mode
                    if container.get("network_mode") == "host":
                        findings.append(Finding.medium(
                            f"Host network container: {container.get('names', ['?'])[0]}",
                            evidence=f"Container {container['id']} uses host network",
                            tags=["container", "network"],
                            confidence=0.65,
                        ))

        except Exception:
            logger.debug("Container enumeration failed for %s", api_url)

        return containers

    def _parse_container(self, raw: dict) -> dict:
        """Parse raw Docker container JSON into a normalized dict."""
        host_config = raw.get("HostConfig", {})
        return {
            "id": raw.get("Id", "")[:12],
            "image": raw.get("Image", ""),
            "state": raw.get("State", ""),
            "names": raw.get("Names", []),
            "ports": [
                {"host": p.get("PublicPort"), "container": p.get("PrivatePort")}
                for p in raw.get("Ports", []) if isinstance(p, dict)
            ],
            "mounts": [
                m.get("Source", "") for m in raw.get("Mounts", []) if isinstance(m, dict)
            ],
            "network_mode": host_config.get("NetworkMode", ""),
            "privileged": host_config.get("Privileged", False),
            "pid_mode": host_config.get("PidMode", ""),
            "capabilities": (
                host_config.get("CapAdd") or []
            ),
            "user": raw.get("User", ""),
        }

    async def _enum_images(self, ctx, api_url: str) -> list[dict]:
        """Enumerate images via Docker API."""
        images = []
        try:
            async with ctx.rate:
                resp = await ctx.http.get(api_url + "/images/json", timeout=10.0)
                if resp.status != 200:
                    return images
                body = await resp.text(encoding="utf-8", errors="replace")
                if not body.startswith("["):
                    return images

                raw = json.loads(body)
                for img in raw[:50]:
                    repo_tags = img.get("RepoTags") or []
                    for tag in repo_tags:
                        parts = tag.rsplit(":", 1)
                        image_name = parts[0] if parts else tag
                        image_tag = parts[1] if len(parts) > 1 else "latest"
                        images.append({
                            "image_name": image_name,
                            "image_tag": image_tag,
                            "id": img.get("Id", "")[:19],
                            "size": img.get("Size", 0),
                            "created": img.get("Created", 0),
                        })
        except Exception:
            logger.debug("Image enumeration failed for %s", api_url)

        return images
