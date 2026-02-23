"""Image fingerprint — detect vulnerable base images and bad practices."""

from __future__ import annotations

import logging
import time
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)

# Base images with known vulnerabilities below these versions
VULNERABLE_BASE_IMAGES: dict[str, str] = {
    "alpine": "3.18",
    "debian": "12",
    "ubuntu": "22.04",
    "centos": "8",
    "node": "18",
    "python": "3.10",
    "golang": "1.20",
    "ruby": "3.1",
    "php": "8.1",
    "nginx": "1.24",
    "httpd": "2.4.58",
    "redis": "7.0",
    "postgres": "15",
    "mysql": "8.0",
    "mongo": "6.0",
    "openjdk": "17",
    "eclipse-temurin": "17",
    "amazoncorretto": "17",
    "tomcat": "10.1",
    "haproxy": "2.8",
    "traefik": "2.10",
    "consul": "1.16",
    "vault": "1.14",
    "elasticsearch": "8.9",
    "kibana": "8.9",
    "logstash": "8.9",
    "grafana": "10.0",
    "prometheus": "2.45",
    "memcached": "1.6.21",
    "rabbitmq": "3.12",
}

MAX_IMAGE_AGE_DAYS = 180


class ImageFingerprintPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="image_fingerprint",
        display_name="Container Image Fingerprint",
        category=PluginCategory.ANALYSIS,
        description="Detect vulnerable base images and image hygiene issues",
        depends_on=["container_enumeration"],
        produces=["image_vulns"],
        timeout=20.0,
        requires_http=False,
        risk_level="safe",
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        image_vulns: list[dict] = []

        # Collect images from state and pipeline
        images = self._collect_images(target.host, ctx)

        if not images:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info("No images to analyze", tags=["container"])],
                data={"image_vulns": []},
            )

        for img in images:
            image_name = img.get("image_name", "")
            image_tag = img.get("image_tag", "latest")
            created = img.get("created", 0)

            # Check for vulnerable base image
            base_name = image_name.rsplit("/", 1)[-1]  # strip registry prefix
            if base_name in VULNERABLE_BASE_IMAGES:
                min_version = VULNERABLE_BASE_IMAGES[base_name]
                if image_tag != "latest" and self._version_lt(image_tag, min_version):
                    vuln = {
                        "image": f"{image_name}:{image_tag}",
                        "issue": f"Outdated base image (minimum safe: {min_version})",
                        "severity": "high",
                    }
                    image_vulns.append(vuln)
                    findings.append(Finding.high(
                        f"Vulnerable base image: {image_name}:{image_tag}",
                        evidence=f"Version {image_tag} < {min_version}",
                        description=f"Base image {base_name} below minimum safe version",
                        tags=["container", "image", "outdated"],
                        confidence=0.6,
                    ))

            # Check for :latest tag
            if image_tag == "latest":
                vuln = {
                    "image": f"{image_name}:latest",
                    "issue": "Using :latest tag (non-deterministic)",
                    "severity": "medium",
                }
                image_vulns.append(vuln)
                findings.append(Finding.medium(
                    f"Image uses :latest tag: {image_name}",
                    evidence=f"Tag: {image_name}:latest",
                    description="Using :latest tag makes builds non-reproducible",
                    tags=["container", "image", "latest"],
                    confidence=0.6,
                ))

            # Check image age
            if created and isinstance(created, (int, float)) and created > 0:
                age_days = (time.time() - created) / 86400
                if age_days > MAX_IMAGE_AGE_DAYS:
                    vuln = {
                        "image": f"{image_name}:{image_tag}",
                        "issue": f"Image is {int(age_days)} days old",
                        "severity": "medium",
                    }
                    image_vulns.append(vuln)
                    findings.append(Finding.medium(
                        f"Stale image: {image_name}:{image_tag} ({int(age_days)}d old)",
                        tags=["container", "image", "stale"],
                        confidence=0.6,
                    ))

        if not findings:
            findings.append(Finding.info(
                "No image issues detected", tags=["container", "image"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"image_vulns": image_vulns},
        )

    def _collect_images(self, host: str, ctx) -> list[dict]:
        """Collect image data from state and pipeline."""
        images = []

        # From ctx.state (populated by orchestrator)
        containers = ctx.state.get("containers", {}).get(host, [])
        seen_refs: set[str] = set()
        for c in containers:
            image_ref = c.get("image", "")
            if image_ref and image_ref not in seen_refs:
                seen_refs.add(image_ref)
                parts = image_ref.rsplit(":", 1)
                images.append({
                    "image_name": parts[0],
                    "image_tag": parts[1] if len(parts) > 1 else "latest",
                    "created": c.get("created", 0),
                })

        # From container_enumeration pipeline
        enum_key = f"container_enumeration:{host}"
        enum_result = ctx.pipeline.get(enum_key)
        if enum_result and enum_result.ok:
            for img in enum_result.data.get("images", []):
                if isinstance(img, dict):
                    ref = f"{img.get('image_name', '')}:{img.get('image_tag', 'latest')}"
                    if ref not in seen_refs:
                        seen_refs.add(ref)
                        images.append(img)

        return images

    @staticmethod
    def _version_lt(version: str, min_version: str) -> bool:
        """Simple version comparison: True if version < min_version."""
        try:
            v_parts = [int(x) for x in version.split(".")[:3]]
            m_parts = [int(x) for x in min_version.split(".")[:3]]
            # Pad to equal length
            while len(v_parts) < len(m_parts):
                v_parts.append(0)
            while len(m_parts) < len(v_parts):
                m_parts.append(0)
            return v_parts < m_parts
        except (ValueError, TypeError):
            return False
