"""Container config audit — detect security misconfigurations in containers."""

from __future__ import annotations

import logging
import re
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)

SENSITIVE_MOUNTS = {"/etc", "/root", "/proc", "/sys", "/dev", "/var/run/docker.sock"}
SECRET_ENV_PATTERNS = re.compile(
    r"(SECRET|PASSWORD|PASSWD|KEY|TOKEN|API_KEY|PRIVATE)", re.IGNORECASE,
)


class ContainerConfigAuditPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="container_config_audit",
        display_name="Container Config Audit",
        category=PluginCategory.ANALYSIS,
        description="Audit container configurations for security misconfigurations",
        depends_on=["container_enumeration"],
        produces=["container_misconfigs"],
        timeout=20.0,
        requires_http=False,
        risk_level="safe",
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        misconfigs: list[dict] = []

        containers = self._collect_containers(target.host, ctx)

        if not containers:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info("No containers to audit", tags=["container"])],
                data={"container_misconfigs": []},
            )

        for container in containers:
            cid = container.get("id", "?")[:12]
            names = container.get("names", [cid])
            name = names[0] if names else cid
            self._audit_container(container, name, findings, misconfigs)

        if not findings:
            findings.append(Finding.info(
                "No container misconfigurations detected",
                tags=["container", "config"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"container_misconfigs": misconfigs},
        )

    def _audit_container(
        self,
        container: dict,
        name: str,
        findings: list[Finding],
        misconfigs: list[dict],
    ) -> None:
        """Run all config checks against a single container."""
        cid = container.get("id", "?")[:12]

        # Privileged mode
        if container.get("privileged"):
            misconfigs.append({"container": name, "issue": "privileged", "severity": "critical"})
            findings.append(Finding.critical(
                f"Privileged container: {name}",
                evidence=f"Container {cid} runs with --privileged flag",
                description="Full host access — trivial container escape",
                tags=["container", "misconfig", "privileged"],
                confidence=0.65,
            ))

        # Host PID namespace
        if container.get("pid_mode") == "host":
            misconfigs.append({"container": name, "issue": "host_pid", "severity": "high"})
            findings.append(Finding.high(
                f"Host PID namespace: {name}",
                evidence=f"Container {cid} uses PID mode 'host'",
                description="Host process visibility enables escape vectors",
                tags=["container", "misconfig", "pid"],
                confidence=0.65,
            ))

        # Host network mode
        if container.get("network_mode") == "host":
            misconfigs.append({"container": name, "issue": "host_network", "severity": "high"})
            findings.append(Finding.high(
                f"Host network mode: {name}",
                evidence=f"Container {cid} uses network mode 'host'",
                description="Host network bypasses container network isolation",
                tags=["container", "misconfig", "network"],
                confidence=0.65,
            ))

        # Docker socket mounted
        mounts = container.get("mounts", [])
        for mount in mounts:
            mount_path = mount if isinstance(mount, str) else mount.get("Source", "")
            if "docker.sock" in mount_path:
                misconfigs.append({
                    "container": name, "issue": "docker_socket", "severity": "critical",
                })
                findings.append(Finding.critical(
                    f"Docker socket mounted: {name}",
                    evidence=f"Container {cid} mounts {mount_path}",
                    description="Docker socket access = full host control",
                    tags=["container", "misconfig", "socket"],
                    confidence=0.65,
                ))
                break

        # Sensitive volume mounts
        for mount in mounts:
            mount_path = mount if isinstance(mount, str) else mount.get("Source", "")
            if any(mount_path.startswith(s) for s in SENSITIVE_MOUNTS):
                if "docker.sock" in mount_path:
                    continue  # Already handled above
                misconfigs.append({
                    "container": name, "issue": f"sensitive_mount:{mount_path}",
                    "severity": "high",
                })
                findings.append(Finding.high(
                    f"Sensitive mount in {name}: {mount_path}",
                    evidence=f"Container {cid} mounts {mount_path}",
                    tags=["container", "misconfig", "mount"],
                    confidence=0.60,
                ))

        # CAP_SYS_ADMIN capability
        caps = container.get("capabilities", [])
        if "CAP_SYS_ADMIN" in caps or "SYS_ADMIN" in caps:
            misconfigs.append({
                "container": name, "issue": "cap_sys_admin", "severity": "high",
            })
            findings.append(Finding.high(
                f"CAP_SYS_ADMIN on container: {name}",
                evidence=f"Container {cid} has CAP_SYS_ADMIN",
                description="SYS_ADMIN capability enables mount-based escapes",
                tags=["container", "misconfig", "capabilities"],
                confidence=0.65,
            ))

        # Running as root
        user = container.get("user", "")
        if not user or user == "root" or user == "0":
            misconfigs.append({"container": name, "issue": "root_user", "severity": "medium"})
            findings.append(Finding.medium(
                f"Container runs as root: {name}",
                evidence=f"Container {cid} user: '{user or "root (default)"}'",
                tags=["container", "misconfig", "root"],
                confidence=0.60,
            ))

        # Environment variables with secrets
        env_vars = container.get("env", [])
        for env in env_vars:
            if isinstance(env, str) and SECRET_ENV_PATTERNS.search(env.split("=")[0]):
                misconfigs.append({
                    "container": name, "issue": "secret_in_env", "severity": "high",
                })
                findings.append(Finding.high(
                    f"Secret in env var: {name}",
                    evidence=f"Container {cid} env contains: {env.split('=')[0]}=***",
                    tags=["container", "misconfig", "secrets"],
                    confidence=0.60,
                ))
                break  # One finding per container for env secrets

    def _collect_containers(self, host: str, ctx) -> list[dict]:
        """Collect container data from state and pipeline."""
        containers = ctx.state.get("containers", {}).get(host, [])
        if containers:
            return containers

        enum_key = f"container_enumeration:{host}"
        enum_result = ctx.pipeline.get(enum_key)
        if enum_result and enum_result.ok:
            return enum_result.data.get("containers", [])

        return []
