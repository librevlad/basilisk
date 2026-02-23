"""Tests for container security plugins."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

from basilisk.core.plugin import PluginCategory
from basilisk.models.result import Finding, PluginResult, Severity
from basilisk.models.target import Target
from basilisk.plugins.analysis.container_config_audit import ContainerConfigAuditPlugin
from basilisk.plugins.analysis.image_fingerprint import ImageFingerprintPlugin
from basilisk.plugins.exploitation.container_escape_probe import ContainerEscapeProbePlugin
from basilisk.plugins.exploitation.container_verification import ContainerVerificationPlugin
from basilisk.plugins.scanning.container_discovery import ContainerDiscoveryPlugin
from basilisk.plugins.scanning.container_enumeration import ContainerEnumerationPlugin
from basilisk.plugins.scanning.registry_lookup import RegistryLookupPlugin


def _make_ctx(**overrides):
    """Create a mock PluginContext."""
    ctx = MagicMock()
    ctx.pipeline = overrides.get("pipeline", {})
    ctx.state = overrides.get("state", {})
    ctx.should_stop = False
    ctx.rate = AsyncMock()
    ctx.rate.__aenter__ = AsyncMock()
    ctx.rate.__aexit__ = AsyncMock()
    if "http" in overrides:
        ctx.http = overrides["http"]
    else:
        ctx.http = AsyncMock()
    return ctx


def _make_response(status=200, body=""):
    resp = AsyncMock()
    resp.status = status
    resp.text = AsyncMock(return_value=body)
    return resp


class TestContainerDiscoveryMeta:
    def test_meta(self):
        assert ContainerDiscoveryPlugin.meta.name == "container_discovery"
        assert ContainerDiscoveryPlugin.meta.category == PluginCategory.SCANNING
        assert ContainerDiscoveryPlugin.meta.requires_http is False
        assert "container_runtimes" in ContainerDiscoveryPlugin.meta.produces


class TestContainerEnumerationMeta:
    def test_meta(self):
        assert ContainerEnumerationPlugin.meta.name == "container_enumeration"
        assert ContainerEnumerationPlugin.meta.category == PluginCategory.SCANNING
        assert "container_discovery" in ContainerEnumerationPlugin.meta.depends_on
        assert "containers" in ContainerEnumerationPlugin.meta.produces
        assert "images" in ContainerEnumerationPlugin.meta.produces


class TestImageFingerprintMeta:
    def test_meta(self):
        assert ImageFingerprintPlugin.meta.name == "image_fingerprint"
        assert ImageFingerprintPlugin.meta.category == PluginCategory.ANALYSIS
        assert "container_enumeration" in ImageFingerprintPlugin.meta.depends_on


class TestContainerConfigAuditMeta:
    def test_meta(self):
        assert ContainerConfigAuditPlugin.meta.name == "container_config_audit"
        assert ContainerConfigAuditPlugin.meta.category == PluginCategory.ANALYSIS
        assert "container_enumeration" in ContainerConfigAuditPlugin.meta.depends_on


class TestContainerEscapeProbeMeta:
    def test_meta(self):
        assert ContainerEscapeProbePlugin.meta.name == "container_escape_probe"
        assert ContainerEscapeProbePlugin.meta.category == PluginCategory.EXPLOITATION
        assert ContainerEscapeProbePlugin.meta.risk_level == "destructive"


class TestRegistryLookupMeta:
    def test_meta(self):
        assert RegistryLookupPlugin.meta.name == "registry_lookup"
        assert RegistryLookupPlugin.meta.category == PluginCategory.SCANNING
        assert RegistryLookupPlugin.meta.requires_http is True


class TestContainerVerificationMeta:
    def test_meta(self):
        assert ContainerVerificationPlugin.meta.name == "container_verification"
        assert ContainerVerificationPlugin.meta.category == PluginCategory.EXPLOITATION
        assert "container_config_audit" in ContainerVerificationPlugin.meta.depends_on
        assert "container_escape_probe" in ContainerVerificationPlugin.meta.depends_on


class TestContainerDiscoveryRun:
    async def test_docker_api_found(self):
        docker_resp = _make_response(200, json.dumps({
            "ApiVersion": "1.44", "Version": "24.0.7",
        }))
        http = AsyncMock()
        http.get = AsyncMock(return_value=docker_resp)
        ctx = _make_ctx(http=http)
        target = Target.domain("example.com")

        plugin = ContainerDiscoveryPlugin()
        result = await plugin.run(target, ctx)

        assert result.ok
        assert len(result.data["container_runtimes"]) > 0
        assert result.data["container_runtimes"][0]["name"] == "docker"
        high_findings = [f for f in result.findings if f.severity.value >= Severity.HIGH.value]
        assert len(high_findings) > 0

    async def test_no_docker_api(self):
        http = AsyncMock()
        http.get = AsyncMock(return_value=_make_response(404, ""))
        ctx = _make_ctx(http=http)
        target = Target.domain("example.com")

        plugin = ContainerDiscoveryPlugin()
        result = await plugin.run(target, ctx)

        assert result.ok
        assert len(result.data["container_runtimes"]) == 0

    async def test_reuse_docker_exploit_data(self):
        docker_result = PluginResult.success(
            "docker_exploit", "example.com",
            data={"accessible": True, "api_url": "http://example.com:2375"},
        )
        ctx = _make_ctx(pipeline={"docker_exploit:example.com": docker_result})
        target = Target.domain("example.com")

        plugin = ContainerDiscoveryPlugin()
        result = await plugin.run(target, ctx)

        assert result.ok
        assert len(result.data["container_runtimes"]) == 1


class TestContainerEnumerationRun:
    async def test_enumerate_containers(self):
        containers_json = json.dumps([{
            "Id": "abc123def456",
            "Image": "nginx:1.24",
            "State": "running",
            "Names": ["/web"],
            "Ports": [],
            "Mounts": [],
            "HostConfig": {"NetworkMode": "bridge", "Privileged": False},
        }])
        images_json = json.dumps([{
            "Id": "sha256:abc123",
            "RepoTags": ["nginx:1.24"],
            "Size": 1024000,
            "Created": 1700000000,
        }])

        http = AsyncMock()
        http.get = AsyncMock(side_effect=[
            _make_response(200, containers_json),
            _make_response(200, images_json),
        ])
        ctx = _make_ctx(
            http=http,
            state={"container_runtimes": {"example.com": [{"api_url": "http://example.com:2375"}]}},
        )
        target = Target.domain("example.com")

        plugin = ContainerEnumerationPlugin()
        result = await plugin.run(target, ctx)

        assert result.ok
        assert len(result.data["containers"]) == 1
        assert result.data["containers"][0]["id"] == "abc123def456"[:12]
        assert len(result.data["images"]) == 1


class TestContainerConfigAuditRun:
    async def test_privileged_container(self):
        ctx = _make_ctx(state={
            "containers": {"example.com": [{
                "id": "abc123",
                "names": ["/privileged-app"],
                "privileged": True,
                "mounts": [],
                "capabilities": [],
                "network_mode": "bridge",
                "user": "root",
            }]},
        })
        target = Target.domain("example.com")

        plugin = ContainerConfigAuditPlugin()
        result = await plugin.run(target, ctx)

        assert result.ok
        critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1  # privileged flag

    async def test_docker_socket_mount(self):
        ctx = _make_ctx(state={
            "containers": {"example.com": [{
                "id": "abc123",
                "names": ["/app"],
                "privileged": False,
                "mounts": ["/var/run/docker.sock"],
                "capabilities": [],
                "network_mode": "bridge",
                "user": "",
            }]},
        })
        target = Target.domain("example.com")

        plugin = ContainerConfigAuditPlugin()
        result = await plugin.run(target, ctx)

        assert result.ok
        critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1

    async def test_cap_sys_admin(self):
        ctx = _make_ctx(state={
            "containers": {"example.com": [{
                "id": "abc123",
                "names": ["/app"],
                "privileged": False,
                "mounts": [],
                "capabilities": ["CAP_SYS_ADMIN"],
                "network_mode": "bridge",
                "user": "app",
            }]},
        })
        target = Target.domain("example.com")

        plugin = ContainerConfigAuditPlugin()
        result = await plugin.run(target, ctx)

        assert result.ok
        high = [f for f in result.findings if f.severity.value >= Severity.HIGH.value]
        assert len(high) >= 1


class TestContainerEscapeProbeRun:
    async def test_privileged_escape(self):
        ctx = _make_ctx(state={
            "containers": {"example.com": [{
                "id": "abc123",
                "names": ["/app"],
                "privileged": True,
                "mounts": [],
                "capabilities": [],
                "pid_mode": "",
            }]},
        })
        target = Target.domain("example.com")

        plugin = ContainerEscapeProbePlugin()
        result = await plugin.run(target, ctx)

        assert result.ok
        escapes = result.data["container_escapes"]
        assert len(escapes) >= 1
        assert any(e["vector"] == "privileged" for e in escapes)

    async def test_cap_sys_admin_escape(self):
        ctx = _make_ctx(state={
            "containers": {"example.com": [{
                "id": "abc123",
                "names": ["/app"],
                "privileged": False,
                "mounts": [],
                "capabilities": ["CAP_SYS_ADMIN"],
                "pid_mode": "",
            }]},
        })
        target = Target.domain("example.com")

        plugin = ContainerEscapeProbePlugin()
        result = await plugin.run(target, ctx)

        assert result.ok
        escapes = result.data["container_escapes"]
        assert any(e["vector"] == "cap_sys_admin" for e in escapes)


class TestImageFingerprintRun:
    async def test_outdated_base_image(self):
        ctx = _make_ctx(state={
            "containers": {"example.com": [{
                "image": "alpine:3.16",
                "id": "abc123",
            }]},
        })
        target = Target.domain("example.com")

        plugin = ImageFingerprintPlugin()
        result = await plugin.run(target, ctx)

        assert result.ok
        high = [f for f in result.findings if f.severity.value >= Severity.HIGH.value]
        assert len(high) >= 1

    async def test_latest_tag(self):
        ctx = _make_ctx(state={
            "containers": {"example.com": [{
                "image": "nginx:latest",
                "id": "abc123",
            }]},
        })
        target = Target.domain("example.com")

        plugin = ImageFingerprintPlugin()
        result = await plugin.run(target, ctx)

        assert result.ok
        medium = [f for f in result.findings if f.severity == Severity.MEDIUM]
        assert len(medium) >= 1


class TestRegistryLookupRun:
    async def test_exposed_registry(self):
        v2_resp = _make_response(200, "{}")
        catalog_resp = _make_response(200, json.dumps({
            "repositories": ["myapp", "backend", "frontend"],
        }))
        http = AsyncMock()
        http.get = AsyncMock(side_effect=[v2_resp, catalog_resp, _make_response(404)])
        ctx = _make_ctx(http=http)
        target = Target.domain("example.com")

        plugin = RegistryLookupPlugin()
        result = await plugin.run(target, ctx)

        assert result.ok
        high = [f for f in result.findings if f.severity.value >= Severity.HIGH.value]
        assert len(high) >= 1
        assert len(result.data["registries"]) >= 1

    async def test_no_registry(self):
        http = AsyncMock()
        http.get = AsyncMock(return_value=_make_response(404, ""))
        ctx = _make_ctx(http=http)
        target = Target.domain("example.com")

        plugin = RegistryLookupPlugin()
        result = await plugin.run(target, ctx)

        assert result.ok
        assert len(result.data["registries"]) == 0


class TestContainerVerificationRun:
    async def test_verify_privileged(self):
        # Create a mock finding with container tag
        finding = Finding.critical(
            "Privileged container: /app",
            evidence="Container abc runs with --privileged flag",
            tags=["container", "misconfig", "privileged"],
        )
        config_result = PluginResult.success(
            "container_config_audit", "example.com",
            findings=[finding],
        )
        ctx = _make_ctx(
            pipeline={"container_config_audit:example.com": config_result},
            state={"containers": {"example.com": [{
                "id": "abc", "privileged": True, "names": ["/app"],
                "mounts": [], "capabilities": [], "pid_mode": "", "network_mode": "bridge",
            }]}},
        )
        target = Target.domain("example.com")

        plugin = ContainerVerificationPlugin()
        result = await plugin.run(target, ctx)

        assert result.ok
        verified = result.data["verified_container_findings"]
        assert any(v.get("confirmed") for v in verified)
