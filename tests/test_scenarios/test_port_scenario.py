"""Tests for port scan scenario."""

from __future__ import annotations

from basilisk.actor.recording import RecordingActor
from basilisk.domain.target import LiveTarget
from basilisk.scenarios.scanning.port_scenario import PortScenario


class TestPortScenario:
    def test_meta(self):
        s = PortScenario()
        assert s.meta.name == "port_scenario"
        assert s.meta.category == "scanning"

    async def test_finds_open_ports(self):
        actor = RecordingActor()
        actor.set_tcp("scan.local", 22, True)
        actor.set_tcp("scan.local", 80, True)
        actor.set_tcp("scan.local", 443, True)
        actor.set_banner("scan.local", 22, "SSH-2.0-OpenSSH_8.9")
        target = LiveTarget.domain("scan.local")
        result = await PortScenario().run(target, actor, [], {})
        assert result.ok
        assert len(result.data["open_ports"]) == 3
        services = {p["service"] for p in result.data["open_ports"]}
        assert "SSH" in services
        assert "HTTP" in services

    async def test_risky_port_finding(self):
        actor = RecordingActor()
        actor.set_tcp("risky.local", 6379, True)
        actor.set_banner("risky.local", 6379, "Redis 7.0")
        target = LiveTarget.domain("risky.local")
        result = await PortScenario().run(target, actor, [], {})
        redis_findings = [f for f in result.findings if "Redis" in f.title]
        assert len(redis_findings) >= 1
        assert redis_findings[0].severity >= 3  # HIGH

    async def test_no_open_ports(self):
        actor = RecordingActor()
        target = LiveTarget.domain("closed.local")
        result = await PortScenario().run(target, actor, [], {})
        assert result.ok
        assert result.data["open_ports"] == []

    async def test_docker_api_critical(self):
        actor = RecordingActor()
        actor.set_tcp("docker.local", 2375, True)
        target = LiveTarget.domain("docker.local")
        result = await PortScenario().run(target, actor, [], {})
        docker_findings = [f for f in result.findings if "Docker" in f.title]
        assert len(docker_findings) >= 1
        assert docker_findings[0].severity == 4  # CRITICAL

    async def test_info_summary_finding(self):
        actor = RecordingActor()
        actor.set_tcp("multi.local", 80, True)
        actor.set_tcp("multi.local", 443, True)
        target = LiveTarget.domain("multi.local")
        result = await PortScenario().run(target, actor, [], {})
        info = [f for f in result.findings if "open port(s)" in f.title]
        assert len(info) == 1

    async def test_data_structure(self):
        actor = RecordingActor()
        actor.set_tcp("test.local", 80, True)
        target = LiveTarget.domain("test.local")
        result = await PortScenario().run(target, actor, [], {})
        assert "scan_ports_count" in result.data
        assert result.data["scan_ports_count"] > 0
