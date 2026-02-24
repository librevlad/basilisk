"""Tests for DNS enumeration scenario."""

from __future__ import annotations

from basilisk.actor.recording import RecordingActor
from basilisk.domain.target import LiveTarget
from basilisk.scenarios.recon.dns_scenario import DnsScenario


class TestDnsScenario:
    def test_meta(self):
        s = DnsScenario()
        assert s.meta.name == "dns_scenario"
        assert s.meta.category == "recon"
        assert s.meta.cost_score == 1.0

    async def test_resolves_records(self):
        actor = RecordingActor()
        actor.set_dns("example.com", ["1.2.3.4"])
        target = LiveTarget.domain("example.com")
        result = await DnsScenario().run(target, actor, [], {})
        assert result.ok
        assert len(result.data["dns_records"]) > 0
        assert "1.2.3.4" in result.data["ips"]

    async def test_missing_spf_finding(self):
        actor = RecordingActor()
        # Only A record, no TXT
        actor.set_dns("no-spf.com", ["1.2.3.4"])
        target = LiveTarget.domain("no-spf.com")
        result = await DnsScenario().run(target, actor, [], {})
        spf_findings = [f for f in result.findings if "SPF" in f.title]
        assert len(spf_findings) >= 1

    async def test_missing_dmarc_finding(self):
        actor = RecordingActor()
        actor.set_dns("no-dmarc.com", ["1.2.3.4"])
        target = LiveTarget.domain("no-dmarc.com")
        result = await DnsScenario().run(target, actor, [], {})
        dmarc_findings = [f for f in result.findings if "DMARC" in f.title]
        assert len(dmarc_findings) >= 1

    async def test_empty_dns(self):
        actor = RecordingActor()
        target = LiveTarget.domain("nonexistent.test")
        result = await DnsScenario().run(target, actor, [], {})
        assert result.ok
        assert result.data["ips"] == []

    async def test_scenario_name_in_findings(self):
        actor = RecordingActor()
        target = LiveTarget.domain("test.com")
        result = await DnsScenario().run(target, actor, [], {})
        for f in result.findings:
            assert f.scenario_name == "dns_scenario"
