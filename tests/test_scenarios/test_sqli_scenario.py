"""Tests for SQL injection scenario."""

from __future__ import annotations

from basilisk.actor.base import HttpResponse
from basilisk.actor.recording import RecordingActor
from basilisk.domain.surface import SearchSurface, Surface
from basilisk.domain.target import LiveTarget
from basilisk.scenarios.pentesting.sqli_scenario import SqliScenario


class TestSqliScenario:
    def test_meta(self):
        s = SqliScenario()
        assert s.meta.name == "sqli_scenario"
        assert s.meta.category == "pentesting"
        assert s.meta.timeout == 120.0

    async def test_detects_error_based_sqli(self):
        actor = RecordingActor()
        # Set up a response with SQL error
        for payload in ["'", "' OR '1'='1", "1 OR 1=1--", "' UNION SELECT NULL--",
                        "1' AND SLEEP(0)--", "'; WAITFOR DELAY '0:0:0'--"]:
            actor.set_response(
                f"http://vuln.local/search?q={payload}",
                HttpResponse(
                    status=500,
                    text=f"Error: you have an error in your sql syntax near '{payload}'",
                ),
            )
        target = LiveTarget.domain("vuln.local")
        surfaces = [SearchSurface(
            host="vuln.local", url="http://vuln.local/search",
            params={"q": "test"}, query_param="q",
        )]
        result = await SqliScenario().run(target, actor, surfaces, {})
        assert result.ok
        assert len(result.findings) >= 1
        assert any("SQL Injection" in f.title for f in result.findings)

    async def test_no_sqli_clean_response(self):
        actor = RecordingActor()
        target = LiveTarget.domain("clean.local")
        surfaces = [Surface(
            host="clean.local", url="http://clean.local/page",
            params={"id": "1"},
        )]
        result = await SqliScenario().run(target, actor, surfaces, {})
        assert result.ok
        sqli_findings = [f for f in result.findings if "SQL" in f.title]
        assert len(sqli_findings) == 0

    async def test_default_surfaces_when_none(self):
        actor = RecordingActor()
        target = LiveTarget.domain("example.com")
        result = await SqliScenario().run(target, actor, [], {})
        assert result.ok
        assert "sqli_tests" in result.data

    async def test_dedup_same_param(self):
        actor = RecordingActor()
        target = LiveTarget.domain("test.local")
        surfaces = [
            Surface(host="test.local", url="http://test.local/a", params={"id": "1"}),
            Surface(host="test.local", url="http://test.local/a", params={"id": "2"}),
        ]
        result = await SqliScenario().run(target, actor, surfaces, {})
        assert result.ok

    async def test_accepts_any_target(self):
        s = SqliScenario()
        assert s.accepts(LiveTarget.domain("example.com"))

    async def test_findings_have_proof(self):
        actor = RecordingActor()
        actor.set_response(
            "http://vuln.local/search?q='",
            HttpResponse(status=500, text="you have an error in your sql syntax"),
        )
        target = LiveTarget.domain("vuln.local")
        surfaces = [SearchSurface(
            host="vuln.local", url="http://vuln.local/search",
            params={"q": "test"}, query_param="q",
        )]
        result = await SqliScenario().run(target, actor, surfaces, {})
        for f in result.findings:
            if f.severity >= 3:  # HIGH+
                assert f.proof is not None

    async def test_data_contains_tests(self):
        actor = RecordingActor()
        target = LiveTarget.domain("test.local")
        surfaces = [Surface(host="test.local", url="http://test.local/", params={"x": "1"})]
        result = await SqliScenario().run(target, actor, surfaces, {})
        assert isinstance(result.data["sqli_tests"], list)
