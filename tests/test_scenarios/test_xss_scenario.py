"""Tests for XSS scenario."""

from __future__ import annotations

from basilisk.actor.base import HttpResponse
from basilisk.actor.recording import RecordingActor
from basilisk.domain.surface import SearchSurface
from basilisk.domain.target import LiveTarget
from basilisk.scenarios.pentesting.xss_scenario import XssScenario, _detect_context


class TestXssScenario:
    def test_meta(self):
        s = XssScenario()
        assert s.meta.name == "xss_scenario"
        assert s.meta.category == "pentesting"

    async def test_detects_reflected_xss(self):
        actor = RecordingActor()
        # Canary reflects
        actor.set_response(
            "http://vuln.local/search?q=basiliskXSS42",
            HttpResponse(status=200, text="Results for: basiliskXSS42"),
        )
        # Payload reflects unfiltered
        actor.set_response(
            "http://vuln.local/search?q=<script>alert(1)</script>",
            HttpResponse(status=200, text="Results for: <script>alert(1)</script>"),
        )
        target = LiveTarget.domain("vuln.local")
        surfaces = [SearchSurface(
            host="vuln.local", url="http://vuln.local/search",
            params={"q": "test"}, query_param="q",
        )]
        result = await XssScenario().run(target, actor, surfaces, {})
        assert result.ok
        assert len(result.findings) >= 1
        assert any("XSS" in f.title for f in result.findings)

    async def test_no_xss_when_filtered(self):
        actor = RecordingActor()
        actor.set_response(
            "http://clean.local/search?q=basiliskXSS42",
            HttpResponse(status=200, text="Results for: filtered"),
        )
        target = LiveTarget.domain("clean.local")
        surfaces = [SearchSurface(
            host="clean.local", url="http://clean.local/search",
            params={"q": "test"}, query_param="q",
        )]
        result = await XssScenario().run(target, actor, surfaces, {})
        xss_findings = [f for f in result.findings if "XSS" in f.title]
        assert len(xss_findings) == 0

    async def test_data_contains_tests(self):
        actor = RecordingActor()
        target = LiveTarget.domain("test.local")
        surfaces = [SearchSurface(
            host="test.local", url="http://test.local/search",
            params={"q": "test"}, query_param="q",
        )]
        result = await XssScenario().run(target, actor, surfaces, {})
        assert "xss_tests" in result.data

    def test_detect_context_html(self):
        assert _detect_context("<p>basiliskXSS42</p>", "basiliskXSS42") == "html"

    def test_detect_context_script(self):
        html = '<script>var x = "basiliskXSS42";</script>'
        assert _detect_context(html, "basiliskXSS42") == "script"

    def test_detect_context_attribute(self):
        html = '<input value="basiliskXSS42">'
        assert _detect_context(html, "basiliskXSS42") == "attribute"
