"""Tests for context adapter — Actor -> PluginContext mapping."""

from __future__ import annotations

from unittest.mock import MagicMock

from basilisk.actor.composite import CompositeActor
from basilisk.bridge.context_adapter import ContextAdapter
from basilisk.config import Settings


class TestContextAdapter:
    def test_basic_build(self):
        actor = CompositeActor(
            http_client=MagicMock(),
            dns_client=MagicMock(),
            net_utils=MagicMock(),
            rate_limiter=MagicMock(),
        )
        settings = Settings.load()
        ctx = ContextAdapter.build(actor, settings)
        assert ctx.http is actor.http_client
        assert ctx.dns is actor.dns_client
        assert ctx.net is actor.net_utils
        assert ctx.rate is actor.rate_limiter
        assert ctx.config is settings

    def test_tools_mapping(self):
        actor = CompositeActor()
        settings = Settings.load()
        wordlists = MagicMock()
        payloads = MagicMock()
        tools = {"wordlists": wordlists, "payloads": payloads}
        ctx = ContextAdapter.build(actor, settings, tools=tools)
        assert ctx.wordlists is wordlists
        assert ctx.payloads is payloads

    def test_state_passthrough(self):
        actor = CompositeActor()
        settings = Settings.load()
        state = {"http_scheme": {"example.com": "https"}}
        ctx = ContextAdapter.build(actor, settings, state=state)
        assert ctx.state["http_scheme"]["example.com"] == "https"

    def test_default_state(self):
        actor = CompositeActor()
        settings = Settings.load()
        ctx = ContextAdapter.build(actor, settings)
        assert ctx.state == {}

    def test_deadline_propagation(self):
        actor = CompositeActor(deadline=0.0)
        settings = Settings.load()
        ctx = ContextAdapter.build(actor, settings)
        assert ctx._deadline == 0.0

    def test_browser_mapping(self):
        browser = MagicMock()
        actor = CompositeActor(browser=browser)
        settings = Settings.load()
        ctx = ContextAdapter.build(actor, settings)
        assert ctx.browser is browser

    def test_none_tools(self):
        actor = CompositeActor()
        settings = Settings.load()
        ctx = ContextAdapter.build(actor, settings, tools=None)
        assert ctx.wordlists is None
        assert ctx.payloads is None

    def test_pipeline_from_tools(self):
        actor = CompositeActor()
        settings = Settings.load()
        pipeline = {"ssl_check:example.com": MagicMock()}
        ctx = ContextAdapter.build(actor, settings, tools={"pipeline": pipeline})
        assert "ssl_check:example.com" in ctx.pipeline
