"""Tests for the Basilisk fluent API."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from basilisk import Basilisk


def _noop_finding(_f):
    pass


def _noop_step(_s):
    pass


class TestFluentAPI:
    def test_plugins_stores_filter(self):
        b = Basilisk("example.com").plugins("sqli_*", "xss_*")
        assert b._plugin_filter == ["sqli_*", "xss_*"]

    def test_exclude_stores_patterns(self):
        b = Basilisk("example.com").exclude("heavy_*", "slow_*")
        assert b._exclude_patterns == ["heavy_*", "slow_*"]

    def test_on_finding_stores_callback(self):
        b = Basilisk("example.com").on_finding(_noop_finding)
        assert b._on_finding is _noop_finding

    def test_on_step_stores_callback(self):
        b = Basilisk("example.com").on_step(_noop_step)
        assert b._on_step is _noop_step


class TestFluentAPIPassthrough:
    """Verify that run() passes fluent API params to AutonomousRunner."""

    @pytest.fixture
    def _mock_deps(self):
        """Patch AutonomousRunner, TargetLoader, and CompositeActor."""
        with (
            patch(
                "basilisk.engine.autonomous.runner.AutonomousRunner",
            ) as mock_runner_cls,
            patch("basilisk.engine.target_loader.TargetLoader") as mock_loader,
            patch("basilisk.actor.composite.CompositeActor") as mock_actor_cls,
        ):
            mock_runner = AsyncMock()
            mock_runner.run.return_value = MagicMock()
            mock_runner_cls.return_value = mock_runner
            mock_loader.load.return_value = []
            mock_actor_cls.build.return_value = MagicMock()
            yield mock_runner_cls

    @pytest.mark.usefixtures("_mock_deps")
    async def test_run_passes_plugin_filter(self, _mock_deps):
        mock_runner_cls = _mock_deps
        await Basilisk("example.com").plugins("sqli_*").run()
        kwargs = mock_runner_cls.call_args[1]
        assert kwargs["plugin_filter"] == ["sqli_*"]

    @pytest.mark.usefixtures("_mock_deps")
    async def test_run_passes_exclude_patterns(self, _mock_deps):
        mock_runner_cls = _mock_deps
        await Basilisk("example.com").exclude("heavy_*").run()
        kwargs = mock_runner_cls.call_args[1]
        assert kwargs["exclude_patterns"] == ["heavy_*"]

    @pytest.mark.usefixtures("_mock_deps")
    async def test_run_passes_on_finding(self, _mock_deps):
        mock_runner_cls = _mock_deps
        await Basilisk("example.com").on_finding(_noop_finding).run()
        kwargs = mock_runner_cls.call_args[1]
        assert kwargs["on_finding"] is _noop_finding

    @pytest.mark.usefixtures("_mock_deps")
    async def test_run_passes_on_step(self, _mock_deps):
        mock_runner_cls = _mock_deps
        await Basilisk("example.com").on_step(_noop_step).run()
        kwargs = mock_runner_cls.call_args[1]
        assert kwargs["on_step"] is _noop_step
