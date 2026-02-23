"""Tests for TUI app and screens — import and structure checks."""

from __future__ import annotations


def test_app_import():
    """BasiliskApp can be imported."""
    from basilisk.tui.app import BasiliskApp
    assert BasiliskApp is not None
    assert BasiliskApp.TITLE == "Basilisk"


def test_screens_import():
    """All screens can be imported."""
    from basilisk.tui.screens import (
        ConfigScreen,
        DashboardScreen,
        ProjectsScreen,
        ReportScreen,
        TargetsScreen,
    )
    assert all([
        ConfigScreen, DashboardScreen, ProjectsScreen,
        ReportScreen, TargetsScreen,
    ])


def test_widgets_import():
    """All widgets can be imported."""
    from basilisk.tui.widgets import (
        FindingFeedWidget,
        PhaseProgressWidget,
        StatsPanelWidget,
        TargetTableWidget,
    )
    assert all([
        FindingFeedWidget, PhaseProgressWidget,
        StatsPanelWidget, TargetTableWidget,
    ])


def test_app_screens_registered():
    """BasiliskApp has correct SCREENS dict."""
    from basilisk.tui.app import BasiliskApp
    assert "projects" in BasiliskApp.SCREENS
    assert "dashboard" in BasiliskApp.SCREENS


def test_app_bindings():
    """BasiliskApp has expected key bindings."""
    from basilisk.tui.app import BasiliskApp
    binding_keys = [b[0] for b in BasiliskApp.BINDINGS]
    assert "q" in binding_keys
    assert "p" in binding_keys
    assert "d" in binding_keys


def test_config_presets():
    """PLUGIN_PRESETS has all four categories."""
    from basilisk.tui.screens.config import PLUGIN_PRESETS
    assert "recon" in PLUGIN_PRESETS
    assert "scanning" in PLUGIN_PRESETS
    assert "analysis" in PLUGIN_PRESETS
    assert "pentesting" in PLUGIN_PRESETS


def test_config_presets_structure():
    """Each preset entry has (name, display_name, default_enabled)."""
    from basilisk.tui.screens.config import PLUGIN_PRESETS
    for category, plugins in PLUGIN_PRESETS.items():
        for entry in plugins:
            assert len(entry) == 3, f"Bad entry in {category}: {entry}"
            name, display, default = entry
            assert isinstance(name, str)
            assert isinstance(display, str)
            assert isinstance(default, bool)


def test_projects_screen_bindings():
    """ProjectsScreen has expected bindings."""
    from basilisk.tui.screens.projects import ProjectsScreen
    binding_keys = [b[0] for b in ProjectsScreen.BINDINGS]
    assert "n" in binding_keys
    assert "d" in binding_keys


def test_dashboard_screen_bindings():
    """DashboardScreen has expected bindings."""
    from basilisk.tui.screens.dashboard import DashboardScreen
    binding_keys = [b[0] for b in DashboardScreen.BINDINGS]
    assert "p" in binding_keys
    assert "e" in binding_keys


def test_targets_screen_bindings():
    """TargetsScreen has expected bindings."""
    from basilisk.tui.screens.targets import TargetsScreen
    binding_keys = [b[0] for b in TargetsScreen.BINDINGS]
    assert "a" in binding_keys
    assert "i" in binding_keys
