"""LiveDisplay — Rich Live visualization driven by EventBus."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from rich.console import Console, Group
from rich.live import Live

from basilisk.display.panels import (
    activity_panel,
    findings_panel,
    header_panel,
    hypothesis_panel,
    knowledge_panel,
)
from basilisk.display.state import DisplayState, PluginActivity
from basilisk.knowledge.snapshot import KnowledgeSnapshotStore

if TYPE_CHECKING:
    from basilisk.events.bus import Event, EventBus


class LiveDisplay:
    """Real-time Rich Live display driven by EventBus events.

    Knowledge data flows through KnowledgeSnapshotStore (snapshot-driven).
    Activity data (plugin started/finished) flows through direct event handlers.
    Render is gated on snapshot fingerprint change — no duplicate output.

    Usage::

        display = LiveDisplay(bus, max_steps=100)
        display.start()
        # ... run autonomous loop ...
        state = display.stop()
    """

    def __init__(
        self,
        bus: EventBus,
        max_steps: int = 100,
        verbose: bool = False,
        console: Console | None = None,
        refresh_rate: float = 4.0,
    ) -> None:
        self._bus = bus
        self._verbose = verbose
        self._console = console or Console()
        self._refresh_rate = refresh_rate
        self.state = DisplayState(max_steps=max_steps)
        self._live: Live | None = None
        self._store = KnowledgeSnapshotStore()
        self._store.subscribe(bus)
        self._subscribe(bus)

    def _subscribe(self, bus: EventBus) -> None:
        """Subscribe to activity events (knowledge is handled by store)."""
        from basilisk.events.bus import EventType

        bus.subscribe(EventType.GAP_DETECTED, self._on_gap_detected)
        bus.subscribe(EventType.PLUGIN_STARTED, self._on_plugin_started)
        bus.subscribe(EventType.PLUGIN_FINISHED, self._on_plugin_finished)
        bus.subscribe(EventType.STEP_COMPLETED, self._on_step_completed)
        # Knowledge events (ENTITY_CREATED/UPDATED) handled by KnowledgeSnapshotStore
        # Findings come from snapshot, not direct events
        bus.subscribe(EventType.BELIEF_STRENGTHENED, self._on_belief_strengthened)
        bus.subscribe(EventType.BELIEF_WEAKENED, self._on_belief_weakened)
        bus.subscribe(EventType.HYPOTHESIS_CONFIRMED, self._on_hypothesis_confirmed)
        bus.subscribe(EventType.HYPOTHESIS_REJECTED, self._on_hypothesis_rejected)

    def start(self) -> None:
        """Begin Rich Live display."""
        self._live = Live(
            self._render(),
            console=self._console,
            refresh_per_second=self._refresh_rate,
            transient=True,
        )
        self._live.start()

    def stop(self) -> DisplayState:
        """Stop Rich Live display and return final state."""
        self.state.finished = True
        # Final snapshot sync
        snapshot = self._store.snapshot()
        self.state.update_from_snapshot(snapshot)
        if self._live is not None:
            self._live.stop()
            self._live = None
        return self.state

    def _render(self) -> Group:
        """Build the full display layout."""
        panels = [header_panel(self.state), activity_panel(self.state)]

        if self.state.findings:
            panels.append(findings_panel(self.state))

        if self._verbose:
            panels.append(knowledge_panel(self.state))
            if (
                self.state.hypotheses_active
                or self.state.hypotheses_confirmed
                or self.state.hypotheses_rejected
            ):
                panels.append(hypothesis_panel(self.state))

        return Group(*panels)

    def _refresh(self) -> None:
        """Update the Live display — gated on snapshot change."""
        snapshot = self._store.snapshot()
        self.state.update_from_snapshot(snapshot)
        if self._live is not None:
            self._live.update(self._render())

    # --- Event handlers (sync, fast O(1) mutations) ---

    def _on_gap_detected(self, event: Event) -> None:
        self.state.gap_count = event.data.get("count", 0)

    def _on_plugin_started(self, event: Event) -> None:
        plugin = event.data.get("plugin", "")
        target = event.data.get("target", "")
        self.state.active_plugins.append(
            PluginActivity(name=plugin, target=target, started_at=time.monotonic())
        )
        self._refresh()

    def _on_plugin_finished(self, event: Event) -> None:
        plugin = event.data.get("plugin", "")
        target = event.data.get("target", "")
        duration = event.data.get("duration", 0.0)
        findings_count = event.data.get("findings_count", 0)

        # Move from active to recent
        remaining = []
        moved = False
        for p in self.state.active_plugins:
            if not moved and p.name == plugin and p.target == target:
                p.finished = True
                p.duration = duration
                p.findings_count = findings_count
                self.state.recent_plugins.append(p)
                moved = True
            else:
                remaining.append(p)
        self.state.active_plugins = remaining

        # Keep recent list bounded
        if len(self.state.recent_plugins) > 10:
            self.state.recent_plugins = self.state.recent_plugins[-10:]

        self._refresh()

    def _on_step_completed(self, event: Event) -> None:
        self.state.step = event.data.get("step", self.state.step)
        self.state.total_entities = event.data.get("entities", self.state.total_entities)
        self.state.total_relations = event.data.get("relations", self.state.total_relations)
        self._refresh()

    def _on_belief_strengthened(self, event: Event) -> None:
        self.state.beliefs_strengthened += 1

    def _on_belief_weakened(self, event: Event) -> None:
        self.state.beliefs_weakened += 1

    def _on_hypothesis_confirmed(self, event: Event) -> None:
        self.state.hypotheses_confirmed += 1
        if self.state.hypotheses_active > 0:
            self.state.hypotheses_active -= 1
        self._refresh()

    def _on_hypothesis_rejected(self, event: Event) -> None:
        self.state.hypotheses_rejected += 1
        if self.state.hypotheses_active > 0:
            self.state.hypotheses_active -= 1
        self._refresh()
