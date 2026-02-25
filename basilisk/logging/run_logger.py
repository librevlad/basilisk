"""RunLogger — subscribes to EventBus and writes structured + human-readable logs."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from basilisk.events.bus import Event, EventBus, EventType
from basilisk.logging.cleanup import cleanup_old_runs
from basilisk.logging.writer import JsonlWriter, TextWriter


def _ts() -> str:
    """Current time as HH:MM:SS."""
    return datetime.now(UTC).strftime("%H:%M:%S")


class RunLogger:
    """Persistent event logger for a single autonomous run.

    Creates a run directory under ``log_dir`` named
    ``YYYYMMDD_HHMMSS_<target>`` and writes:
    - ``events.jsonl`` — one JSON object per event (machine-readable)
    - ``run.log`` — formatted human-readable log
    """

    def __init__(
        self,
        log_dir: Path,
        target: str,
        bus: EventBus,
        *,
        jsonl: bool = True,
        human_readable: bool = True,
        max_runs: int = 50,
    ) -> None:
        self._bus = bus
        self._jsonl_enabled = jsonl
        self._human_enabled = human_readable
        self._target = target

        # Build run directory
        stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace(":", "_").replace("/", "_")
        self._run_dir = log_dir / f"{stamp}_{safe_target}"
        self._run_dir.mkdir(parents=True, exist_ok=True)

        # Cleanup old runs
        cleanup_old_runs(log_dir, max_runs)

        # Writers
        self._jsonl: JsonlWriter | None = None
        self._text: TextWriter | None = None

        if self._jsonl_enabled:
            self._jsonl = JsonlWriter(self._run_dir / "events.jsonl")
        if self._human_enabled:
            self._text = TextWriter(self._run_dir / "run.log")

        self._subscribe(bus)

    async def open(self) -> None:
        """Open underlying file writers."""
        if self._jsonl is not None:
            await self._jsonl.open()
        if self._text is not None:
            await self._text.open()

    @property
    def run_dir(self) -> Path:
        return self._run_dir

    # -- Event subscriptions -------------------------------------------------

    def _subscribe(self, bus: EventBus) -> None:
        bus.subscribe(EventType.DECISION_MADE, self._on_decision)
        bus.subscribe(EventType.PLUGIN_STARTED, self._on_plugin_started)
        bus.subscribe(EventType.PLUGIN_FINISHED, self._on_plugin_finished)
        bus.subscribe(EventType.GAP_DETECTED, self._on_gap_detected)
        bus.subscribe(EventType.STEP_COMPLETED, self._on_step_completed)
        bus.subscribe(EventType.ENTITY_CREATED, self._on_entity_created)
        bus.subscribe(EventType.ENTITY_UPDATED, self._on_entity_updated)
        bus.subscribe(EventType.OBSERVATION_APPLIED, self._on_observation)
        bus.subscribe(EventType.BELIEF_STRENGTHENED, self._on_belief_strengthened)
        bus.subscribe(EventType.BELIEF_WEAKENED, self._on_belief_weakened)
        bus.subscribe(EventType.HYPOTHESIS_CONFIRMED, self._on_hypothesis_confirmed)
        bus.subscribe(EventType.HYPOTHESIS_REJECTED, self._on_hypothesis_rejected)
        bus.subscribe(EventType.FINDING_VERIFIED, self._on_finding_verified)

    # -- Handlers ------------------------------------------------------------

    def _on_decision(self, event: Event) -> None:
        d = event.data
        step = d.get("step", "?")
        plugin = d.get("plugin", "")
        target = d.get("target", "")
        score = d.get("score", 0.0)
        reasoning = d.get("reasoning", "")

        self._write_jsonl("DECISION_MADE", d, step=step)
        self._write_text(
            step,
            "DECISION",
            f"{plugin} -> {target} (score={score:.2f}) -- {reasoning}",
        )

    def _on_plugin_started(self, event: Event) -> None:
        d = event.data
        step = d.get("step", "?")
        self._write_jsonl("PLUGIN_STARTED", d, step=step)
        self._write_text(step, "PLUGIN", f"Started: {d.get('plugin', '')} on {d.get('target', '')}")

    def _on_plugin_finished(self, event: Event) -> None:
        d = event.data
        step = d.get("step", "?")
        plugin = d.get("plugin", "")
        duration = d.get("duration", 0.0)
        findings = d.get("findings_count", 0)
        self._write_jsonl("PLUGIN_FINISHED", d, step=step)
        msg = f"Finished: {plugin} ({duration:.1f}s, {findings} findings)"
        self._write_text(step, "PLUGIN", msg)

    def _on_gap_detected(self, event: Event) -> None:
        d = event.data
        step = d.get("step", "?")
        count = d.get("count", 0)
        self._write_jsonl("GAP_DETECTED", d, step=step)
        self._write_text(step, "GAPS", f"{count} gaps detected")

    def _on_step_completed(self, event: Event) -> None:
        d = event.data
        step = d.get("step", "?")
        duration = d.get("duration", 0.0)
        entities_gained = d.get("entities_gained", 0)
        batch_size = d.get("batch_size", 0)
        self._write_jsonl("STEP_COMPLETED", d, step=step)
        self._write_text(
            step,
            "STEP",
            f"Step {step} completed ({duration:.1f}s, +{entities_gained} entities, "
            f"batch={batch_size})",
        )

    def _on_entity_created(self, event: Event) -> None:
        d = event.data
        entity_id = d.get("entity_id", "")
        entity_type = d.get("entity_type", "")
        key_data = d.get("key_data", "")
        self._write_jsonl("ENTITY_CREATED", d)
        display = f"{entity_type} {key_data}" if entity_type else entity_id
        self._write_text(None, "ENTITY", f"New: {display}")

    def _on_entity_updated(self, event: Event) -> None:
        d = event.data
        entity_id = d.get("entity_id", "")
        delta = d.get("confidence_delta", 0.0)
        self._write_jsonl("ENTITY_UPDATED", d)
        self._write_text(None, "ENTITY", f"Updated: {entity_id} (confidence delta={delta:+.2f})")

    def _on_observation(self, event: Event) -> None:
        d = event.data
        plugin = d.get("source_plugin", "")
        entity = d.get("entity_id", "")
        was_new = d.get("was_new", False)
        self._write_jsonl("OBSERVATION_APPLIED", d)
        self._write_text(None, "OBS", f"{plugin} -> {entity} (new={'Y' if was_new else 'N'})")

    def _on_belief_strengthened(self, event: Event) -> None:
        d = event.data
        entity_id = d.get("entity_id", "")
        old = d.get("old_confidence", 0.0)
        new = d.get("new_confidence", 0.0)
        self._write_jsonl("BELIEF_STRENGTHENED", d)
        self._write_text(None, "BELIEF", f"^ {entity_id}: {old:.2f} -> {new:.2f}")

    def _on_belief_weakened(self, event: Event) -> None:
        d = event.data
        entity_id = d.get("entity_id", "")
        old = d.get("old_confidence", 0.0)
        new = d.get("new_confidence", 0.0)
        self._write_jsonl("BELIEF_WEAKENED", d)
        self._write_text(None, "BELIEF", f"v {entity_id}: {old:.2f} -> {new:.2f}")

    def _on_hypothesis_confirmed(self, event: Event) -> None:
        d = event.data
        statement = d.get("statement", "")
        self._write_jsonl("HYPOTHESIS_CONFIRMED", d)
        self._write_text(None, "HYPOTHESIS", f"CONFIRMED: {statement}")

    def _on_hypothesis_rejected(self, event: Event) -> None:
        d = event.data
        statement = d.get("statement", "")
        self._write_jsonl("HYPOTHESIS_REJECTED", d)
        self._write_text(None, "HYPOTHESIS", f"REJECTED: {statement}")

    def _on_finding_verified(self, event: Event) -> None:
        d = event.data
        entity_id = d.get("entity_id", "")
        plugin = d.get("plugin", "")
        self._write_jsonl("FINDING_VERIFIED", d)
        self._write_text(None, "FINDING", f"Verified: {entity_id} by {plugin}")

    # -- Write helpers -------------------------------------------------------

    def _write_jsonl(
        self,
        event_type: str,
        data: dict[str, Any],
        *,
        step: Any = None,
    ) -> None:
        if self._jsonl is None:
            return
        record: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "event_type": event_type,
        }
        if step is not None:
            record["step"] = step
        record.update(data)
        # Schedule async write from sync handler
        import asyncio

        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._jsonl.write(record))
        except RuntimeError:
            pass

    def _write_text(
        self,
        step: Any,
        tag: str,
        message: str,
    ) -> None:
        if self._text is None:
            return
        ts = _ts()
        step_str = f" [STEP {step}]" if step is not None else ""
        line = f"[{ts}]{step_str} [{tag}] {message}"
        import asyncio

        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._text.write(line))
        except RuntimeError:
            pass

    # -- Summary -------------------------------------------------------------

    async def log_summary(
        self,
        timeline: Any,
        history: Any,
        *,
        termination_reason: str = "",
        graph: Any = None,
    ) -> None:
        """Write final summary section to run.log."""
        if self._text is None:
            return

        now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
        steps = timeline.total_steps if timeline else 0

        # Collect stats from graph
        entity_count = 0
        host_count = 0
        service_count = 0
        endpoint_count = 0
        finding_count = 0
        findings_list: list[Any] = []
        duration = 0.0

        if graph is not None:
            entity_count = graph.entity_count
            host_count = len(graph.hosts())
            service_count = len(graph.services())
            endpoint_count = len(graph.endpoints())
            findings_list = graph.findings()
            finding_count = len(findings_list)

        if timeline and timeline.entries:
            duration = sum(e.duration for e in timeline.entries)

        # Count decisions
        decisions_list = []
        if history is not None and hasattr(history, "decisions"):
            decisions_list = history.decisions

        # Severity breakdown
        sev_counts: dict[str, int] = {}
        for f in findings_list:
            sev = f.data.get("severity", "info").lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        sev_summary = ", ".join(
            f"{count} {name}" for name, count in sorted(sev_counts.items(), reverse=True)
        )

        sep = "=" * 43
        lines = [
            "",
            sep,
            f" RUN SUMMARY -- {self._target} -- {now}",
            sep,
            f" Steps:     {steps}",
            f" Duration:  {duration:.1f}s",
            f" Entities:  {entity_count} ({host_count} hosts, {service_count} services, "
            f"{endpoint_count} endpoints)",
            f" Findings:  {finding_count} ({sev_summary})" if sev_summary
            else f" Findings:  {finding_count}",
            f" Decisions: {len(decisions_list)}",
            f" Termination: {termination_reason}",
            sep,
        ]

        # Top findings
        if findings_list:
            lines.append("")
            lines.append(" TOP FINDINGS:")
            sorted_findings = sorted(
                findings_list,
                key=lambda f: f.data.get("severity_value", 0),
                reverse=True,
            )
            for f in sorted_findings[:10]:
                sev = f.data.get("severity", "INFO").upper()
                title = f.data.get("title", f.id[:16])
                conf = f.confidence
                lines.append(f"  [{sev}] {title} (confidence: {conf:.2f})")

        # Timeline summary
        if timeline and timeline.entries:
            lines.append("")
            lines.append(" TIMELINE:")
            lines.append(timeline.summary())

        for line in lines:
            await self._text.write(line)

    async def close(self) -> None:
        """Flush and close both writers."""
        if self._jsonl is not None:
            await self._jsonl.close()
        if self._text is not None:
            await self._text.close()
