"""Target loader — CLI args -> BaseTarget instances."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from basilisk.domain.target import BaseTarget, LiveTarget, TrainingTarget
from basilisk.utils.net import is_ip_or_local as _is_ip_or_local

if TYPE_CHECKING:
    from basilisk.config import Settings


def _split_host_port(raw: str) -> tuple[str, int | None]:
    """Split 'host:port' into (host, port)."""
    if raw.startswith("["):
        bracket_end = raw.find("]")
        if bracket_end != -1 and bracket_end + 1 < len(raw) and raw[bracket_end + 1] == ":":
            host = raw[1:bracket_end]
            try:
                return host, int(raw[bracket_end + 2:])
            except ValueError:
                return raw, None
        return raw[1:bracket_end] if bracket_end != -1 else raw, None
    if "." in raw and ":" in raw:
        host, _, port_s = raw.rpartition(":")
        try:
            return host, int(port_s)
        except ValueError:
            return raw, None
    if raw.startswith("localhost:"):
        try:
            return "localhost", int(raw[len("localhost:"):])
        except ValueError:
            return raw, None
    return raw, None


class TargetLoader:
    """Converts raw CLI target strings into typed BaseTarget instances."""

    @staticmethod
    def load(raw_targets: list[str], settings: Settings | None = None) -> list[BaseTarget]:
        """Parse raw target strings into LiveTarget instances."""
        targets: list[BaseTarget] = []
        for raw in raw_targets:
            if raw.startswith(("http://", "https://")):
                targets.append(LiveTarget.url(raw))
            elif _is_ip_or_local(raw):
                bare, port = _split_host_port(raw)
                host = raw if port else bare
                ports = [port] if port else []
                targets.append(LiveTarget.ip(host, ports=ports))
            else:
                targets.append(LiveTarget.domain(raw))
        return targets

    @staticmethod
    def load_training(
        profile_path: Path,
        target_override: str | None = None,
    ) -> TrainingTarget:
        """Load a TrainingTarget from a YAML profile."""
        tt = TrainingTarget.from_profile(profile_path)
        if target_override:
            tt = tt.model_copy(update={"host": target_override})
        return tt
