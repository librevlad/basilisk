"""Custom Textual messages for audit pipeline events."""

from __future__ import annotations

from textual.message import Message

from basilisk.core.pipeline import PipelineState
from basilisk.models.result import Finding


class AuditProgress(Message):
    """Emitted when pipeline state changes (phase progress)."""

    def __init__(self, state: PipelineState) -> None:
        super().__init__()
        self.state = state


class AuditFinding(Message):
    """Emitted when a new finding is discovered."""

    def __init__(self, finding: Finding, target: str = "") -> None:
        super().__init__()
        self.finding = finding
        self.target = target


class AuditComplete(Message):
    """Emitted when the audit finishes (success or failure)."""

    def __init__(self, state: PipelineState, error: str | None = None) -> None:
        super().__init__()
        self.state = state
        self.error = error
