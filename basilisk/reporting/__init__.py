"""Real-time HTML + JSON reporting for autonomous audits and training."""

from __future__ import annotations

from basilisk.reporting.model import (
    REPORT_SCHEMA_VERSION,
    ReportModel,
    ReportStatistics,
    TrainingSection,
    VulnerabilityInstance,
)
from basilisk.reporting.writer import ReportWriter

__all__ = [
    "REPORT_SCHEMA_VERSION",
    "ReportModel",
    "ReportStatistics",
    "ReportWriter",
    "TrainingSection",
    "VulnerabilityInstance",
]
