"""Core domain entities for Basilisk v4."""

from __future__ import annotations

from basilisk.domain.finding import Finding as V4Finding
from basilisk.domain.finding import Proof, ReproductionStep, Severity
from basilisk.domain.scenario import Scenario, ScenarioMeta, ScenarioResult
from basilisk.domain.surface import (
    ApiSurface,
    GraphqlSurface,
    LoginSurface,
    SearchSurface,
    Surface,
    UploadSurface,
)
from basilisk.domain.target import (
    AuthConfig,
    BaseTarget,
    ExpectedFinding,
    LiveTarget,
    TrainingTarget,
)

__all__ = [
    "ApiSurface",
    "AuthConfig",
    "BaseTarget",
    "ExpectedFinding",
    "GraphqlSurface",
    "LiveTarget",
    "LoginSurface",
    "Proof",
    "ReproductionStep",
    "Scenario",
    "ScenarioMeta",
    "ScenarioResult",
    "SearchSurface",
    "Severity",
    "Surface",
    "TrainingTarget",
    "UploadSurface",
    "V4Finding",
]
