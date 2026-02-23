"""Project models — case/engagement management."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class ProjectStatus(StrEnum):
    CREATED = "created"
    CONFIGURED = "configured"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


class ProjectConfig(BaseModel):
    """Configuration for a project's audit run."""

    plugins: list[str] = Field(
        default_factory=list, description="Explicit plugin list (empty = all)"
    )
    excluded_plugins: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default=[80, 443, 8080, 8443, 21, 22, 25, 3306, 5432])
    wordlists: list[str] = Field(default=["dirs_common"])
    max_concurrency: int = 50
    timeout: float = 30.0
    rate_limit: float = 100.0  # requests per second
    subdomain_providers: list[str] = Field(
        default_factory=list,
        description="Empty = all available providers",
    )
    phases: list[str] = Field(
        default=["recon", "scanning", "analysis", "pentesting"],
        description="Which phases to run",
    )
    extra: dict[str, Any] = Field(default_factory=dict)


class Project(BaseModel):
    """An audit project/engagement."""

    name: str
    path: Path
    targets: list[str] = Field(default_factory=list)
    config: ProjectConfig = Field(default_factory=ProjectConfig)
    status: ProjectStatus = ProjectStatus.CREATED
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    description: str = ""

    @property
    def db_path(self) -> Path:
        return self.path / "audit.db"

    @property
    def targets_dir(self) -> Path:
        return self.path / "targets"

    @property
    def reports_dir(self) -> Path:
        return self.path / "reports"

    @property
    def evidence_dir(self) -> Path:
        return self.path / "evidence"

    @property
    def config_file(self) -> Path:
        return self.path / "project.yaml"

    def subdirs(self) -> list[Path]:
        return [self.targets_dir, self.reports_dir, self.evidence_dir]
