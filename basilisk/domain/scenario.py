"""Scenario ABC — the v4 replacement for BasePlugin."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, ClassVar, Literal

from pydantic import BaseModel, Field

from basilisk.domain.finding import Finding
from basilisk.domain.surface import Surface

if TYPE_CHECKING:
    from basilisk.actor.base import ActorProtocol
    from basilisk.domain.target import BaseTarget


class ScenarioMeta(BaseModel):
    """Metadata declaring what a scenario does and needs."""

    name: str
    display_name: str
    category: str
    description: str = ""
    target_surfaces: list[str] = Field(default_factory=list)
    depends_on: list[str] = Field(default_factory=list)
    produces: list[str] = Field(default_factory=list)
    timeout: float = 30.0
    requires_auth: bool = False
    risk_level: str = "safe"
    required_tools: list[str] = Field(default_factory=list)
    # Knowledge graph integration
    requires_knowledge: list[str] = Field(default_factory=list)
    produces_knowledge: list[str] = Field(default_factory=list)
    cost_score: float = 1.0
    noise_score: float = 1.0


class ScenarioResult(BaseModel):
    """Result of running a scenario."""

    scenario: str
    target: str
    findings: list[Finding] = Field(default_factory=list)
    surfaces_discovered: list[Surface] = Field(default_factory=list)
    data: dict[str, Any] = Field(default_factory=dict)
    status: Literal["success", "partial", "error", "timeout", "skipped"] = "success"
    duration: float = 0.0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.status in ("success", "partial")


class Scenario(ABC):
    """Base class for all v4 scenarios.

    Like BasePlugin but receives Actor instead of PluginContext.
    Tools dict carries shared utilities (wordlists, payloads, etc.).
    """

    meta: ClassVar[ScenarioMeta]

    @abstractmethod
    async def run(
        self,
        target: BaseTarget,
        actor: ActorProtocol,
        surfaces: list[Surface],
        tools: dict[str, Any],
    ) -> ScenarioResult:
        """Execute the scenario against a target."""

    def accepts(self, target: BaseTarget) -> bool:
        """Return True if this scenario can work with the given target."""
        return True

    def __repr__(self) -> str:
        return f"<Scenario {self.meta.name}>"
