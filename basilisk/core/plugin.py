"""Plugin system — BasePlugin ABC, PluginMeta, PluginCategory."""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import StrEnum
from typing import TYPE_CHECKING, ClassVar

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from basilisk.core.executor import PluginContext
    from basilisk.models.result import PluginResult
    from basilisk.models.target import Target


class PluginCategory(StrEnum):
    RECON = "recon"
    SCANNING = "scanning"
    ANALYSIS = "analysis"
    PENTESTING = "pentesting"


class PluginMeta(BaseModel):
    """Metadata declaring what a plugin does and needs."""

    name: str
    display_name: str
    category: PluginCategory
    description: str = ""
    depends_on: list[str] = Field(default_factory=list)
    produces: list[str] = Field(default_factory=list)
    provides: str | None = None  # e.g. "subdomains" — for ProviderPool
    default_enabled: bool = True
    timeout: float = 30.0


class BasePlugin(ABC):
    """Base class for all Basilisk plugins.

    Convention: one file in plugins/<category>/, one class with `meta`, one `run` method.
    """

    meta: ClassVar[PluginMeta]

    @abstractmethod
    async def run(self, target: Target, ctx: PluginContext) -> PluginResult:
        """Execute the plugin against a single target."""

    def accepts(self, target: Target) -> bool:
        """Return True if this plugin can work with the given target."""
        return True

    async def setup(self, ctx: PluginContext) -> None:  # noqa: B027
        """Called once before the plugin is first used."""

    async def teardown(self) -> None:  # noqa: B027
        """Called once after all targets are processed."""

    def __repr__(self) -> str:
        return f"<Plugin {self.meta.name}>"
