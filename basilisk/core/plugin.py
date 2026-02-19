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
    EXPLOITATION = "exploitation"
    POST_EXPLOIT = "post_exploit"
    PRIVESC = "privesc"
    LATERAL = "lateral"
    CRYPTO = "crypto"
    FORENSICS = "forensics"


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
    requires_http: bool = True      # False for DNS/port/subdomain-only plugins
    requires_auth: bool = False     # Skip if no auth session available
    requires_browser: bool = False  # Skip if headless browser unavailable
    requires_callback: bool = False  # Skip if OOB callback server unavailable
    requires_shell: bool = False        # Needs active shell session
    requires_credentials: bool = False   # Needs creds from CredentialStore
    platform: str = "any"               # "linux" / "windows" / "any"
    risk_level: str = "safe"            # "safe" / "noisy" / "destructive"


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
