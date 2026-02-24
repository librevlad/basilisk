"""Target models — LiveTarget for real audits, TrainingTarget for validation."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class ExpectedFinding(BaseModel):
    """A single expected finding in a training profile."""

    title: str
    severity: str
    category: str = ""
    plugin_hints: list[str] = Field(default_factory=list)
    verification_required: bool = True


class AuthConfig(BaseModel):
    """Authentication configuration for training targets."""

    username: str = ""
    password: str = ""
    login_url: str = ""
    setup_url: str = ""
    setup_data: dict[str, str] = Field(default_factory=dict)
    extra_cookies: dict[str, str] = Field(default_factory=dict)


class BaseTarget(BaseModel, ABC):
    """Abstract base for all audit targets."""

    host: str
    ports: list[int] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=dict)

    @property
    @abstractmethod
    def target_type(self) -> str:
        """Return target type identifier."""

    @property
    def is_training(self) -> bool:
        return False

    @property
    def base_url(self) -> str:
        """Compute base URL from host and ports."""
        if self.host.startswith(("http://", "https://")):
            return self.host.rstrip("/")
        scheme = "https" if 443 in self.ports else "http"
        port_suffix = ""
        if self.ports:
            port = self.ports[0]
            if (scheme == "https" and port != 443) or (scheme == "http" and port != 80):
                port_suffix = f":{port}"
        return f"{scheme}://{self.host}{port_suffix}"

    def __hash__(self) -> int:
        return hash((self.host, self.target_type))

    def __eq__(self, other: object) -> bool:
        if isinstance(other, BaseTarget):
            return self.host == other.host and self.target_type == other.target_type
        return NotImplemented


class LiveTarget(BaseTarget):
    """A real target for live auditing."""

    host_type: str = "domain"  # domain | ip | url

    @property
    def target_type(self) -> str:
        return "live"

    @classmethod
    def domain(cls, host: str, **kwargs: Any) -> LiveTarget:
        return cls(host=host, host_type="domain", **kwargs)

    @classmethod
    def ip(cls, addr: str, **kwargs: Any) -> LiveTarget:
        return cls(host=addr, host_type="ip", **kwargs)

    @classmethod
    def url(cls, url: str, **kwargs: Any) -> LiveTarget:
        return cls(host=url, host_type="url", **kwargs)


class TrainingTarget(BaseTarget):
    """A training target with expected findings for validation."""

    expected_findings: list[ExpectedFinding] = Field(default_factory=list)
    required_coverage: float = 1.0
    max_steps: int = 200
    auth: AuthConfig = Field(default_factory=AuthConfig)
    scan_paths: list[str] = Field(default_factory=list)

    @property
    def target_type(self) -> str:
        return "training"

    @property
    def is_training(self) -> bool:
        return True

    @classmethod
    def from_profile(cls, path: Path) -> TrainingTarget:
        """Load a TrainingTarget from a YAML profile file."""
        import yaml

        text = Path(path).read_text(encoding="utf-8")
        data = yaml.safe_load(text)
        # Map profile fields to TrainingTarget fields
        return cls(
            host=data.get("target", ""),
            ports=data.get("target_ports", []),
            expected_findings=[
                ExpectedFinding.model_validate(f) for f in data.get("expected_findings", [])
            ],
            required_coverage=data.get("required_coverage", 1.0),
            max_steps=data.get("max_steps", 200),
            auth=AuthConfig.model_validate(data["auth"]) if "auth" in data else AuthConfig(),
            scan_paths=data.get("scan_paths", []),
            meta={"name": data.get("name", ""), "description": data.get("description", "")},
        )
