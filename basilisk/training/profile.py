"""Training profile models — expected findings for vulnerable applications."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field


class DockerConfig(BaseModel):
    """Docker Compose configuration for a training target."""

    compose_file: str = ""
    service_name: str = ""
    ready_timeout: float = 120.0
    ready_url: str = ""


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
    setup_url: str = ""          # URL to POST to before login (e.g. DVWA DB reset)
    setup_get_url: str = ""      # URL to GET before POST (for cookie/token extraction)
    setup_data: dict[str, str] = Field(default_factory=dict)
    extra_cookies: dict[str, str] = Field(default_factory=dict)
    login_fields: dict[str, str] = Field(default_factory=dict)  # custom form field names

    # JSON API auth (for REST-only apps like VamPi)
    auth_type: str = "form"      # "form" or "json_api"
    register_url: str = ""       # e.g. /users/v1/register
    register_data: dict[str, str] = Field(default_factory=dict)
    token_path: str = ""         # JSON key for token, e.g. "auth_token"
    token_header: str = "Authorization"
    token_prefix: str = ""       # e.g. "Bearer "


class TrainingProfile(BaseModel):
    """Profile describing a vulnerable training application and its known vulns."""

    name: str
    description: str = ""
    target: str
    target_ports: list[int] = Field(default_factory=list)
    expected_findings: list[ExpectedFinding]
    max_steps: int = 200
    required_coverage: float = 1.0
    auth: AuthConfig = Field(default_factory=AuthConfig)
    docker: DockerConfig = Field(default_factory=DockerConfig)
    scan_paths: list[str] = Field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> TrainingProfile:
        """Load a training profile from a YAML file."""
        import yaml

        text = Path(path).read_text(encoding="utf-8")
        data = yaml.safe_load(text)
        return cls.model_validate(data)
