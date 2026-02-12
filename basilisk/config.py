"""Configuration — Pydantic Settings + YAML loading."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings

DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / "config" / "default.yaml"
PROJECTS_DIR = Path("projects")
WORDLISTS_DIR = Path(__file__).parent.parent / "wordlists"


class HttpSettings(BaseSettings):
    timeout: float = 10.0
    max_connections: int = 100
    max_connections_per_host: int = 30
    user_agent: str = "Basilisk/2.0"
    follow_redirects: bool = True
    max_redirects: int = 5
    verify_ssl: bool = False


class DnsSettings(BaseSettings):
    timeout: float = 5.0
    nameservers: list[str] = Field(default=["8.8.8.8", "1.1.1.1"])
    retries: int = 2


class ScanSettings(BaseSettings):
    default_ports: list[int] = Field(
        default=[
            # Web
            80, 443, 8080, 8443, 8000, 8888, 9443,
            # Email
            25, 110, 143, 465, 587, 993, 995,
            # Remote Access
            22, 23, 3389, 5900, 5901,
            # File Transfer
            21, 69, 873,
            # Databases
            1433, 1521, 3306, 5432, 6379, 27017, 9200, 5984,
            # Directory / DNS
            389, 636, 53,
            # SMB/NetBIOS
            139, 445,
            # Infrastructure
            2375, 2376, 8500, 9090, 11211,
            # Monitoring
            161, 162, 10050, 10051,
            # Proxy
            3128, 1080,
        ]
    )
    port_timeout: float = 3.0
    max_concurrency: int = 50


class RateLimitSettings(BaseSettings):
    requests_per_second: float = 100.0
    burst: int = 20


class StorageSettings(BaseSettings):
    db_path: str = "basilisk.db"
    wal_mode: bool = True
    cache_size_mb: int = 64
    mmap_size_mb: int = 2048
    bulk_chunk_size: int = 1000


class AuthSettings(BaseSettings):
    enabled: bool = False
    username: str = ""
    password: str = ""
    bearer_token: str = ""
    login_url: str = ""
    session_file: str = ""


class BrowserSettings(BaseSettings):
    enabled: bool = False
    max_pages: int = 5
    timeout: float = 15.0


class CallbackSettings(BaseSettings):
    enabled: bool = False
    http_port: int = 8880
    dns_port: int = 8853
    domain: str = ""


class Settings(BaseSettings):
    """Root settings — merges defaults, YAML config, and env vars."""

    http: HttpSettings = Field(default_factory=HttpSettings)
    dns: DnsSettings = Field(default_factory=DnsSettings)
    scan: ScanSettings = Field(default_factory=ScanSettings)
    rate_limit: RateLimitSettings = Field(default_factory=RateLimitSettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)
    auth: AuthSettings = Field(default_factory=AuthSettings)
    browser: BrowserSettings = Field(default_factory=BrowserSettings)
    callback: CallbackSettings = Field(default_factory=CallbackSettings)
    projects_dir: Path = PROJECTS_DIR
    wordlists_dir: Path = WORDLISTS_DIR
    log_level: str = "INFO"

    @classmethod
    def load(cls, config_path: Path | str | None = None) -> Settings:
        """Load settings from YAML file, falling back to defaults."""
        data: dict[str, Any] = {}

        if config_path is None:
            config_path = DEFAULT_CONFIG_PATH

        path = Path(config_path)
        if path.exists():
            with open(path, encoding="utf-8") as f:
                raw = yaml.safe_load(f)
                if isinstance(raw, dict):
                    data = raw

        return cls(**data)
