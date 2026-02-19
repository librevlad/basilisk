"""Knowledge graph entities — typed nodes with deterministic IDs."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class EntityType(StrEnum):
    HOST = "host"
    SERVICE = "service"
    ENDPOINT = "endpoint"
    TECHNOLOGY = "technology"
    CREDENTIAL = "credential"
    FINDING = "finding"
    VULNERABILITY = "vulnerability"


class Entity(BaseModel):
    """A single node in the knowledge graph.

    IDs are deterministic: hash of type + sorted key fields.
    Same real-world object always gets the same ID, enabling dedup.
    """

    id: str
    type: EntityType
    data: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    observation_count: int = 1

    @staticmethod
    def make_id(entity_type: EntityType, **key_fields: str) -> str:
        """Deterministic ID from type + sorted key fields.

        Examples:
            make_id(HOST, host="example.com") → "a1b2c3d4..."
            make_id(SERVICE, host="example.com", port="443", protocol="https") → "e5f6..."
        """
        raw = f"{entity_type}:" + "&".join(
            f"{k}={v}" for k, v in sorted(key_fields.items())
        )
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @classmethod
    def host(cls, hostname: str, **extra_data: Any) -> Entity:
        """Create a Host entity."""
        now = datetime.now(UTC)
        data = {"host": hostname, **extra_data}
        return cls(
            id=cls.make_id(EntityType.HOST, host=hostname),
            type=EntityType.HOST,
            data=data,
            first_seen=now,
            last_seen=now,
        )

    @classmethod
    def service(
        cls, host: str, port: int, protocol: str = "tcp", **extra_data: Any,
    ) -> Entity:
        """Create a Service entity."""
        now = datetime.now(UTC)
        data = {"host": host, "port": port, "protocol": protocol, **extra_data}
        return cls(
            id=cls.make_id(EntityType.SERVICE, host=host, port=str(port), protocol=protocol),
            type=EntityType.SERVICE,
            data=data,
            first_seen=now,
            last_seen=now,
        )

    @classmethod
    def endpoint(cls, host: str, path: str, **extra_data: Any) -> Entity:
        """Create an Endpoint entity."""
        now = datetime.now(UTC)
        data = {"host": host, "path": path, **extra_data}
        return cls(
            id=cls.make_id(EntityType.ENDPOINT, host=host, path=path),
            type=EntityType.ENDPOINT,
            data=data,
            first_seen=now,
            last_seen=now,
        )

    @classmethod
    def technology(
        cls, host: str, name: str, version: str = "", **extra_data: Any,
    ) -> Entity:
        """Create a Technology entity."""
        now = datetime.now(UTC)
        data = {"host": host, "name": name, "version": version, **extra_data}
        return cls(
            id=cls.make_id(EntityType.TECHNOLOGY, host=host, name=name, version=version),
            type=EntityType.TECHNOLOGY,
            data=data,
            first_seen=now,
            last_seen=now,
        )

    @classmethod
    def credential(
        cls, host: str, username: str, password: str = "", **extra_data: Any,
    ) -> Entity:
        """Create a Credential entity."""
        now = datetime.now(UTC)
        data = {"host": host, "username": username, "password": password, **extra_data}
        return cls(
            id=cls.make_id(EntityType.CREDENTIAL, host=host, username=username),
            type=EntityType.CREDENTIAL,
            data=data,
            first_seen=now,
            last_seen=now,
        )

    @classmethod
    def finding(cls, host: str, title: str, severity: str = "info", **extra_data: Any) -> Entity:
        """Create a Finding entity."""
        now = datetime.now(UTC)
        data = {"host": host, "title": title, "severity": severity, **extra_data}
        return cls(
            id=cls.make_id(EntityType.FINDING, host=host, title=title),
            type=EntityType.FINDING,
            data=data,
            first_seen=now,
            last_seen=now,
        )

    @classmethod
    def vulnerability(
        cls, host: str, name: str, severity: str = "medium", **extra_data: Any,
    ) -> Entity:
        """Create a Vulnerability entity."""
        now = datetime.now(UTC)
        data = {"host": host, "name": name, "severity": severity, **extra_data}
        return cls(
            id=cls.make_id(EntityType.VULNERABILITY, host=host, name=name),
            type=EntityType.VULNERABILITY,
            data=data,
            first_seen=now,
            last_seen=now,
        )
