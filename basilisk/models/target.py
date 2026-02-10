"""Target models — what we're auditing."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class TargetType(StrEnum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    URL = "url"


class Target(BaseModel):
    """A single audit target (domain, IP, URL, or subdomain)."""

    host: str
    type: TargetType = TargetType.DOMAIN
    ips: list[str] = Field(default_factory=list)
    parent: str | None = None
    ports: list[int] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=dict)

    def __hash__(self) -> int:
        return hash(self.host)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Target):
            return self.host == other.host
        return NotImplemented

    @classmethod
    def domain(cls, host: str, **kwargs: Any) -> Target:
        return cls(host=host, type=TargetType.DOMAIN, **kwargs)

    @classmethod
    def subdomain(cls, host: str, parent: str, **kwargs: Any) -> Target:
        return cls(host=host, type=TargetType.SUBDOMAIN, parent=parent, **kwargs)

    @classmethod
    def ip(cls, addr: str, **kwargs: Any) -> Target:
        return cls(host=addr, type=TargetType.IP, **kwargs)


class TargetScope(BaseModel):
    """Collection of targets for an audit run."""

    targets: list[Target] = Field(default_factory=list)

    @property
    def domains(self) -> list[Target]:
        return [t for t in self.targets if t.type == TargetType.DOMAIN]

    @property
    def subdomains(self) -> list[Target]:
        return [t for t in self.targets if t.type == TargetType.SUBDOMAIN]

    @property
    def hosts(self) -> list[str]:
        return [t.host for t in self.targets]

    def add(self, target: Target) -> bool:
        """Add target if not already present. Returns True if added."""
        if target not in self.targets:
            self.targets.append(target)
            return True
        return False

    def add_many(self, targets: list[Target]) -> int:
        """Add multiple targets. Returns count of newly added."""
        count = 0
        existing = set(self.targets)
        for t in targets:
            if t not in existing:
                self.targets.append(t)
                existing.add(t)
                count += 1
        return count

    def __len__(self) -> int:
        return len(self.targets)

    def __iter__(self):
        return iter(self.targets)
