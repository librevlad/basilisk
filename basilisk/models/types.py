"""Domain-specific types — DNS, SSL, HTTP, Port data structures."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# === DNS ===

class DnsRecordType(StrEnum):
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    NS = "NS"
    TXT = "TXT"
    SOA = "SOA"
    PTR = "PTR"
    SRV = "SRV"


class DnsRecord(BaseModel):
    type: DnsRecordType
    name: str
    value: str
    ttl: int = 0
    priority: int | None = None  # for MX


# === SSL/TLS ===

class SslInfo(BaseModel):
    subject: dict[str, str] = Field(default_factory=dict)
    issuer: dict[str, str] = Field(default_factory=dict)
    serial_number: str = ""
    version: int = 0
    not_before: datetime | None = None
    not_after: datetime | None = None
    san: list[str] = Field(default_factory=list)  # Subject Alternative Names
    protocol: str = ""  # TLSv1.2, TLSv1.3
    cipher: str = ""
    key_size: int = 0
    signature_algorithm: str = ""
    is_expired: bool = False
    is_self_signed: bool = False
    days_until_expiry: int | None = None
    chain_length: int = 0
    raw: dict[str, Any] = Field(default_factory=dict)


# === Ports ===

class PortState(StrEnum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


class PortInfo(BaseModel):
    port: int
    state: PortState = PortState.CLOSED
    protocol: str = "tcp"
    service: str = ""
    banner: str = ""
    version: str = ""


# === HTTP ===

class HttpInfo(BaseModel):
    url: str = ""
    status_code: int = 0
    headers: dict[str, str] = Field(default_factory=dict)
    title: str = ""
    server: str = ""
    content_length: int = 0
    redirect_url: str = ""
    technologies: list[str] = Field(default_factory=list)
    security_headers: dict[str, str | None] = Field(default_factory=dict)


# === WHOIS ===

class WhoisInfo(BaseModel):
    domain: str = ""
    registrar: str = ""
    creation_date: datetime | None = None
    expiration_date: datetime | None = None
    updated_date: datetime | None = None
    name_servers: list[str] = Field(default_factory=list)
    registrant: str = ""
    country: str = ""
    raw: str = ""
