"""Data models — contracts for the entire system."""

from basilisk.models.result import Finding, PluginResult, Severity
from basilisk.models.target import Target, TargetScope, TargetType
from basilisk.models.types import (
    DnsRecord,
    DnsRecordType,
    HttpInfo,
    PortInfo,
    PortState,
    SslInfo,
)

__all__ = [
    "DnsRecord",
    "DnsRecordType",
    "Finding",
    "HttpInfo",
    "PluginResult",
    "PortInfo",
    "PortState",
    "Severity",
    "SslInfo",
    "Target",
    "TargetScope",
    "TargetType",
]
