"""Knowledge graph relations — typed edges between entities."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class RelationType(StrEnum):
    EXPOSES = "exposes"              # HOST → SERVICE
    RUNS = "runs"                    # SERVICE → TECHNOLOGY
    HAS_ENDPOINT = "has_endpoint"    # SERVICE → ENDPOINT
    HAS_VULNERABILITY = "has_vuln"   # TECHNOLOGY → VULNERABILITY
    ACCESSES = "accesses"            # CREDENTIAL → HOST
    RELATES_TO = "relates_to"        # FINDING → any Entity
    PARENT_OF = "parent_of"          # HOST → HOST (domain → subdomain)


class Relation(BaseModel):
    """A directed edge in the knowledge graph."""

    source_id: str
    target_id: str
    type: RelationType
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    source_plugin: str = ""
