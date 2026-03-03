"""Typed data schemas for each EntityType.

Provides Pydantic models that validate and type-hint the Entity.data dict.
All models use extra="allow" so gap satisfaction flags and unknown keys
pass through without errors.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from basilisk.knowledge.entities import EntityType


class HostData(BaseModel):
    model_config = ConfigDict(extra="allow")
    host: str
    type: str = "primary"
    parent: str = ""


class ServiceData(BaseModel):
    model_config = ConfigDict(extra="allow")
    host: str
    port: int
    protocol: str = "tcp"
    service: str = ""
    banner: str = ""


class EndpointData(BaseModel):
    model_config = ConfigDict(extra="allow")
    host: str
    path: str
    status: int = 0
    has_params: bool = False
    is_api: bool = False
    is_upload: bool = False


class TechnologyData(BaseModel):
    model_config = ConfigDict(extra="allow")
    host: str
    name: str
    version: str = ""
    is_cms: bool = False
    is_waf: bool = False
    is_cdn: bool = False
    is_container_runtime: bool = False


class CredentialData(BaseModel):
    model_config = ConfigDict(extra="allow")
    host: str
    username: str
    password: str = ""


class FindingData(BaseModel):
    model_config = ConfigDict(extra="allow")
    host: str
    title: str
    severity: str = "info"
    category: str = ""
    description: str = ""
    evidence: str = ""


class VulnerabilityData(BaseModel):
    model_config = ConfigDict(extra="allow")
    host: str
    name: str
    severity: str = "medium"


class ContainerData(BaseModel):
    model_config = ConfigDict(extra="allow")
    host: str
    container_id: str
    image: str = ""
    state: str = ""
    privileged: bool = False


class ImageData(BaseModel):
    model_config = ConfigDict(extra="allow")
    host: str
    image_name: str
    image_tag: str = "latest"


ENTITY_DATA_MODELS: dict[EntityType, type[BaseModel]] = {
    EntityType.HOST: HostData,
    EntityType.SERVICE: ServiceData,
    EntityType.ENDPOINT: EndpointData,
    EntityType.TECHNOLOGY: TechnologyData,
    EntityType.CREDENTIAL: CredentialData,
    EntityType.FINDING: FindingData,
    EntityType.VULNERABILITY: VulnerabilityData,
    EntityType.CONTAINER: ContainerData,
    EntityType.IMAGE: ImageData,
}
