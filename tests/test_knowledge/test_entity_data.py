"""Tests for typed entity data schemas."""

from __future__ import annotations

from basilisk.knowledge.entities import Entity, EntityType
from basilisk.knowledge.entity_data import (
    ENTITY_DATA_MODELS,
    ContainerData,
    CredentialData,
    EndpointData,
    FindingData,
    HostData,
    ImageData,
    ServiceData,
    TechnologyData,
    VulnerabilityData,
)


class TestHostData:
    def test_required_fields(self):
        data = HostData(host="example.com")
        assert data.host == "example.com"
        assert data.type == "primary"
        assert data.parent == ""

    def test_extra_fields_allowed(self):
        data = HostData(host="example.com", services_checked=True)
        assert data.host == "example.com"
        assert data.services_checked is True


class TestServiceData:
    def test_required_fields(self):
        data = ServiceData(host="example.com", port=443)
        assert data.host == "example.com"
        assert data.port == 443
        assert data.protocol == "tcp"
        assert data.service == ""

    def test_all_fields(self):
        data = ServiceData(
            host="example.com", port=22, protocol="tcp",
            service="ssh", banner="OpenSSH",
        )
        assert data.service == "ssh"
        assert data.banner == "OpenSSH"


class TestEndpointData:
    def test_required_fields(self):
        data = EndpointData(host="example.com", path="/login")
        assert data.host == "example.com"
        assert data.path == "/login"
        assert data.has_params is False

    def test_params_and_api(self):
        data = EndpointData(
            host="example.com", path="/api/v1",
            has_params=True, is_api=True,
        )
        assert data.has_params is True
        assert data.is_api is True


class TestTechnologyData:
    def test_required_fields(self):
        data = TechnologyData(host="example.com", name="nginx")
        assert data.name == "nginx"
        assert data.version == ""
        assert data.is_waf is False

    def test_flags(self):
        data = TechnologyData(
            host="example.com", name="docker",
            is_container_runtime=True,
        )
        assert data.is_container_runtime is True


class TestCredentialData:
    def test_required_fields(self):
        data = CredentialData(host="example.com", username="admin")
        assert data.username == "admin"
        assert data.password == ""


class TestFindingData:
    def test_required_fields(self):
        data = FindingData(host="example.com", title="XSS Found")
        assert data.title == "XSS Found"
        assert data.severity == "info"
        assert data.evidence == ""

    def test_all_fields(self):
        data = FindingData(
            host="example.com", title="SQLi",
            severity="critical", evidence="proof",
            category="sqli", description="SQL injection found",
        )
        assert data.severity == "critical"


class TestVulnerabilityData:
    def test_required_fields(self):
        data = VulnerabilityData(host="example.com", name="CVE-2024-1234")
        assert data.name == "CVE-2024-1234"
        assert data.severity == "medium"


class TestContainerData:
    def test_required_fields(self):
        data = ContainerData(host="example.com", container_id="abc123")
        assert data.container_id == "abc123"
        assert data.privileged is False

    def test_privileged(self):
        data = ContainerData(
            host="example.com", container_id="abc123",
            privileged=True, state="running",
        )
        assert data.privileged is True
        assert data.state == "running"


class TestImageData:
    def test_required_fields(self):
        data = ImageData(host="example.com", image_name="nginx")
        assert data.image_name == "nginx"
        assert data.image_tag == "latest"


class TestEntityDataModels:
    def test_all_entity_types_covered(self):
        for entity_type in EntityType:
            assert entity_type in ENTITY_DATA_MODELS, (
                f"Missing data model for {entity_type}"
            )


class TestEntityTypedData:
    def test_host_typed_data(self):
        entity = Entity.host("example.com")
        typed = entity.typed_data
        assert isinstance(typed, HostData)
        assert typed.host == "example.com"

    def test_service_typed_data(self):
        entity = Entity.service("example.com", 443)
        typed = entity.typed_data
        assert isinstance(typed, ServiceData)
        assert typed.port == 443

    def test_endpoint_typed_data(self):
        entity = Entity.endpoint("example.com", "/login")
        typed = entity.typed_data
        assert isinstance(typed, EndpointData)
        assert typed.path == "/login"

    def test_technology_typed_data(self):
        entity = Entity.technology("example.com", "nginx", "1.21")
        typed = entity.typed_data
        assert isinstance(typed, TechnologyData)
        assert typed.name == "nginx"
        assert typed.version == "1.21"

    def test_credential_typed_data(self):
        entity = Entity.credential("example.com", "admin", "pass123")
        typed = entity.typed_data
        assert isinstance(typed, CredentialData)
        assert typed.username == "admin"

    def test_finding_typed_data(self):
        entity = Entity.finding("example.com", "XSS", "high")
        typed = entity.typed_data
        assert isinstance(typed, FindingData)
        assert typed.title == "XSS"
        assert typed.severity == "high"

    def test_vulnerability_typed_data(self):
        entity = Entity.vulnerability("example.com", "CVE-2024-1")
        typed = entity.typed_data
        assert isinstance(typed, VulnerabilityData)
        assert typed.name == "CVE-2024-1"

    def test_container_typed_data(self):
        entity = Entity.container("example.com", "abc123")
        typed = entity.typed_data
        assert isinstance(typed, ContainerData)
        assert typed.container_id == "abc123"

    def test_image_typed_data(self):
        entity = Entity.image("example.com", "nginx", "1.21")
        typed = entity.typed_data
        assert isinstance(typed, ImageData)
        assert typed.image_name == "nginx"

    def test_roundtrip_preserves_data(self):
        """typed_data.model_dump() matches entity.data for known fields."""
        entity = Entity.host("example.com")
        typed = entity.typed_data
        dumped = typed.model_dump()
        # All original data keys should be present
        for key, value in entity.data.items():
            assert dumped[key] == value

    def test_extra_keys_pass_through(self):
        """Gap satisfaction flags survive typed_data."""
        entity = Entity.host("example.com")
        entity.data["services_checked"] = True
        entity.data["custom_flag"] = 42
        typed = entity.typed_data
        assert typed.services_checked is True
        assert typed.custom_flag == 42
