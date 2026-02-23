"""Tests for container observation adapter."""

from __future__ import annotations

from basilisk.knowledge.entities import EntityType
from basilisk.knowledge.relations import RelationType
from basilisk.models.result import PluginResult
from basilisk.observations.adapter import (
    _parse_image_ref,
    adapt_result,
)


class TestContainerRuntimeAdapter:
    def test_container_runtime_dict(self):
        result = PluginResult.success(
            "container_discovery", "example.com",
            data={"container_runtimes": [{"name": "docker", "version": "24.0"}]},
        )
        observations = adapt_result(result)
        tech_obs = [o for o in observations if o.entity_type == EntityType.TECHNOLOGY]
        assert len(tech_obs) == 1
        assert tech_obs[0].entity_data["is_container_runtime"] is True
        assert tech_obs[0].entity_data["name"] == "docker"
        assert tech_obs[0].relation is not None
        assert tech_obs[0].relation.type == RelationType.RUNS

    def test_container_runtime_string(self):
        result = PluginResult.success(
            "container_discovery", "example.com",
            data={"container_runtimes": ["docker"]},
        )
        observations = adapt_result(result)
        tech_obs = [o for o in observations if o.entity_type == EntityType.TECHNOLOGY]
        assert len(tech_obs) == 1
        assert tech_obs[0].entity_data["is_container_runtime"] is True

    def test_container_runtime_empty_name(self):
        result = PluginResult.success(
            "test", "example.com",
            data={"container_runtimes": [{"name": ""}]},
        )
        observations = adapt_result(result)
        tech_obs = [o for o in observations if o.entity_type == EntityType.TECHNOLOGY]
        assert len(tech_obs) == 0


class TestContainerAdapter:
    def test_container_entity(self):
        result = PluginResult.success(
            "container_enumeration", "example.com",
            data={"containers": [{"id": "abc123", "image": "nginx:1.24", "state": "running"}]},
        )
        observations = adapt_result(result)
        container_obs = [o for o in observations if o.entity_type == EntityType.CONTAINER]
        assert len(container_obs) == 1
        assert container_obs[0].entity_data["container_id"] == "abc123"
        assert container_obs[0].relation is not None
        assert container_obs[0].relation.type == RelationType.RUNS_CONTAINER

    def test_container_with_image(self):
        result = PluginResult.success(
            "container_enumeration", "example.com",
            data={"containers": [{"id": "abc123", "image": "nginx:1.24"}]},
        )
        observations = adapt_result(result)
        image_obs = [o for o in observations if o.entity_type == EntityType.IMAGE]
        assert len(image_obs) == 1
        assert image_obs[0].entity_data["image_name"] == "nginx"
        assert image_obs[0].entity_data["image_tag"] == "1.24"
        assert image_obs[0].relation is not None
        assert image_obs[0].relation.type == RelationType.USES_IMAGE

    def test_container_without_image(self):
        result = PluginResult.success(
            "test", "example.com",
            data={"containers": [{"id": "abc123"}]},
        )
        observations = adapt_result(result)
        container_obs = [o for o in observations if o.entity_type == EntityType.CONTAINER]
        image_obs = [o for o in observations if o.entity_type == EntityType.IMAGE]
        assert len(container_obs) == 1
        assert len(image_obs) == 0

    def test_container_no_id(self):
        result = PluginResult.success(
            "test", "example.com",
            data={"containers": [{"image": "nginx"}]},
        )
        observations = adapt_result(result)
        container_obs = [o for o in observations if o.entity_type == EntityType.CONTAINER]
        assert len(container_obs) == 0

    def test_container_preserves_fields(self):
        result = PluginResult.success(
            "test", "example.com",
            data={"containers": [{
                "id": "abc", "image": "nginx:1.24", "state": "running",
                "privileged": True, "network_mode": "host",
            }]},
        )
        observations = adapt_result(result)
        container_obs = [o for o in observations if o.entity_type == EntityType.CONTAINER]
        assert container_obs[0].entity_data["privileged"] is True
        assert container_obs[0].entity_data["network_mode"] == "host"


class TestImageAdapter:
    def test_image_dict(self):
        result = PluginResult.success(
            "test", "example.com",
            data={"images": [{"image_name": "nginx", "image_tag": "1.24"}]},
        )
        observations = adapt_result(result)
        image_obs = [o for o in observations if o.entity_type == EntityType.IMAGE]
        assert len(image_obs) == 1
        assert image_obs[0].entity_data["image_name"] == "nginx"
        assert image_obs[0].relation is None  # standalone image, no parent

    def test_image_string(self):
        result = PluginResult.success(
            "test", "example.com",
            data={"images": ["nginx:1.24"]},
        )
        observations = adapt_result(result)
        image_obs = [o for o in observations if o.entity_type == EntityType.IMAGE]
        assert len(image_obs) == 1
        assert image_obs[0].entity_data["image_name"] == "nginx"
        assert image_obs[0].entity_data["image_tag"] == "1.24"

    def test_image_empty_name(self):
        result = PluginResult.success(
            "test", "example.com",
            data={"images": [{"image_name": ""}]},
        )
        observations = adapt_result(result)
        image_obs = [o for o in observations if o.entity_type == EntityType.IMAGE]
        assert len(image_obs) == 0


class TestParseImageRef:
    def test_name_and_tag(self):
        assert _parse_image_ref("nginx:1.24") == ("nginx", "1.24")

    def test_name_only(self):
        assert _parse_image_ref("ubuntu") == ("ubuntu", "latest")

    def test_registry_with_tag(self):
        assert _parse_image_ref("registry.io/app:v2") == ("registry.io/app", "v2")

    def test_sha256_digest(self):
        name, tag = _parse_image_ref("sha256:abc123")
        assert name == "sha256:abc123"
        assert tag == ""

    def test_empty(self):
        assert _parse_image_ref("") == ("", "")

    def test_registry_with_port_and_tag(self):
        # "registry:5000/app:v1" — colon in registry
        name, tag = _parse_image_ref("registry:5000/app:v1")
        assert name == "registry:5000/app"
        assert tag == "v1"
