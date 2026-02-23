"""Tests for container/image entity types and relations."""

from __future__ import annotations

from basilisk.knowledge.entities import Entity, EntityType
from basilisk.knowledge.graph import KnowledgeGraph
from basilisk.knowledge.relations import Relation, RelationType


class TestContainerEntity:
    def test_factory(self):
        entity = Entity.container("example.com", "abc123")
        assert entity.type == EntityType.CONTAINER
        assert entity.data["host"] == "example.com"
        assert entity.data["container_id"] == "abc123"

    def test_deterministic_id(self):
        e1 = Entity.container("example.com", "abc123")
        e2 = Entity.container("example.com", "abc123")
        assert e1.id == e2.id

    def test_different_ids(self):
        e1 = Entity.container("example.com", "abc123")
        e2 = Entity.container("example.com", "def456")
        assert e1.id != e2.id

    def test_extra_data(self):
        entity = Entity.container("example.com", "abc123", privileged=True)
        assert entity.data["privileged"] is True

    def test_merge_behavior(self):
        graph = KnowledgeGraph()
        e1 = Entity.container("example.com", "abc123")
        e1.confidence = 0.5
        graph.add_entity(e1)

        e2 = Entity.container("example.com", "abc123")
        e2.confidence = 0.5
        merged = graph.add_entity(e2)
        assert merged.confidence > 0.5  # probabilistic OR


class TestImageEntity:
    def test_factory(self):
        entity = Entity.image("example.com", "nginx", "1.24")
        assert entity.type == EntityType.IMAGE
        assert entity.data["host"] == "example.com"
        assert entity.data["image_name"] == "nginx"
        assert entity.data["image_tag"] == "1.24"

    def test_default_tag(self):
        entity = Entity.image("example.com", "nginx")
        assert entity.data["image_tag"] == "latest"

    def test_deterministic_id(self):
        e1 = Entity.image("example.com", "nginx", "1.24")
        e2 = Entity.image("example.com", "nginx", "1.24")
        assert e1.id == e2.id

    def test_different_tags_different_ids(self):
        e1 = Entity.image("example.com", "nginx", "1.24")
        e2 = Entity.image("example.com", "nginx", "1.25")
        assert e1.id != e2.id

    def test_merge_behavior(self):
        graph = KnowledgeGraph()
        e1 = Entity.image("example.com", "nginx", "1.24")
        e1.confidence = 0.5
        graph.add_entity(e1)

        e2 = Entity.image("example.com", "nginx", "1.24")
        e2.confidence = 0.5
        merged = graph.add_entity(e2)
        assert merged.confidence > 0.5


class TestContainerRelations:
    def test_runs_container_relation(self):
        graph = KnowledgeGraph()
        tech = Entity.technology("example.com", "docker", "24.0")
        tech.data["is_container_runtime"] = True
        container = Entity.container("example.com", "abc123")
        graph.add_entity(tech)
        graph.add_entity(container)
        graph.add_relation(Relation(
            source_id=tech.id, target_id=container.id,
            type=RelationType.RUNS_CONTAINER,
        ))

        neighbors = graph.neighbors(tech.id, RelationType.RUNS_CONTAINER)
        assert len(neighbors) == 1
        assert neighbors[0].type == EntityType.CONTAINER

    def test_uses_image_relation(self):
        graph = KnowledgeGraph()
        container = Entity.container("example.com", "abc123")
        image = Entity.image("example.com", "nginx", "1.24")
        graph.add_entity(container)
        graph.add_entity(image)
        graph.add_relation(Relation(
            source_id=container.id, target_id=image.id,
            type=RelationType.USES_IMAGE,
        ))

        neighbors = graph.neighbors(container.id, RelationType.USES_IMAGE)
        assert len(neighbors) == 1
        assert neighbors[0].type == EntityType.IMAGE

    def test_relation_dedup(self):
        graph = KnowledgeGraph()
        tech = Entity.technology("example.com", "docker")
        container = Entity.container("example.com", "abc123")
        graph.add_entity(tech)
        graph.add_entity(container)

        rel = Relation(
            source_id=tech.id, target_id=container.id,
            type=RelationType.RUNS_CONTAINER,
        )
        graph.add_relation(rel)
        graph.add_relation(rel)  # duplicate
        assert graph.relation_count == 1


class TestGraphShortcuts:
    def test_containers(self):
        graph = KnowledgeGraph()
        graph.add_entity(Entity.container("example.com", "abc"))
        graph.add_entity(Entity.container("example.com", "def"))
        graph.add_entity(Entity.host("example.com"))
        assert len(graph.containers()) == 2

    def test_images(self):
        graph = KnowledgeGraph()
        graph.add_entity(Entity.image("example.com", "nginx"))
        graph.add_entity(Entity.image("example.com", "redis"))
        graph.add_entity(Entity.host("example.com"))
        assert len(graph.images()) == 2
