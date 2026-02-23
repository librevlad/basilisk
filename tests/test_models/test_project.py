"""Tests for Project and ProjectConfig models."""

from pathlib import Path

from basilisk.models.project import Project, ProjectConfig, ProjectStatus


class TestProjectConfig:
    def test_defaults(self):
        cfg = ProjectConfig()
        assert 80 in cfg.ports
        assert 443 in cfg.ports
        assert cfg.max_concurrency == 50
        assert cfg.timeout == 30.0
        assert cfg.rate_limit == 100.0
        assert "recon" in cfg.phases
        assert "pentesting" in cfg.phases

    def test_custom_ports(self):
        cfg = ProjectConfig(ports=[80, 443, 8080])
        assert cfg.ports == [80, 443, 8080]

    def test_wordlists(self):
        cfg = ProjectConfig(wordlists=["dirs_common", "dirs_medium"])
        assert len(cfg.wordlists) == 2


class TestProject:
    def test_creation(self):
        p = Project(name="test", path=Path("/tmp/test"))
        assert p.name == "test"
        assert p.status == ProjectStatus.CREATED

    def test_derived_paths(self):
        p = Project(name="test", path=Path("/tmp/test"))
        assert p.db_path == Path("/tmp/test/audit.db")
        assert p.targets_dir == Path("/tmp/test/targets")
        assert p.reports_dir == Path("/tmp/test/reports")
        assert p.evidence_dir == Path("/tmp/test/evidence")
        assert p.config_file == Path("/tmp/test/project.yaml")

    def test_subdirs(self):
        p = Project(name="test", path=Path("/tmp/test"))
        subdirs = p.subdirs()
        assert len(subdirs) == 3
        assert p.targets_dir in subdirs

    def test_status_enum(self):
        assert ProjectStatus.RUNNING == "running"
        assert ProjectStatus.COMPLETED == "completed"
