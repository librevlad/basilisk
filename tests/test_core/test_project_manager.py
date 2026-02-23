"""Tests for ProjectManager — CRUD operations with tmp directories."""

import pytest

from basilisk.config import Settings
from basilisk.core.project_manager import ProjectManager
from basilisk.models.project import ProjectConfig, ProjectStatus


@pytest.fixture
def pm(tmp_path):
    settings = Settings()
    settings.projects_dir = tmp_path / "projects"
    settings.projects_dir.mkdir()
    return ProjectManager(settings)


class TestProjectCreate:
    def test_create_basic(self, pm):
        proj = pm.create("test-project", targets=["example.com"])
        assert proj.name == "test-project"
        assert proj.targets == ["example.com"]
        assert proj.path.exists()
        assert (proj.path / "project.yaml").exists()

    def test_create_with_description(self, pm):
        proj = pm.create("my-audit", description="Test audit")
        assert proj.description == "Test audit"

    def test_create_directories(self, pm):
        proj = pm.create("dir-test", targets=["example.com"])
        # Check subdirectories exist
        for subdir in proj.subdirs():
            assert subdir.exists()

    def test_create_targets_file(self, pm):
        proj = pm.create("targets-test", targets=["a.com", "b.com"])
        targets_file = proj.targets_dir / "domains.txt"
        assert targets_file.exists()
        content = targets_file.read_text()
        assert "a.com" in content
        assert "b.com" in content

    def test_create_no_targets_no_file(self, pm):
        proj = pm.create("empty-test")
        targets_file = proj.targets_dir / "domains.txt"
        assert not targets_file.exists()

    def test_create_duplicate_raises(self, pm):
        pm.create("dup-test")
        with pytest.raises(FileExistsError):
            pm.create("dup-test")

    def test_create_with_custom_config(self, pm):
        config = ProjectConfig(ports=[80, 443])
        proj = pm.create("config-test", config=config)
        assert proj.config.ports == [80, 443]


class TestProjectLoad:
    def test_load_existing(self, pm):
        pm.create("load-test", targets=["example.com"], description="desc")
        loaded = pm.load("load-test")
        assert loaded.name == "load-test"
        assert loaded.targets == ["example.com"]
        assert loaded.description == "desc"

    def test_load_nonexistent(self, pm):
        with pytest.raises(FileNotFoundError):
            pm.load("does-not-exist")

    def test_load_no_yaml(self, pm, tmp_path):
        # Create directory without project.yaml
        (pm.projects_dir / "broken").mkdir()
        with pytest.raises(FileNotFoundError, match="project.yaml"):
            pm.load("broken")

    def test_load_preserves_status(self, pm):
        proj = pm.create("status-test")
        pm.update_status(proj, ProjectStatus.RUNNING)
        loaded = pm.load("status-test")
        assert loaded.status == ProjectStatus.RUNNING


class TestProjectListAll:
    def test_list_empty(self, pm):
        assert pm.list_all() == []

    def test_list_multiple(self, pm):
        pm.create("proj-a")
        pm.create("proj-b")
        projects = pm.list_all()
        names = {p.name for p in projects}
        assert names == {"proj-a", "proj-b"}

    def test_list_skips_non_project_dirs(self, pm):
        pm.create("real-project")
        (pm.projects_dir / "not-a-project").mkdir()
        projects = pm.list_all()
        assert len(projects) == 1

    def test_list_nonexistent_dir(self, tmp_path):
        settings = Settings()
        settings.projects_dir = tmp_path / "nonexistent"
        pm = ProjectManager(settings)
        assert pm.list_all() == []


class TestProjectUpdateStatus:
    def test_update_status(self, pm):
        proj = pm.create("upd-test")
        assert proj.status == ProjectStatus.CREATED
        pm.update_status(proj, ProjectStatus.COMPLETED)
        assert proj.status == ProjectStatus.COMPLETED
        # Verify persisted
        loaded = pm.load("upd-test")
        assert loaded.status == ProjectStatus.COMPLETED


class TestProjectDelete:
    def test_delete_existing(self, pm):
        pm.create("del-test")
        pm.delete("del-test")
        assert not (pm.projects_dir / "del-test").exists()

    def test_delete_nonexistent_no_error(self, pm):
        pm.delete("ghost")  # Should not raise
