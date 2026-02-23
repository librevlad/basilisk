"""Project manager — CRUD for projects, auto-create directories."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

import yaml

from basilisk.config import Settings
from basilisk.models.project import Project, ProjectConfig, ProjectStatus

logger = logging.getLogger(__name__)


class ProjectManager:
    """Manages audit projects — each project gets its own directory tree."""

    def __init__(self, settings: Settings):
        self.projects_dir = settings.projects_dir

    def create(
        self,
        name: str,
        targets: list[str] | None = None,
        config: ProjectConfig | None = None,
        description: str = "",
    ) -> Project:
        """Create a new project with directory structure."""
        project_path = self.projects_dir / name
        if project_path.exists():
            msg = f"Project '{name}' already exists at {project_path}"
            raise FileExistsError(msg)

        project = Project(
            name=name,
            path=project_path,
            targets=targets or [],
            config=config or ProjectConfig(),
            description=description,
        )

        # Create directory tree
        project_path.mkdir(parents=True)
        for subdir in project.subdirs():
            subdir.mkdir(parents=True, exist_ok=True)

        # Save project config
        self._save_config(project)

        # Save initial targets
        if project.targets:
            targets_file = project.targets_dir / "domains.txt"
            targets_file.write_text("\n".join(project.targets) + "\n")

        logger.info("Created project '%s' at %s", name, project_path)
        return project

    def load(self, name: str) -> Project:
        """Load an existing project by name."""
        project_path = self.projects_dir / name
        if not project_path.exists():
            msg = f"Project '{name}' not found at {project_path}"
            raise FileNotFoundError(msg)

        config_file = project_path / "project.yaml"
        if not config_file.exists():
            msg = f"No project.yaml found in {project_path}"
            raise FileNotFoundError(msg)

        with open(config_file, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        targets = data.get("targets", [])
        config = ProjectConfig(**data.get("config", {}))

        return Project(
            name=data.get("name", name),
            path=project_path,
            targets=targets,
            config=config,
            status=ProjectStatus(data.get("status", "created")),
            description=data.get("description", ""),
            created_at=datetime.fromisoformat(data["created_at"])
            if "created_at" in data else datetime.now(UTC),
        )

    def list_all(self) -> list[Project]:
        """List all projects."""
        if not self.projects_dir.exists():
            return []

        projects = []
        for path in sorted(self.projects_dir.iterdir()):
            if path.is_dir() and (path / "project.yaml").exists():
                try:
                    projects.append(self.load(path.name))
                except Exception as e:
                    logger.warning("Failed to load project %s: %s", path.name, e)
        return projects

    def update_status(self, project: Project, status: ProjectStatus) -> None:
        """Update project status and save."""
        project.status = status
        project.updated_at = datetime.now(UTC)
        self._save_config(project)

    def delete(self, name: str) -> None:
        """Delete a project and all its files."""
        import shutil
        project_path = self.projects_dir / name
        if project_path.exists():
            shutil.rmtree(project_path)

    def _save_config(self, project: Project) -> None:
        """Save project config to YAML."""
        data = {
            "name": project.name,
            "targets": project.targets,
            "config": project.config.model_dump(),
            "status": project.status.value,
            "description": project.description,
            "created_at": project.created_at.isoformat(),
            "updated_at": project.updated_at.isoformat(),
        }
        with open(project.config_file, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True)
