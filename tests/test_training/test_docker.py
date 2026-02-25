"""Tests for DockerComposeManager."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from basilisk.training.docker import DockerComposeManager, _find_compose_cmd

PATCH_CMD = "basilisk.training.docker._find_compose_cmd"
DOCKER_CMD = ["docker", "compose"]


class TestFindComposeCmd:
    @patch("basilisk.training.docker.shutil.which")
    def test_docker_compose_v2(self, mock_which):
        mock_which.side_effect = lambda cmd: "/usr/bin/docker" if cmd == "docker" else None
        result = _find_compose_cmd()
        assert result == ["docker", "compose"]

    @patch("basilisk.training.docker.shutil.which")
    def test_docker_compose_v1(self, mock_which):
        def which_side(cmd):
            if cmd == "docker":
                return None
            if cmd == "docker-compose":
                return "/usr/bin/docker-compose"
            return None
        mock_which.side_effect = which_side
        result = _find_compose_cmd()
        assert result == ["docker-compose"]

    @patch("basilisk.training.docker.shutil.which")
    def test_no_docker(self, mock_which):
        mock_which.return_value = None
        result = _find_compose_cmd()
        assert result is None


def _mock_proc(rc: int = 0) -> AsyncMock:
    proc = AsyncMock()
    proc.returncode = rc
    proc.communicate = AsyncMock(return_value=(b"ok", b""))
    return proc


class TestDockerComposeManager:
    def test_available_without_docker(self):
        with patch(PATCH_CMD, return_value=None):
            mgr = DockerComposeManager()
            assert mgr.available is False

    def test_available_with_docker(self):
        with patch(PATCH_CMD, return_value=DOCKER_CMD):
            mgr = DockerComposeManager()
            assert mgr.available is True

    @pytest.mark.asyncio
    async def test_up_no_docker(self):
        with patch(PATCH_CMD, return_value=None):
            mgr = DockerComposeManager()
            await mgr.up("docker-compose.test.yml")
            assert mgr._active == []

    @pytest.mark.asyncio
    async def test_up_success(self, tmp_path):
        f = tmp_path / "docker-compose.test.yml"
        f.write_text("services:\n  test:\n    image: alpine\n")
        with patch(PATCH_CMD, return_value=DOCKER_CMD):
            mgr = DockerComposeManager()
            with patch("asyncio.create_subprocess_exec", return_value=_mock_proc()):
                await mgr.up(str(f))
                assert str(f) in mgr._active

    @pytest.mark.asyncio
    async def test_up_failure(self, tmp_path):
        f = tmp_path / "docker-compose.test.yml"
        f.write_text("services:\n  test:\n    image: alpine\n")
        with patch(PATCH_CMD, return_value=DOCKER_CMD):
            mgr = DockerComposeManager()
            with patch("asyncio.create_subprocess_exec", return_value=_mock_proc(1)):
                await mgr.up(str(f))
                assert mgr._active == []

    @pytest.mark.asyncio
    async def test_down_removes_from_active(self, tmp_path):
        f = tmp_path / "docker-compose.test.yml"
        f.write_text("services:\n  test:\n    image: alpine\n")
        with patch(PATCH_CMD, return_value=DOCKER_CMD):
            mgr = DockerComposeManager()
            mgr._active = [str(f)]
            with patch("asyncio.create_subprocess_exec", return_value=_mock_proc()):
                await mgr.down(str(f))
                assert mgr._active == []

    @pytest.mark.asyncio
    async def test_wait_ready_empty_url(self):
        with patch(PATCH_CMD, return_value=None):
            mgr = DockerComposeManager()
            result = await mgr.wait_ready("")
            assert result is True

    @pytest.mark.asyncio
    async def test_cleanup(self, tmp_path):
        a = tmp_path / "a.yml"
        b = tmp_path / "b.yml"
        a.write_text("services:\n  a:\n    image: alpine\n")
        b.write_text("services:\n  b:\n    image: alpine\n")
        with patch(PATCH_CMD, return_value=DOCKER_CMD):
            mgr = DockerComposeManager()
            mgr._active = [str(a), str(b)]
            with patch("asyncio.create_subprocess_exec", return_value=_mock_proc()):
                await mgr.cleanup()
                assert mgr._active == []

    def test_resolve_path_absolute(self, tmp_path):
        abs_path = str(tmp_path / "compose.yml")
        p = DockerComposeManager._resolve_path(abs_path)
        assert p == Path(abs_path)

    def test_resolve_path_with_project_root(self):
        p = DockerComposeManager._resolve_path("compose.yml", Path("/project"))
        assert p == Path("/project/compose.yml")

    def test_resolve_path_relative(self):
        p = DockerComposeManager._resolve_path("compose.yml")
        assert p == Path.cwd() / "compose.yml"
