"""Tests for log rotation cleanup."""

from __future__ import annotations

from basilisk.logging.cleanup import cleanup_old_runs


class TestCleanup:
    def test_removes_oldest(self, tmp_path):
        log_dir = tmp_path / "logs"
        log_dir.mkdir()

        # Create 5 run directories with timestamps
        names = [
            "20260101_100000_target",
            "20260102_100000_target",
            "20260103_100000_target",
            "20260104_100000_target",
            "20260105_100000_target",
        ]
        for name in names:
            (log_dir / name).mkdir()

        cleanup_old_runs(log_dir, max_runs=3)

        remaining = sorted(d.name for d in log_dir.iterdir() if d.is_dir())
        assert len(remaining) == 3
        # Oldest two should be removed
        assert "20260101_100000_target" not in remaining
        assert "20260102_100000_target" not in remaining
        assert "20260103_100000_target" in remaining
        assert "20260104_100000_target" in remaining
        assert "20260105_100000_target" in remaining

    def test_noop_when_under_limit(self, tmp_path):
        log_dir = tmp_path / "logs"
        log_dir.mkdir()

        (log_dir / "20260101_100000_target").mkdir()
        (log_dir / "20260102_100000_target").mkdir()

        cleanup_old_runs(log_dir, max_runs=5)

        remaining = list(log_dir.iterdir())
        assert len(remaining) == 2

    def test_noop_when_dir_missing(self, tmp_path):
        log_dir = tmp_path / "nonexistent"
        # Should not raise
        cleanup_old_runs(log_dir, max_runs=3)

    def test_ignores_files(self, tmp_path):
        log_dir = tmp_path / "logs"
        log_dir.mkdir()

        # Create dirs and a stray file
        (log_dir / "20260101_100000_target").mkdir()
        (log_dir / "20260102_100000_target").mkdir()
        (log_dir / "20260103_100000_target").mkdir()
        (log_dir / "stray_file.txt").write_text("x")

        cleanup_old_runs(log_dir, max_runs=2)

        dirs = sorted(d.name for d in log_dir.iterdir() if d.is_dir())
        assert len(dirs) == 2
        # File should still exist
        assert (log_dir / "stray_file.txt").exists()
