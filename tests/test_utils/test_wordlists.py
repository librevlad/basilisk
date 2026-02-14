"""Tests for WordlistManager."""

import pytest

from basilisk.utils.wordlists import WordlistManager


@pytest.fixture
def wl_dirs(tmp_path):
    bundled = tmp_path / "bundled"
    downloaded = tmp_path / "downloaded"
    custom = tmp_path / "custom"
    bundled.mkdir()
    downloaded.mkdir()
    custom.mkdir()
    return bundled, downloaded, custom


@pytest.fixture
def manager(wl_dirs):
    bundled, downloaded, custom = wl_dirs
    return WordlistManager(
        bundled_dir=bundled,
        downloaded_dir=downloaded,
        custom_dir=custom,
    )


class TestWordlistManager:
    async def test_get_wordlist(self, manager, wl_dirs):
        bundled, _, _ = wl_dirs
        wl = bundled / "common.txt"
        wl.write_text("admin\nlogin\napi\n# comment\n\ndashboard\n")

        entries = await manager.get_all("common")
        assert entries == ["admin", "login", "api", "dashboard"]

    async def test_get_not_found(self, manager):
        with pytest.raises(FileNotFoundError):
            await manager.get_all("nonexistent")

    async def test_get_with_extension(self, manager, wl_dirs):
        bundled, _, _ = wl_dirs
        wl = bundled / "dirs.txt"
        wl.write_text("admin\nbackup\n")

        # Should find by name without extension
        entries = await manager.get_all("dirs")
        assert len(entries) == 2

    async def test_merge(self, manager, wl_dirs):
        bundled, _, _ = wl_dirs
        (bundled / "a.txt").write_text("admin\nlogin\n")
        (bundled / "b.txt").write_text("login\napi\nconfig\n")

        merged = [e async for e in manager.merge("a", "b")]
        assert merged == ["admin", "login", "api", "config"]

    async def test_merge_no_dedupe(self, manager, wl_dirs):
        bundled, _, _ = wl_dirs
        (bundled / "a.txt").write_text("admin\nlogin\n")
        (bundled / "b.txt").write_text("login\napi\n")

        merged = [e async for e in manager.merge("a", "b", dedupe=False)]
        assert merged == ["admin", "login", "login", "api"]

    def test_list_available(self, manager, wl_dirs):
        bundled, downloaded, custom = wl_dirs
        (bundled / "common.txt").write_text("a\nb\nc\n")
        (bundled / "large.txt").write_text("a\nb\nc\nd\ne\n")
        (custom / "my_words.txt").write_text("x\ny\n")

        available = manager.list_available()
        assert len(available) == 3
        names = [w.name for w in available]
        assert "common" in names
        assert "large" in names
        assert "my_words" in names
        # line_count is now an estimate based on file size
        for w in available:
            assert w.line_count >= 1

    async def test_list_available_async(self, manager, wl_dirs):
        """Async version returns exact line counts."""
        bundled, _, _ = wl_dirs
        (bundled / "exact.txt").write_text("one\ntwo\nthree\nfour\nfive\n")

        available = await manager.list_available_async()
        exact = [w for w in available if w.name == "exact"][0]
        assert exact.line_count == 5

    def test_add_custom(self, manager, wl_dirs, tmp_path):
        source = tmp_path / "source.txt"
        source.write_text("word1\nword2\nword3\n")
        _, _, custom = wl_dirs

        dest = manager.add_custom(source, name="my_list")
        assert dest.exists()
        assert dest.name == "my_list.txt"
        assert dest.read_text() == "word1\nword2\nword3\n"

    async def test_streaming_memory_efficient(self, manager, wl_dirs):
        """Test that get() streams lines without loading all into memory."""
        bundled, _, _ = wl_dirs
        wl = bundled / "big.txt"
        wl.write_text("\n".join(f"entry{i}" for i in range(10000)))

        count = 0
        async for _ in manager.get("big"):
            count += 1
        assert count == 10000

    def test_search_order(self, manager, wl_dirs):
        """Bundled > downloaded > custom priority."""
        bundled, downloaded, _ = wl_dirs
        (bundled / "test.txt").write_text("bundled_entry\n")
        (downloaded / "test.txt").write_text("downloaded_entry\n")

        # Should find the bundled one first
        path = manager._find_file("test")
        assert "bundled" in str(path)
