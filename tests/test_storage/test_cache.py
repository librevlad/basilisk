"""Tests for ResultCache — CRUD, TTL expiry, invalidation."""

from __future__ import annotations

import pytest

from basilisk.models.result import Finding, PluginResult
from basilisk.storage.cache import DEFAULT_TTL, ResultCache, _reconstruct_finding
from basilisk.storage.db import close_db, open_db


@pytest.fixture
async def cache(tmp_path):
    db = await open_db(tmp_path / "cache_test.db")
    cache = ResultCache(db)
    yield cache
    await close_db(db)


def _make_result(plugin: str = "ssl_check", host: str = "example.com") -> PluginResult:
    return PluginResult.success(
        plugin, host,
        findings=[
            Finding.high("Expired cert", evidence="cert not_after=2024-01-01"),
            Finding.info("TLS 1.3 supported"),
        ],
        data={"protocol": "TLSv1.3", "issuer": "Let's Encrypt"},
        duration=1.5,
    )


class TestCachePut:
    async def test_put_stores_result(self, cache):
        result = _make_result()
        await cache.put("example.com", result)

        # Verify data was stored
        cursor = await cache.db.execute("SELECT COUNT(*) FROM plugin_data")
        row = await cursor.fetchone()
        assert row[0] == 1

    async def test_put_stores_findings(self, cache):
        result = _make_result()
        await cache.put("example.com", result)

        cursor = await cache.db.execute("SELECT COUNT(*) FROM findings")
        row = await cursor.fetchone()
        assert row[0] == 2

    async def test_put_creates_domain(self, cache):
        result = _make_result()
        await cache.put("example.com", result)

        cursor = await cache.db.execute("SELECT host FROM domains")
        row = await cursor.fetchone()
        assert row[0] == "example.com"

    async def test_put_skips_error_results(self, cache):
        result = PluginResult.fail("ssl_check", "example.com", error="Connection refused")
        await cache.put("example.com", result)

        cursor = await cache.db.execute("SELECT COUNT(*) FROM plugin_data")
        row = await cursor.fetchone()
        assert row[0] == 0

    async def test_put_creates_cache_run(self, cache):
        result = _make_result()
        await cache.put("example.com", result)

        cursor = await cache.db.execute(
            "SELECT status FROM scan_runs WHERE status = 'cache'"
        )
        row = await cursor.fetchone()
        assert row is not None

    async def test_put_reuses_cache_run(self, cache):
        await cache.put("example.com", _make_result())
        await cache.put("other.com", _make_result(host="other.com"))

        cursor = await cache.db.execute(
            "SELECT COUNT(*) FROM scan_runs WHERE status = 'cache'"
        )
        row = await cursor.fetchone()
        assert row[0] == 1


class TestCacheGet:
    async def test_get_returns_cached(self, cache):
        result = _make_result()
        await cache.put("example.com", result)

        cached = await cache.get_cached("ssl_check", "example.com", max_age_hours=1.0)
        assert cached is not None
        assert cached.plugin == "ssl_check"
        assert cached.target == "example.com"
        assert cached.status == "success"
        assert cached.data["protocol"] == "TLSv1.3"

    async def test_get_returns_findings(self, cache):
        await cache.put("example.com", _make_result())

        cached = await cache.get_cached("ssl_check", "example.com", max_age_hours=1.0)
        assert cached is not None
        assert len(cached.findings) == 2
        assert cached.findings[0].title == "Expired cert"
        assert cached.findings[0].evidence == "cert not_after=2024-01-01"
        assert cached.findings[1].title == "TLS 1.3 supported"

    async def test_get_returns_none_for_missing(self, cache):
        cached = await cache.get_cached("ssl_check", "example.com", max_age_hours=1.0)
        assert cached is None

    async def test_get_returns_none_for_wrong_plugin(self, cache):
        await cache.put("example.com", _make_result())
        cached = await cache.get_cached("port_scan", "example.com", max_age_hours=1.0)
        assert cached is None

    async def test_get_returns_none_for_wrong_host(self, cache):
        await cache.put("example.com", _make_result())
        cached = await cache.get_cached("ssl_check", "other.com", max_age_hours=1.0)
        assert cached is None

    async def test_get_respects_ttl(self, cache):
        """Result with age > TTL should return None."""
        result = _make_result()
        await cache.put("example.com", result)

        # Manually set created_at to the past
        await cache.db.execute(
            "UPDATE plugin_data SET created_at = datetime('now', '-2 hours')"
        )
        await cache.db.commit()

        # 3 hours TTL → still fresh
        cached = await cache.get_cached("ssl_check", "example.com", max_age_hours=3.0)
        assert cached is not None

        # 1 hour TTL → expired
        cached = await cache.get_cached("ssl_check", "example.com", max_age_hours=1.0)
        assert cached is None

    async def test_get_returns_latest(self, cache):
        """When multiple cached results exist, return the newest."""
        r1 = PluginResult.success(
            "ssl_check", "example.com",
            data={"version": "old"}, duration=1.0,
        )
        await cache.put("example.com", r1)

        r2 = PluginResult.success(
            "ssl_check", "example.com",
            data={"version": "new"}, duration=2.0,
        )
        await cache.put("example.com", r2)

        cached = await cache.get_cached("ssl_check", "example.com", max_age_hours=1.0)
        assert cached is not None
        assert cached.data["version"] == "new"


class TestCacheInvalidate:
    async def test_invalidate_by_host(self, cache):
        await cache.put("example.com", _make_result())
        await cache.put("other.com", _make_result(host="other.com"))

        deleted = await cache.invalidate(host="example.com")
        assert deleted == 1

        # other.com should still be cached
        cached = await cache.get_cached("ssl_check", "other.com", max_age_hours=1.0)
        assert cached is not None

    async def test_invalidate_by_plugin(self, cache):
        await cache.put("example.com", _make_result())
        await cache.put("example.com", _make_result(plugin="port_scan"))

        deleted = await cache.invalidate(plugin="ssl_check")
        assert deleted == 1

    async def test_invalidate_all(self, cache):
        await cache.put("example.com", _make_result())
        await cache.put("other.com", _make_result(host="other.com"))

        deleted = await cache.invalidate()
        assert deleted == 2

    async def test_invalidate_by_host_and_plugin(self, cache):
        await cache.put("example.com", _make_result())
        await cache.put("example.com", _make_result(plugin="port_scan"))
        await cache.put("other.com", _make_result(host="other.com"))

        deleted = await cache.invalidate(host="example.com", plugin="ssl_check")
        assert deleted == 1

        # port_scan for example.com should still exist
        cursor = await cache.db.execute(
            "SELECT COUNT(*) FROM plugin_data WHERE plugin = 'port_scan'"
        )
        row = await cursor.fetchone()
        assert row[0] == 1


class TestReconstructFinding:
    def test_reconstruct_from_dict(self):
        row = {
            "severity": 3,
            "title": "XSS Found",
            "description": "Reflected XSS",
            "evidence": "<script>alert(1)</script>",
            "remediation": "Encode output",
            "tags": '["xss", "reflected"]',
        }
        finding = _reconstruct_finding(row)
        assert finding.title == "XSS Found"
        assert finding.severity.value == 3
        assert finding.tags == ["xss", "reflected"]

    def test_reconstruct_with_list_tags(self):
        row = {
            "severity": 0,
            "title": "Info",
            "description": "",
            "evidence": "",
            "remediation": "",
            "tags": ["tag1"],
        }
        finding = _reconstruct_finding(row)
        assert finding.tags == ["tag1"]


class TestDefaultTTL:
    def test_default_ttl_values(self):
        assert DEFAULT_TTL["recon"] == 24.0
        assert DEFAULT_TTL["scanning"] == 12.0
        assert DEFAULT_TTL["analysis"] == 12.0
        assert DEFAULT_TTL["pentesting"] == 6.0
