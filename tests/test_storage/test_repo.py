"""Tests for storage repository — CRUD, bulk ops, performance."""

import pytest

from basilisk.models.result import Finding, PluginResult, Severity
from basilisk.storage.db import close_db, open_db
from basilisk.storage.repo import ResultRepository


@pytest.fixture
async def repo(tmp_path):
    db = await open_db(tmp_path / "test.db")
    repo = ResultRepository(db)
    yield repo
    await close_db(db)


class TestProjects:
    async def test_create_and_get(self, repo):
        pid = await repo.create_project("test", "/tmp/test")
        assert pid > 0
        project = await repo.get_project(pid)
        assert project is not None
        assert project["name"] == "test"

    async def test_get_by_name(self, repo):
        await repo.create_project("myproject", "/tmp/mp")
        project = await repo.get_project_by_name("myproject")
        assert project is not None
        assert project["path"] == "/tmp/mp"

    async def test_list_projects(self, repo):
        await repo.create_project("p1", "/tmp/p1")
        await repo.create_project("p2", "/tmp/p2")
        projects = await repo.list_projects()
        assert len(projects) == 2

    async def test_update_status(self, repo):
        pid = await repo.create_project("test", "/tmp/test")
        await repo.update_project_status(pid, "running")
        project = await repo.get_project(pid)
        assert project["status"] == "running"


class TestDomains:
    async def test_insert_and_get(self, repo):
        did = await repo.insert_domain("example.com")
        assert did > 0
        domain = await repo.get_domain("example.com")
        assert domain is not None
        assert domain["host"] == "example.com"

    async def test_insert_duplicate(self, repo):
        id1 = await repo.insert_domain("example.com", project_id=None)
        id2 = await repo.insert_domain("example.com", project_id=None)
        count = await repo.count_domains()
        assert count == 1
        assert id1 == id2
        assert id1 > 0

    async def test_insert_duplicate_with_project(self, repo):
        pid = await repo.create_project("test", "/tmp/test")
        id1 = await repo.insert_domain("sub.example.com", project_id=pid)
        id2 = await repo.insert_domain("sub.example.com", project_id=pid)
        assert id1 == id2
        assert id1 > 0
        # Can save plugin_data with the returned ID (no FOREIGN KEY error)
        run_id = await repo.create_run(project_id=pid)
        from basilisk.models.result import PluginResult
        result = PluginResult(plugin="test_plugin", target="sub.example.com")
        saved_id = await repo.save_plugin_result(run_id, id2, result)
        assert saved_id > 0

    async def test_bulk_insert_strings(self, repo):
        pid = await repo.create_project("test", "/tmp/test")
        domains = [{"host": f"sub{i}.example.com"} for i in range(100)]
        total = await repo.bulk_insert_domains(domains, project_id=pid)
        assert total == 100
        count = await repo.count_domains(project_id=pid)
        assert count == 100

    async def test_pagination(self, repo):
        pid = await repo.create_project("test", "/tmp/test")
        domains = [{"host": f"sub{i}.example.com"} for i in range(50)]
        await repo.bulk_insert_domains(domains, project_id=pid)

        page1 = await repo.get_domains_page(project_id=pid, offset=0, limit=20)
        assert len(page1) == 20

        page2 = await repo.get_domains_page(project_id=pid, offset=20, limit=20)
        assert len(page2) == 20

        page3 = await repo.get_domains_page(project_id=pid, offset=40, limit=20)
        assert len(page3) == 10

    async def test_type_filter(self, repo):
        await repo.insert_domain("example.com", type_="domain")
        await repo.insert_domain("sub.example.com", type_="subdomain")
        page = await repo.get_domains_page(type_filter="subdomain")
        assert len(page) == 1
        assert page[0]["host"] == "sub.example.com"


class TestScanRuns:
    async def test_create_and_finish(self, repo):
        run_id = await repo.create_run(plugins=["ssl_check"])
        assert run_id > 0
        await repo.finish_run(run_id, status="completed")
        run = await repo.get_run(run_id)
        assert run["status"] == "completed"
        assert run["finished_at"] is not None


class TestFindings:
    async def test_insert_and_query(self, repo):
        did = await repo.insert_domain("example.com")
        run_id = await repo.create_run()
        finding = Finding.high("Expired SSL", evidence="cert expired")
        fid = await repo.insert_finding(run_id, did, "ssl_check", finding)
        assert fid > 0

        findings = await repo.get_findings(run_id=run_id)
        assert len(findings) == 1
        assert findings[0]["title"] == "Expired SSL"
        assert findings[0]["host"] == "example.com"

    async def test_severity_filter(self, repo):
        did = await repo.insert_domain("example.com")
        run_id = await repo.create_run()
        await repo.insert_finding(run_id, did, "p1", Finding.high("high"))
        await repo.insert_finding(run_id, did, "p2", Finding.low("low"))
        await repo.insert_finding(run_id, did, "p3", Finding.high("high2"))

        highs = await repo.get_findings(run_id=run_id, severity=Severity.HIGH)
        assert len(highs) == 2

    async def test_bulk_insert_findings(self, repo):
        did = await repo.insert_domain("example.com")
        run_id = await repo.create_run()

        findings = [
            (did, "plugin1", Finding.medium(f"Finding {i}"))
            for i in range(200)
        ]
        total = await repo.bulk_insert_findings(run_id, findings)
        assert total == 200
        assert await repo.count_findings(run_id=run_id) == 200

    async def test_count_by_severity(self, repo):
        did = await repo.insert_domain("example.com")
        run_id = await repo.create_run()
        await repo.insert_finding(run_id, did, "p1", Finding.critical("crit"))
        await repo.insert_finding(run_id, did, "p2", Finding.high("high"))
        await repo.insert_finding(run_id, did, "p3", Finding.low("low"))

        assert await repo.count_findings(severity=Severity.CRITICAL) == 1
        assert await repo.count_findings(severity=Severity.HIGH) == 1
        assert await repo.count_findings() == 3


class TestPluginData:
    async def test_save_result(self, repo):
        did = await repo.insert_domain("example.com")
        run_id = await repo.create_run()
        result = PluginResult.success(
            "ssl_check", "example.com",
            data={"protocol": "TLSv1.3"}, duration=1.5,
        )
        pid = await repo.save_plugin_result(run_id, did, result)
        assert pid > 0


class TestStats:
    async def test_stats(self, repo):
        did = await repo.insert_domain("example.com")
        run_id = await repo.create_run()
        await repo.insert_finding(run_id, did, "p1", Finding.high("h1"))
        await repo.insert_finding(run_id, did, "p2", Finding.high("h2"))
        await repo.insert_finding(run_id, did, "p3", Finding.low("l1"))

        stats = await repo.stats()
        assert stats["total_findings"] == 3
        assert stats["total_domains"] == 1
        assert stats["findings_by_severity"]["HIGH"] == 2
        assert stats["findings_by_severity"]["LOW"] == 1


class TestBulkPerformance:
    async def test_bulk_insert_10k_domains(self, repo):
        """Insert 10K domains — should be fast with chunked inserts."""
        pid = await repo.create_project("perf", "/tmp/perf")
        domains = [{"host": f"sub{i}.example.com"} for i in range(10_000)]
        total = await repo.bulk_insert_domains(domains, project_id=pid)
        assert total == 10_000
        assert await repo.count_domains(project_id=pid) == 10_000
