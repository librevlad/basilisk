"""Tests for file_upload_check plugin."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from basilisk.models.target import Target
from basilisk.plugins.pentesting.file_upload_check import FileUploadCheckPlugin


def _make_ctx(
    *,
    crawled_urls: dict | None = None,
    forms: dict | None = None,
    get_responses: list[tuple[int, str]] | None = None,
    post_responses: list[tuple[int, str]] | None = None,
):
    """Build a mock PluginContext with separate GET/POST response queues."""
    ctx = MagicMock()
    ctx.should_stop = False
    ctx.state = {}
    if crawled_urls:
        ctx.state["crawled_urls"] = crawled_urls
    if forms:
        ctx.state["discovered_forms"] = forms
    ctx.pipeline = {}

    rate = MagicMock()
    rate.__aenter__ = AsyncMock()
    rate.__aexit__ = AsyncMock()
    ctx.rate = rate

    get_iter = iter(get_responses or [])
    post_iter = iter(post_responses or [])

    async def _get(url, **kw):
        try:
            status, body = next(get_iter)
        except StopIteration:
            status, body = 404, "Not Found"
        resp = MagicMock()
        resp.status = status
        resp.text = AsyncMock(return_value=body)
        resp.headers = MagicMock()
        resp.headers.getall = MagicMock(return_value=[])
        return resp

    async def _post(url, **kw):
        try:
            status, body = next(post_iter)
        except StopIteration:
            status, body = 404, "Not Found"
        resp = MagicMock()
        resp.status = status
        resp.text = AsyncMock(return_value=body)
        return resp

    async def _head(url, **kw):
        resp = MagicMock()
        resp.status = 200
        return resp

    http = MagicMock()
    http.get = AsyncMock(side_effect=_get)
    http.post = AsyncMock(side_effect=_post)
    http.head = AsyncMock(side_effect=_head)
    ctx.http = http

    dns = MagicMock()
    dns.resolve = AsyncMock(return_value=["127.0.0.1"])
    ctx.dns = dns

    config = MagicMock()
    config.http = MagicMock()
    config.http.verify_ssl = False
    ctx.config = config

    return ctx


class TestFileUploadCheckMeta:
    def test_meta(self):
        p = FileUploadCheckPlugin()
        assert p.meta.name == "file_upload_check"
        assert p.meta.category.value == "pentesting"
        assert "upload" in p.meta.description.lower()

    def test_discovery(self):
        from basilisk.core.registry import PluginRegistry
        r = PluginRegistry()
        r.discover()
        names = [p.meta.name for p in r.all()]
        assert "file_upload_check" in names


class TestFileUploadCheckNoHttp:
    @pytest.mark.asyncio
    async def test_no_http_client(self):
        ctx = MagicMock()
        ctx.http = None
        target = Target.domain("test.com")
        p = FileUploadCheckPlugin()
        result = await p.run(target, ctx)
        assert not result.ok


class TestFileUploadCheckNoEndpoints:
    @pytest.mark.asyncio
    async def test_no_upload_endpoints(self):
        """When no upload endpoints found, returns info finding."""
        ctx = _make_ctx(get_responses=[(404, "Not Found")] * 30)
        target = Target.domain("test.com")
        p = FileUploadCheckPlugin()
        result = await p.run(target, ctx)
        assert result.ok
        assert any("no file upload" in f.title.lower() for f in result.findings)


class TestFileUploadCheckDetection:
    @pytest.mark.asyncio
    async def test_detects_upload_from_crawled_urls(self):
        """Upload keyword in crawled URL triggers endpoint discovery."""
        ctx = _make_ctx(
            crawled_urls={"test.com": ["http://test.com/upload"]},
            # GET responses for common path probes (crawled /upload skips probe)
            get_responses=[(404, "Not Found")] * 20,
            # POST responses for upload testing
            post_responses=[
                (200, "File uploaded successfully"),  # baseline .txt
                (200, "File uploaded successfully"),  # .php
                (403, "Extension not allowed"),       # .php5
                (403, "Extension not allowed"),       # .phtml
                (403, "Extension not allowed"),       # .phar
                (403, "Extension not allowed"),       # .jsp
                (403, "Extension not allowed"),       # .jspx
                (403, "Extension not allowed"),       # .asp
                (403, "Extension not allowed"),       # .aspx
                (403, "Extension not allowed"),       # .py
            ],
        )
        target = Target.domain("test.com")
        p = FileUploadCheckPlugin()
        result = await p.run(target, ctx)
        assert result.ok
        assert any(
            f.severity.value >= 3  # HIGH or CRITICAL
            for f in result.findings
        )

    @pytest.mark.asyncio
    async def test_detects_upload_from_forms(self):
        """Forms with file inputs are discovered."""
        forms = {
            "test.com": [
                {
                    "action": "/upload",
                    "method": "POST",
                    "inputs": [{"type": "file", "name": "userfile"}],
                },
            ],
        }
        ctx = _make_ctx(
            forms=forms,
            get_responses=[(404, "Not Found")] * 20,
            post_responses=[
                (200, "File uploaded successfully"),   # baseline
                (200, "File uploaded successfully"),   # .php — dangerous!
            ] + [(403, "Rejected")] * 20,
        )
        target = Target.domain("test.com")
        p = FileUploadCheckPlugin()
        result = await p.run(target, ctx)
        assert result.ok
        assert result.data.get("forms_found", 0) >= 1

    @pytest.mark.asyncio
    async def test_all_rejected(self):
        """When all dangerous extensions are rejected, reports as info."""
        ctx = _make_ctx(
            crawled_urls={"test.com": ["http://test.com/file-upload"]},
            get_responses=[(404, "Not Found")] * 20,
            post_responses=[
                (200, "File uploaded successfully"),  # baseline .txt OK
            ] + [(403, "File type not allowed")] * 20,
        )
        target = Target.domain("test.com")
        p = FileUploadCheckPlugin()
        result = await p.run(target, ctx)
        assert result.ok
        high_findings = [f for f in result.findings if f.severity.value >= 3]
        assert len(high_findings) == 0


class TestFileUploadCheckCapability:
    def test_capability_mapping(self):
        from basilisk.capabilities.mapping import CAPABILITY_MAP
        entry = CAPABILITY_MAP["file_upload_check"]
        assert "Host" in entry["requires"]
        assert "Service:http" in entry["requires"]
        assert "Vulnerability" in entry["produces"]
