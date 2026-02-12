"""Tests for API Logic Engine (Auto-IDOR/BOLA)."""

from __future__ import annotations

import json
import logging
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from basilisk.config import Settings
from basilisk.core.auth import AuthManager
from basilisk.core.executor import PluginContext
from basilisk.models.target import Target
from basilisk.plugins.pentesting.api_logic_engine import ApiLogicEnginePlugin


def _make_ctx_with_dual_sessions(*, victim_body: str = "", attacker_body: str = "",
                                  attacker_status: int = 200):
    """Create mock PluginContext with dual auth sessions."""
    rate = AsyncMock()
    rate.__aenter__ = AsyncMock(return_value=rate)
    rate.__aexit__ = AsyncMock(return_value=False)

    http = AsyncMock()

    # Setup mock responses based on auth headers
    async def fake_request(method, url, headers=None, **kwargs):
        resp = MagicMock()
        headers = headers or {}
        auth_header = headers.get("Authorization", "")
        if "victim" in auth_header.lower():
            resp.status = 200
            resp.text = AsyncMock(return_value=victim_body)
        elif "attacker" in auth_header.lower():
            resp.status = attacker_status
            resp.text = AsyncMock(return_value=attacker_body)
        else:
            resp.status = 200
            resp.text = AsyncMock(return_value=victim_body)
        return resp

    http.request = fake_request

    # Mock HEAD for resolve_base_url
    head_resp = MagicMock()
    head_resp.status = 200
    http.head = AsyncMock(return_value=head_resp)

    auth = AuthManager()
    auth.set_named_bearer("example.com", "attacker", "attacker-token-123")
    auth.set_named_bearer("example.com", "victim", "victim-token-456")

    ctx = PluginContext(
        config=Settings(),
        http=http,
        rate=rate,
        auth=auth,
        log=logging.getLogger("test"),
        state={
            "http_scheme": {"example.com": "https"},
            "api_endpoints_detailed": {
                "example.com": [
                    {
                        "path": "/api/users/{user_id}",
                        "method": "get",
                        "parameters": [
                            {"name": "user_id", "in": "path", "type": "integer"},
                        ],
                        "requires_auth": True,
                        "tags": ["users"],
                        "summary": "Get user by ID",
                    },
                    {
                        "path": "/api/orders/{order_id}",
                        "method": "get",
                        "parameters": [
                            {"name": "order_id", "in": "path", "type": "integer"},
                        ],
                        "requires_auth": True,
                        "tags": ["orders"],
                        "summary": "Get order details",
                    },
                ],
            },
        },
    )
    ctx._deadline = time.monotonic() + 60
    return ctx


class TestApiLogicEngine:
    @pytest.mark.asyncio
    async def test_idor_detected(self):
        """Attacker gets same data as victim -> CRITICAL IDOR."""
        victim_data = json.dumps({"id": 42, "name": "Victim", "email": "v@test.com"})
        attacker_data = json.dumps({"id": 42, "name": "Victim", "email": "v@test.com"})

        ctx = _make_ctx_with_dual_sessions(
            victim_body=victim_data,
            attacker_body=attacker_data,
            attacker_status=200,
        )

        plugin = ApiLogicEnginePlugin()
        target = Target.domain("example.com")
        result = await plugin.run(target, ctx)

        assert result.ok
        critical = [f for f in result.findings if f.severity.name == "CRITICAL"]
        assert len(critical) >= 1
        assert "IDOR" in critical[0].title
        assert critical[0].verified is True

    @pytest.mark.asyncio
    async def test_idor_blocked(self):
        """Attacker gets 403 -> no vulnerability."""
        victim_data = json.dumps({"id": 42, "name": "Victim"})

        ctx = _make_ctx_with_dual_sessions(
            victim_body=victim_data,
            attacker_body='{"error": "forbidden"}',
            attacker_status=403,
        )

        plugin = ApiLogicEnginePlugin()
        target = Target.domain("example.com")
        result = await plugin.run(target, ctx)

        assert result.ok
        critical = [f for f in result.findings if f.severity.name == "CRITICAL"]
        assert len(critical) == 0

    @pytest.mark.asyncio
    async def test_no_dual_sessions(self):
        """No dual sessions configured -> skip with INFO."""
        rate = AsyncMock()
        rate.__aenter__ = AsyncMock(return_value=rate)
        rate.__aexit__ = AsyncMock(return_value=False)

        ctx = PluginContext(
            config=Settings(),
            http=AsyncMock(),
            rate=rate,
            auth=AuthManager(),  # No sessions configured
            log=logging.getLogger("test"),
        )

        plugin = ApiLogicEnginePlugin()
        target = Target.domain("example.com")
        result = await plugin.run(target, ctx)

        assert result.ok
        assert result.data.get("reason") == "no_dual_sessions"

    @pytest.mark.asyncio
    async def test_no_http(self):
        """No HTTP client -> error."""
        rate = AsyncMock()
        rate.__aenter__ = AsyncMock(return_value=rate)
        rate.__aexit__ = AsyncMock(return_value=False)

        ctx = PluginContext(
            config=Settings(),
            http=None,
            rate=rate,
            log=logging.getLogger("test"),
        )

        plugin = ApiLogicEnginePlugin()
        target = Target.domain("example.com")
        result = await plugin.run(target, ctx)
        assert result.status == "error"

    @pytest.mark.asyncio
    async def test_no_openapi_endpoints(self):
        """No API endpoints in state -> INFO finding."""
        ctx = _make_ctx_with_dual_sessions(victim_body="", attacker_body="")
        ctx.state["api_endpoints_detailed"] = {}

        plugin = ApiLogicEnginePlugin()
        target = Target.domain("example.com")
        result = await plugin.run(target, ctx)

        assert result.ok
        assert result.data.get("reason") == "no_id_endpoints"


class TestComputeSimilarity:
    def test_identical_json(self):
        a = json.dumps({"id": 1, "name": "test"})
        b = json.dumps({"id": 1, "name": "test"})
        sim = ApiLogicEnginePlugin._compute_similarity(a, b)
        assert sim > 0.99

    def test_different_json(self):
        a = json.dumps({"id": 1, "name": "alice"})
        b = json.dumps({"error": "not found"})
        sim = ApiLogicEnginePlugin._compute_similarity(a, b)
        assert sim < 0.5

    def test_similar_json(self):
        a = json.dumps({"id": 1, "name": "alice", "email": "a@test.com"})
        b = json.dumps({"id": 1, "name": "alice", "email": "a@test.com", "extra": "x"})
        sim = ApiLogicEnginePlugin._compute_similarity(a, b)
        assert sim > 0.7

    def test_non_json(self):
        sim = ApiLogicEnginePlugin._compute_similarity("<html>A</html>", "<html>A</html>")
        assert sim > 0.99

    def test_empty(self):
        assert ApiLogicEnginePlugin._compute_similarity("", "") == 1.0
        assert ApiLogicEnginePlugin._compute_similarity("a", "") == 0.0


class TestExtractIds:
    def test_extract_from_object(self):
        body = json.dumps({"id": 42, "name": "test"})
        ids = ApiLogicEnginePlugin._extract_ids_from_json(body)
        assert "42" in ids

    def test_extract_from_list(self):
        body = json.dumps([{"id": 1}, {"id": 2}])
        ids = ApiLogicEnginePlugin._extract_ids_from_json(body)
        assert "1" in ids
        assert "2" in ids

    def test_nested_ids(self):
        body = json.dumps({"data": {"user_id": 99}})
        ids = ApiLogicEnginePlugin._extract_ids_from_json(body)
        assert "99" in ids

    def test_invalid_json(self):
        ids = ApiLogicEnginePlugin._extract_ids_from_json("not json")
        assert ids == []


class TestLooksLikeUuid:
    def test_uuid(self):
        assert ApiLogicEnginePlugin._looks_like_uuid(
            "550e8400-e29b-41d4-a716-446655440000",
        )

    def test_not_uuid(self):
        assert not ApiLogicEnginePlugin._looks_like_uuid("42")
        assert not ApiLogicEnginePlugin._looks_like_uuid("abc")
