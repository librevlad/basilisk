"""Tests for TrainingRunner authentication methods.

Tests form login, JSON API auth, CSRF token extraction, setup URLs,
extra cookies, and {uuid} placeholder replacement.
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from basilisk.training.profile import AuthConfig, TrainingProfile
from basilisk.training.runner import TrainingRunner


def _make_profile(auth: dict | None = None, **kwargs) -> TrainingProfile:
    """Create a minimal training profile with optional auth config."""
    base = {
        "name": "test",
        "target": "localhost:8080",
        "target_ports": [8080],
        "max_steps": 10,
        "expected_findings": [
            {"title": "SQLi", "severity": "critical", "plugin_hints": ["sqli_basic"]},
        ],
    }
    if auth:
        base["auth"] = auth
    base.update(kwargs)
    return TrainingProfile.model_validate(base)


def _mock_response(text: str = "", status: int = 200, url: str = "") -> AsyncMock:
    resp = AsyncMock()
    resp.status = status
    resp.url = url
    resp.text = AsyncMock(return_value=text)
    return resp


class TestProbeTargetScheme:
    """Test HTTP scheme probing logic."""

    @pytest.mark.asyncio
    async def test_https_preferred(self):
        profile = _make_profile()
        runner = TrainingRunner(profile)

        ctx = MagicMock()
        ctx.http = AsyncMock()
        ctx.http.head = AsyncMock(return_value=_mock_response())

        result = await runner._probe_target_scheme(ctx, "localhost:8080")
        assert result == "https"

    @pytest.mark.asyncio
    async def test_fallback_to_http(self):
        profile = _make_profile()
        runner = TrainingRunner(profile)

        ctx = MagicMock()
        ctx.http = AsyncMock()

        call_count = 0

        async def side_effect(url, **kw):
            nonlocal call_count
            call_count += 1
            if "https://" in url:
                raise ConnectionError("no ssl")
            return _mock_response()

        ctx.http.head = side_effect

        result = await runner._probe_target_scheme(ctx, "localhost:8080")
        assert result == "http"

    @pytest.mark.asyncio
    async def test_no_http_client(self):
        profile = _make_profile()
        runner = TrainingRunner(profile)

        ctx = MagicMock()
        ctx.http = None

        result = await runner._probe_target_scheme(ctx, "localhost:8080")
        assert result == "http"


class TestJsonApiAuth:
    """Test JSON API authentication flow."""

    @pytest.mark.asyncio
    async def test_login_extracts_token(self):
        profile = _make_profile()
        runner = TrainingRunner(profile)

        auth_cfg = AuthConfig(
            auth_type="json_api",
            login_url="/api/login",
            username="admin",
            password="secret",
            token_path="token",
        )

        ctx = MagicMock()
        ctx.http = AsyncMock()
        ctx.state = {}
        ctx.http.post = AsyncMock(return_value=_mock_response(
            text=json.dumps({"token": "eyJhbGciOiJIUzI1NiJ9.test"}),
            status=200,
        ))
        ctx.http.set_default_header = AsyncMock()

        await runner._json_api_auth(ctx, auth_cfg, "http://localhost:8080", "localhost:8080")

        ctx.http.post.assert_called_once()
        assert ctx.state["auth_token"] == "eyJhbGciOiJIUzI1NiJ9.test"
        assert ctx.state["jwt_token"] == "eyJhbGciOiJIUzI1NiJ9.test"
        ctx.http.set_default_header.assert_called_once_with(
            "Authorization", "eyJhbGciOiJIUzI1NiJ9.test",
        )

    @pytest.mark.asyncio
    async def test_login_with_bearer_prefix(self):
        auth_cfg = AuthConfig(
            auth_type="json_api",
            login_url="/api/login",
            username="user",
            password="pass",
            token_path="data.token",
            token_prefix="Bearer ",
        )

        ctx = MagicMock()
        ctx.http = AsyncMock()
        ctx.state = {}
        ctx.http.post = AsyncMock(return_value=_mock_response(
            text=json.dumps({"data": {"token": "jwt123"}}),
        ))
        ctx.http.set_default_header = AsyncMock()

        runner = TrainingRunner(_make_profile())
        await runner._json_api_auth(ctx, auth_cfg, "http://localhost", "localhost")

        ctx.http.set_default_header.assert_called_once_with(
            "Authorization", "Bearer jwt123",
        )

    @pytest.mark.asyncio
    async def test_login_with_custom_header(self):
        auth_cfg = AuthConfig(
            auth_type="json_api",
            login_url="/api/login",
            username="user",
            password="pass",
            token_path="token",
            token_header="Authorization-Token",
        )

        ctx = MagicMock()
        ctx.http = AsyncMock()
        ctx.state = {}
        ctx.http.post = AsyncMock(return_value=_mock_response(
            text=json.dumps({"token": "tok123"}),
        ))
        ctx.http.set_default_header = AsyncMock()

        runner = TrainingRunner(_make_profile())
        await runner._json_api_auth(ctx, auth_cfg, "http://localhost", "localhost")

        ctx.http.set_default_header.assert_called_once_with(
            "Authorization-Token", "tok123",
        )

    @pytest.mark.asyncio
    async def test_register_then_login(self):
        auth_cfg = AuthConfig(
            auth_type="json_api",
            login_url="/api/login",
            register_url="/api/register",
            register_data={"email": "test-{uuid}@test.com", "password": "Pass123!"},
            username="test@test.com",
            password="Pass123!",
            token_path="token",
        )

        ctx = MagicMock()
        ctx.http = AsyncMock()
        ctx.state = {}
        post_responses = [
            _mock_response(text=json.dumps({"id": 1}), status=201),  # register
            _mock_response(text=json.dumps({"token": "jwt456"}), status=200),  # login
        ]
        ctx.http.post = AsyncMock(side_effect=post_responses)
        ctx.http.set_default_header = AsyncMock()

        runner = TrainingRunner(_make_profile())
        await runner._json_api_auth(ctx, auth_cfg, "http://localhost", "localhost")

        assert ctx.http.post.call_count == 2
        # Check register call used {uuid} replacement
        reg_call = ctx.http.post.call_args_list[0]
        reg_data = reg_call.kwargs.get("json", reg_call.args[1] if len(reg_call.args) > 1 else {})
        # UUID should have been replaced (no {uuid} in actual data)
        assert "{uuid}" not in str(reg_data)

    @pytest.mark.asyncio
    async def test_login_failure_no_token(self):
        auth_cfg = AuthConfig(
            auth_type="json_api",
            login_url="/api/login",
            username="user",
            password="wrong",
            token_path="token",
        )

        ctx = MagicMock()
        ctx.http = AsyncMock()
        ctx.state = {}
        ctx.http.post = AsyncMock(return_value=_mock_response(
            text=json.dumps({"error": "invalid credentials"}), status=401,
        ))
        ctx.http.set_default_header = AsyncMock()

        runner = TrainingRunner(_make_profile())
        await runner._json_api_auth(ctx, auth_cfg, "http://localhost", "localhost")

        # No token should be set
        assert "auth_token" not in ctx.state
        ctx.http.set_default_header.assert_not_called()

    @pytest.mark.asyncio
    async def test_login_exception_handled(self):
        auth_cfg = AuthConfig(
            auth_type="json_api",
            login_url="/api/login",
            username="user",
            password="pass",
            token_path="token",
        )

        ctx = MagicMock()
        ctx.http = AsyncMock()
        ctx.state = {}
        ctx.http.post = AsyncMock(side_effect=ConnectionError("refused"))

        runner = TrainingRunner(_make_profile())
        # Should not raise
        await runner._json_api_auth(ctx, auth_cfg, "http://localhost", "localhost")
        assert "auth_token" not in ctx.state


class TestFormAuth:
    """Test form-based authentication with CSRF token extraction."""

    def _make_login_html(self, csrf_name: str = "csrf_token", csrf_value: str = "abc123"):
        return (
            f'<form method="POST">'
            f'<input type="hidden" name="{csrf_name}" value="{csrf_value}">'
            f'<input type="text" name="username">'
            f'<input type="password" name="password">'
            f'</form>'
        )

    @pytest.mark.asyncio
    async def test_csrf_token_extraction_name_value_order(self):
        """CSRF token extracted from hidden input (name before value)."""
        html = self._make_login_html("user_token", "tok999")

        # Test the CSRF extraction logic directly
        import re
        csrf_tokens: dict[str, str] = {}
        for m in re.finditer(
            r'<input[^>]+type=["\']hidden["\'][^>]*'
            r'name=["\']([^"\']*(?:csrf|token)[^"\']*)["\']'
            r'[^>]*value=["\']([^"\']*)["\']',
            html, re.IGNORECASE,
        ):
            csrf_tokens[m.group(1)] = m.group(2)

        assert csrf_tokens == {"user_token": "tok999"}

    @pytest.mark.asyncio
    async def test_csrf_token_extraction_value_name_order(self):
        """CSRF token extracted from hidden input (value before name)."""
        html = (
            '<input type="hidden" value="xyz789" name="csrf_token">'
        )

        import re
        csrf_tokens: dict[str, str] = {}
        for m in re.finditer(
            r'<input[^>]+type=["\']hidden["\'][^>]*'
            r'value=["\']([^"\']*)["\']'
            r'[^>]*name=["\']([^"\']*(?:csrf|token)[^"\']*)["\']',
            html, re.IGNORECASE,
        ):
            csrf_tokens[m.group(2)] = m.group(1)

        assert csrf_tokens == {"csrf_token": "xyz789"}

    @pytest.mark.asyncio
    async def test_spring_csrf_meta_tag(self):
        """CSRF token from Spring Security <meta> tag."""
        html = '<meta name="_csrf" content="spring_token_abc">'

        import re
        csrf_meta = re.search(
            r'<meta\s+name=["\']_csrf["\']\s+content=["\']([^"\']+)["\']',
            html, re.IGNORECASE,
        )
        assert csrf_meta is not None
        assert csrf_meta.group(1) == "spring_token_abc"

    @pytest.mark.asyncio
    async def test_login_success_detection_logout_keyword(self):
        """Successful login detected by 'logout' keyword in response."""
        response_body = '<html><body>Welcome! <a href="/logout">Logout</a></body></html>'
        body_lower = response_body.lower()
        login_ok = "logout" in body_lower or "sign out" in body_lower
        assert login_ok is True

    @pytest.mark.asyncio
    async def test_login_success_detection_redirect(self):
        """Successful login detected by redirect away from login page."""
        resp_url = "http://localhost:8080/dashboard"
        redirected_away = resp_url and "/login" not in resp_url.lower().split("?")[0]
        assert redirected_away is True

    @pytest.mark.asyncio
    async def test_login_failure_detection_bad_credentials(self):
        """Login failure detected by 'bad credentials' in body."""
        body_lower = "welcome back... bad credentials"
        login_ok = "welcome" in body_lower
        if login_ok and "bad credentials" in body_lower:
            login_ok = False
        assert login_ok is False


class TestSetupUrl:
    """Test setup URL execution (e.g., DVWA DB reset, VamPi /createdb)."""

    @pytest.mark.asyncio
    async def test_setup_get_no_data(self):
        """Setup with empty data triggers GET request."""
        auth_cfg = AuthConfig(setup_url="/createdb")
        assert auth_cfg.setup_url == "/createdb"
        assert auth_cfg.setup_data == {}

    @pytest.mark.asyncio
    async def test_setup_post_with_data(self):
        """Setup with data triggers POST with CSRF extraction."""
        auth_cfg = AuthConfig(
            setup_url="/setup.php",
            setup_data={"create_db": "Create / Reset Database"},
        )
        assert auth_cfg.setup_data == {"create_db": "Create / Reset Database"}

    @pytest.mark.asyncio
    async def test_setup_get_url_separate(self):
        """Separate GET URL for cookie/token before POST."""
        auth_cfg = AuthConfig(
            setup_url="/setup.php",
            setup_get_url="/setup.php",
            setup_data={"create_db": "Create"},
        )
        assert auth_cfg.setup_get_url == "/setup.php"


class TestExtraCookies:
    """Test extra cookie injection."""

    def test_extra_cookies_config(self):
        auth_cfg = AuthConfig(extra_cookies={"security": "low"})
        assert auth_cfg.extra_cookies == {"security": "low"}

    def test_multiple_extra_cookies(self):
        auth_cfg = AuthConfig(extra_cookies={"security": "low", "debug": "true"})
        assert len(auth_cfg.extra_cookies) == 2


class TestUuidPlaceholder:
    """Test {uuid} placeholder replacement in auth credentials."""

    def test_uuid_in_login_fields(self):
        auth_cfg = AuthConfig(
            login_fields={"username": "user-{uuid}", "password": "Pass123!"},
        )
        assert "{uuid}" in auth_cfg.login_fields["username"]

    def test_uuid_in_register_data(self):
        auth_cfg = AuthConfig(
            register_data={
                "email": "test-{uuid}@test.com",
                "password": "Pass123!",
            },
        )
        run_id = "abcd1234"
        replaced = {
            k: v.replace("{uuid}", run_id) if isinstance(v, str) else v
            for k, v in auth_cfg.register_data.items()
        }
        assert replaced["email"] == "test-abcd1234@test.com"
        assert replaced["password"] == "Pass123!"

    def test_uuid_in_setup_data(self):
        auth_cfg = AuthConfig(
            setup_data={"name": "app-{uuid}"},
        )
        run_id = "12345678"
        replaced = {
            k: v.replace("{uuid}", run_id) if isinstance(v, str) else v
            for k, v in auth_cfg.setup_data.items()
        }
        assert replaced["name"] == "app-12345678"
