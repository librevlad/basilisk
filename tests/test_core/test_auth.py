"""Tests for session engine (auth manager)."""

from __future__ import annotations

from basilisk.core.auth import (
    AuthManager,
    AuthSession,
    BasicAuthStrategy,
    BearerTokenStrategy,
    FormLoginStrategy,
)


class TestAuthSession:
    def test_empty_session(self):
        session = AuthSession(host="example.com")
        assert not session.is_authenticated
        assert session.cookies == {}
        assert session.headers == {}

    def test_inject_headers_with_cookies(self):
        session = AuthSession(
            host="example.com",
            cookies={"session_id": "abc123", "csrf": "xyz"},
            headers={"Authorization": "Bearer token"},
            is_authenticated=True,
        )
        result = session.inject_headers({"Accept": "text/html"})
        assert result["Accept"] == "text/html"
        assert result["Authorization"] == "Bearer token"
        assert "session_id=abc123" in result["Cookie"]
        assert "csrf=xyz" in result["Cookie"]

    def test_inject_headers_merges_cookies(self):
        session = AuthSession(
            host="example.com",
            cookies={"new": "value"},
        )
        result = session.inject_headers({"Cookie": "existing=old"})
        assert "existing=old" in result["Cookie"]
        assert "new=value" in result["Cookie"]

    def test_inject_no_existing(self):
        session = AuthSession(
            host="example.com",
            headers={"X-API-Key": "secret"},
        )
        result = session.inject_headers()
        assert result["X-API-Key"] == "secret"


class TestBearerTokenStrategy:
    def test_can_handle(self):
        strategy = BearerTokenStrategy(token="my-jwt-token")
        assert strategy.can_handle("example.com", None)

    def test_cannot_handle_empty(self):
        strategy = BearerTokenStrategy(token="")
        assert not strategy.can_handle("example.com", None)

    async def test_login(self):
        strategy = BearerTokenStrategy(token="my-jwt-token")
        session = await strategy.login("example.com", None)
        assert session.is_authenticated
        assert session.headers["Authorization"] == "Bearer my-jwt-token"
        assert session.strategy == "bearer"


class TestBasicAuthStrategy:
    def test_can_handle(self):
        strategy = BasicAuthStrategy(username="admin", password="pass")
        assert strategy.can_handle("example.com", None)

    async def test_login(self):
        strategy = BasicAuthStrategy(username="admin", password="secret")
        session = await strategy.login("example.com", None)
        assert session.is_authenticated
        assert "Basic" in session.headers["Authorization"]
        assert session.strategy == "basic"


class TestFormLoginStrategy:
    def test_can_handle(self):
        strategy = FormLoginStrategy(username="user", password="pass")
        assert strategy.can_handle("example.com", None)

    def test_cannot_handle_no_creds(self):
        strategy = FormLoginStrategy()
        assert not strategy.can_handle("example.com", None)

    def test_extract_csrf(self):
        html = '''
        <form>
            <input type="hidden" name="csrf_token" value="abc123">
            <input name="username">
            <input name="password" type="password">
        </form>
        '''
        result = FormLoginStrategy._extract_csrf(html)
        assert result is not None
        assert result[0] == "csrf_token"
        assert result[1] == "abc123"

    def test_extract_csrf_not_found(self):
        html = "<form><input name='name'></form>"
        result = FormLoginStrategy._extract_csrf(html)
        assert result is None

    def test_guess_username_field(self):
        html = '<input name="email" type="text">'
        assert FormLoginStrategy._guess_username_field(html) == "email"

    def test_guess_username_field_default(self):
        html = "<input name='something_else'>"
        assert FormLoginStrategy._guess_username_field(html) == "username"

    def test_guess_password_field(self):
        html = '<input name="passwd" type="password">'
        assert FormLoginStrategy._guess_password_field(html) == "passwd"

    def test_extract_form_action(self):
        html = '<form action="/auth/login" method="post">'
        action = FormLoginStrategy._extract_form_action(html, "/fallback")
        assert action == "/auth/login"

    def test_extract_form_action_fallback(self):
        html = "<form>"
        action = FormLoginStrategy._extract_form_action(html, "/fallback")
        assert action == "/fallback"

    def test_check_auth_success_positive(self):
        assert FormLoginStrategy._check_auth_success(
            200, "<html>Welcome! <a href='/logout'>Logout</a></html>"
        )

    def test_check_auth_success_failure(self):
        assert not FormLoginStrategy._check_auth_success(
            200, "<html>Login failed: Invalid credentials</html>"
        )


class TestAuthManager:
    def test_initial_state(self):
        manager = AuthManager()
        assert manager.authenticated_hosts == []
        assert manager.get_session("example.com") is None

    def test_set_bearer(self):
        manager = AuthManager()
        manager.set_bearer("api.example.com", "jwt-token-123")
        session = manager.get_session("api.example.com")
        assert session is not None
        assert session.is_authenticated
        assert session.headers["Authorization"] == "Bearer jwt-token-123"
        assert "api.example.com" in manager.authenticated_hosts

    def test_inject_authenticated(self):
        manager = AuthManager()
        manager.set_bearer("example.com", "token")
        headers = manager.inject("example.com", {"Accept": "application/json"})
        assert headers["Accept"] == "application/json"
        assert headers["Authorization"] == "Bearer token"

    def test_inject_unauthenticated(self):
        manager = AuthManager()
        headers = manager.inject("example.com", {"Accept": "text/html"})
        assert headers == {"Accept": "text/html"}

    def test_save_and_load(self, tmp_path):
        path = tmp_path / "sessions.json"
        manager = AuthManager()
        manager.set_bearer("host1.com", "token1")
        manager.set_bearer("host2.com", "token2")
        manager.save(path)

        manager2 = AuthManager()
        manager2.load(path)
        assert "host1.com" in manager2.authenticated_hosts
        assert "host2.com" in manager2.authenticated_hosts
        s = manager2.get_session("host1.com")
        assert s is not None
        assert s.headers["Authorization"] == "Bearer token1"

    def test_load_nonexistent(self, tmp_path):
        manager = AuthManager()
        manager.load(tmp_path / "does_not_exist.json")
        assert manager.authenticated_hosts == []

    def test_add_strategy(self):
        manager = AuthManager()
        strategy = BearerTokenStrategy(token="test")
        manager.add_strategy(strategy)
        assert len(manager._strategies) == 1

    def test_set_credentials(self):
        manager = AuthManager()
        manager.set_credentials("example.com", "admin", "password123")
        assert manager._credentials["example.com"] == {
            "username": "admin", "password": "password123",
        }
