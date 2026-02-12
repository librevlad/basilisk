"""Session engine — authentication, cookie persistence, login strategies."""

from __future__ import annotations

import json
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class AuthSession:
    """Authenticated session state for a single host."""

    host: str
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    is_authenticated: bool = False
    strategy: str = ""
    meta: dict[str, Any] = field(default_factory=dict)

    def inject_headers(self, existing: dict[str, str] | None = None) -> dict[str, str]:
        """Merge auth headers/cookies into a request headers dict."""
        result = dict(existing or {})
        result.update(self.headers)
        if self.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            existing_cookie = result.get("Cookie", "")
            if existing_cookie:
                result["Cookie"] = f"{existing_cookie}; {cookie_str}"
            else:
                result["Cookie"] = cookie_str
        return result


class LoginStrategy(ABC):
    """Base class for authentication strategies."""

    name: str = "base"

    @abstractmethod
    async def login(self, host: str, ctx: Any) -> AuthSession:
        """Perform login and return an authenticated session."""

    @abstractmethod
    def can_handle(self, host: str, ctx: Any) -> bool:
        """Check if this strategy applies to the given host."""


class FormLoginStrategy(LoginStrategy):
    """HTML form-based login (POST username/password to form action)."""

    name = "form"

    def __init__(
        self,
        username: str = "",
        password: str = "",
        login_url: str = "",
        username_field: str = "",
        password_field: str = "",
    ) -> None:
        self.username = username
        self.password = password
        self.login_url = login_url
        self.username_field = username_field
        self.password_field = password_field

    def can_handle(self, host: str, ctx: Any) -> bool:
        return bool(self.username and self.password)

    async def login(self, host: str, ctx: Any) -> AuthSession:
        session = AuthSession(host=host, strategy=self.name)

        if ctx.http is None:
            return session

        base_url = await self._resolve_base(host, ctx)
        if not base_url:
            return session

        # Discover login page if URL not provided
        login_url = self.login_url
        if not login_url:
            login_url = await self._discover_login(base_url, ctx)
        if not login_url:
            logger.warning("No login page found for %s", host)
            return session

        if not login_url.startswith("http"):
            login_url = f"{base_url}{login_url}"

        # Fetch login page for CSRF token and form fields
        try:
            async with ctx.rate:
                resp = await ctx.http.get(login_url, timeout=10.0)
                body = await resp.text(encoding="utf-8", errors="replace")
                cookies = self._extract_cookies(resp)
                session.cookies.update(cookies)
        except Exception:
            logger.debug("Failed to fetch login page: %s", login_url)
            return session

        # Extract form fields
        csrf_token = self._extract_csrf(body)
        u_field = self.username_field or self._guess_username_field(body)
        p_field = self.password_field or self._guess_password_field(body)
        action = self._extract_form_action(body, login_url)

        # Build POST data
        post_data: dict[str, str] = {
            u_field: self.username,
            p_field: self.password,
        }
        if csrf_token:
            post_data[csrf_token[0]] = csrf_token[1]

        # Submit login form
        try:
            headers = session.inject_headers({
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": login_url,
            })
            async with ctx.rate:
                resp = await ctx.http.post(
                    action, data=post_data, headers=headers,
                    timeout=10.0, allow_redirects=False,
                )
                new_cookies = self._extract_cookies(resp)
                session.cookies.update(new_cookies)

                # Follow redirect if present
                location = resp.headers.get("Location", "")
                if resp.status in (301, 302, 303) and location:
                    if not location.startswith("http"):
                        location = f"{base_url}{location}"
                    redirect_headers = session.inject_headers({})
                    async with ctx.rate:
                        resp2 = await ctx.http.get(
                            location, headers=redirect_headers, timeout=10.0,
                        )
                        session.cookies.update(self._extract_cookies(resp2))
                        final_body = await resp2.text(
                            encoding="utf-8", errors="replace",
                        )
                        # Check authentication success
                        if self._check_auth_success(resp2.status, final_body):
                            session.is_authenticated = True
                elif resp.status == 200:
                    resp_body = await resp.text(
                        encoding="utf-8", errors="replace",
                    )
                    if self._check_auth_success(resp.status, resp_body):
                        session.is_authenticated = True

        except Exception:
            logger.debug("Login POST failed for %s", host)

        if session.is_authenticated:
            logger.info("Authenticated to %s via form login", host)
        else:
            logger.warning("Form login to %s may have failed", host)

        return session

    async def _resolve_base(self, host: str, ctx: Any) -> str:
        for scheme in ("https", "http"):
            try:
                async with ctx.rate:
                    await ctx.http.head(f"{scheme}://{host}/", timeout=5.0)
                    return f"{scheme}://{host}"
            except Exception:
                continue
        return ""

    async def _discover_login(self, base_url: str, ctx: Any) -> str:
        """Try common login paths."""
        login_paths = [
            "/login", "/signin", "/auth/login", "/user/login",
            "/account/login", "/admin/login", "/api/auth/login",
            "/auth/signin", "/sign-in", "/log-in",
            "/wp-login.php", "/administrator",
        ]
        for path in login_paths:
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(
                        f"{base_url}{path}", timeout=5.0,
                        allow_redirects=False,
                    )
                    if resp.status in (200, 301, 302):
                        return path
            except Exception:
                continue
        return ""

    @staticmethod
    def _extract_cookies(resp: Any) -> dict[str, str]:
        cookies: dict[str, str] = {}
        for hdr in resp.headers.getall("Set-Cookie", []):
            parts = hdr.split(";")[0].strip()
            if "=" in parts:
                name, _, value = parts.partition("=")
                cookies[name.strip()] = value.strip()
        return cookies

    @staticmethod
    def _extract_csrf(html: str) -> tuple[str, str] | None:
        """Extract CSRF token from HTML form."""
        csrf_names = [
            "csrf_token", "_token", "csrfmiddlewaretoken",
            "authenticity_token", "__RequestVerificationToken",
            "_csrf", "csrf", "CSRF_TOKEN", "nonce",
        ]
        for name in csrf_names:
            pattern = (
                rf'name\s*=\s*["\']({re.escape(name)})["\']'
                rf'\s+value\s*=\s*["\']([^"\']*)["\']'
            )
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return (match.group(1), match.group(2))
            # Try reversed order (value before name)
            pattern2 = (
                rf'value\s*=\s*["\']([^"\']*)["\']'
                rf'\s+name\s*=\s*["\']({re.escape(name)})["\']'
            )
            match2 = re.search(pattern2, html, re.IGNORECASE)
            if match2:
                return (match2.group(2), match2.group(1))
        return None

    @staticmethod
    def _guess_username_field(html: str) -> str:
        for name in ("username", "email", "login", "user", "user_email"):
            if re.search(
                rf'name\s*=\s*["\']({re.escape(name)})["\']',
                html, re.IGNORECASE,
            ):
                return name
        return "username"

    @staticmethod
    def _guess_password_field(html: str) -> str:
        for name in ("password", "passwd", "pass", "pwd"):
            if re.search(
                rf'name\s*=\s*["\']({re.escape(name)})["\']',
                html, re.IGNORECASE,
            ):
                return name
        return "password"

    @staticmethod
    def _extract_form_action(html: str, fallback_url: str) -> str:
        match = re.search(
            r'<form[^>]*action\s*=\s*["\']([^"\']*)["\']',
            html, re.IGNORECASE,
        )
        if match:
            action = match.group(1)
            if action and action != "#":
                return action
        return fallback_url

    @staticmethod
    def _check_auth_success(status: int, body: str) -> bool:
        """Heuristic: did we successfully log in?"""
        lower = body.lower()
        failure_indicators = (
            "invalid credentials", "invalid password", "login failed",
            "incorrect password", "authentication failed", "wrong password",
            "bad credentials", "неверный пароль", "ошибка авторизации",
        )
        if any(ind in lower for ind in failure_indicators):
            return False
        success_indicators = (
            "logout", "sign out", "log out", "my account",
            "dashboard", "profile", "welcome", "выйти",
            "личный кабинет",
        )
        if any(ind in lower for ind in success_indicators):
            return True
        # 200 with session cookie likely = success
        return status == 200


class BearerTokenStrategy(LoginStrategy):
    """Bearer token authentication (API key, JWT, etc.)."""

    name = "bearer"

    def __init__(self, token: str = "") -> None:
        self.token = token

    def can_handle(self, host: str, ctx: Any) -> bool:
        return bool(self.token)

    async def login(self, host: str, ctx: Any) -> AuthSession:
        session = AuthSession(
            host=host,
            strategy=self.name,
            headers={"Authorization": f"Bearer {self.token}"},
            is_authenticated=True,
        )
        return session


class BasicAuthStrategy(LoginStrategy):
    """HTTP Basic authentication."""

    name = "basic"

    def __init__(self, username: str = "", password: str = "") -> None:
        self.username = username
        self.password = password

    def can_handle(self, host: str, ctx: Any) -> bool:
        return bool(self.username)

    async def login(self, host: str, ctx: Any) -> AuthSession:
        import base64
        creds = base64.b64encode(
            f"{self.username}:{self.password}".encode()
        ).decode()
        return AuthSession(
            host=host,
            strategy=self.name,
            headers={"Authorization": f"Basic {creds}"},
            is_authenticated=True,
        )


class AuthManager:
    """Manages authentication sessions across targets.

    Coordinates login strategies, cookie persistence, and session injection.
    Plugins access via ``ctx.auth.get_session(host)`` and
    ``ctx.auth.inject(host, headers)``.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, AuthSession] = {}
        self._strategies: list[LoginStrategy] = []
        self._credentials: dict[str, dict[str, str]] = {}

    def add_strategy(self, strategy: LoginStrategy) -> None:
        """Register a login strategy."""
        self._strategies.append(strategy)

    def set_credentials(
        self, host: str, username: str, password: str,
    ) -> None:
        """Set credentials for a specific host."""
        self._credentials[host] = {
            "username": username, "password": password,
        }

    def set_bearer(self, host: str, token: str) -> None:
        """Set bearer token for a specific host."""
        self._sessions[host] = AuthSession(
            host=host,
            strategy="bearer",
            headers={"Authorization": f"Bearer {token}"},
            is_authenticated=True,
        )

    async def login(self, host: str, ctx: Any) -> AuthSession:
        """Attempt login to host using registered strategies."""
        if host in self._sessions and self._sessions[host].is_authenticated:
            return self._sessions[host]

        for strategy in self._strategies:
            if strategy.can_handle(host, ctx):
                try:
                    session = await strategy.login(host, ctx)
                    if session.is_authenticated:
                        self._sessions[host] = session
                        return session
                except Exception:
                    logger.debug(
                        "Strategy %s failed for %s",
                        strategy.name, host,
                    )
                    continue

        # Fallback: return unauthenticated session
        session = AuthSession(host=host)
        self._sessions[host] = session
        return session

    def get_session(self, host: str) -> AuthSession | None:
        """Get existing session for host, or None."""
        return self._sessions.get(host)

    def inject(
        self,
        host: str,
        headers: dict[str, str] | None = None,
    ) -> dict[str, str]:
        """Inject auth headers/cookies for host into request headers."""
        session = self._sessions.get(host)
        if session and session.is_authenticated:
            return session.inject_headers(headers)
        return dict(headers or {})

    @property
    def authenticated_hosts(self) -> list[str]:
        """List of hosts with active authenticated sessions."""
        return [
            h for h, s in self._sessions.items() if s.is_authenticated
        ]

    def save(self, path: Path) -> None:
        """Persist sessions to a JSON file."""
        data: dict[str, Any] = {}
        for host, session in self._sessions.items():
            if session.is_authenticated:
                data[host] = {
                    "cookies": session.cookies,
                    "headers": session.headers,
                    "strategy": session.strategy,
                }
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def load(self, path: Path) -> None:
        """Load persisted sessions from a JSON file."""
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            for host, info in data.items():
                self._sessions[host] = AuthSession(
                    host=host,
                    cookies=info.get("cookies", {}),
                    headers=info.get("headers", {}),
                    is_authenticated=True,
                    strategy=info.get("strategy", "loaded"),
                )
        except Exception:
            logger.warning("Failed to load auth sessions from %s", path)
