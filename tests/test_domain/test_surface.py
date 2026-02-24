"""Tests for domain surface models."""

from __future__ import annotations

from basilisk.domain.surface import (
    ApiSurface,
    GraphqlSurface,
    LoginSurface,
    SearchSurface,
    Surface,
    UploadSurface,
)


class TestSurface:
    def test_generic_surface(self):
        s = Surface(host="example.com", url="https://example.com/page")
        assert s.surface_type == "generic"
        assert s.method == "GET"

    def test_login_surface(self):
        s = LoginSurface(
            host="example.com",
            url="https://example.com/login",
            username_field="user",
            password_field="pass",
            csrf_field="_token",
        )
        assert s.surface_type == "login"
        assert s.csrf_field == "_token"

    def test_upload_surface(self):
        s = UploadSurface(
            host="example.com",
            url="https://example.com/upload",
            file_field="document",
            allowed_extensions=[".pdf", ".doc"],
        )
        assert s.surface_type == "upload"
        assert ".pdf" in s.allowed_extensions

    def test_search_surface(self):
        s = SearchSurface(
            host="example.com",
            url="https://example.com/search",
            query_param="query",
        )
        assert s.surface_type == "search"
        assert s.query_param == "query"

    def test_api_surface(self):
        s = ApiSurface(
            host="example.com",
            url="https://example.com/api/v1",
            endpoints=["/users", "/posts"],
            auth_type="bearer",
        )
        assert s.surface_type == "api"
        assert len(s.endpoints) == 2

    def test_graphql_surface(self):
        s = GraphqlSurface(
            host="example.com",
            url="https://example.com/graphql",
            introspection_enabled=True,
        )
        assert s.surface_type == "graphql"
        assert s.introspection_enabled

    def test_surface_params(self):
        s = Surface(
            host="example.com",
            url="https://example.com/search",
            params={"q": "test", "page": "1"},
        )
        assert s.params["q"] == "test"

    def test_surface_headers(self):
        s = Surface(
            host="example.com",
            headers={"Authorization": "Bearer token123"},
        )
        assert "Authorization" in s.headers
