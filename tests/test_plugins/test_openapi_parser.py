"""Tests for OpenAPI/Swagger parser plugin."""

from __future__ import annotations

from basilisk.plugins.analysis.openapi_parser import OpenApiParserPlugin


class TestOpenApiParser:
    def test_meta(self):
        plugin = OpenApiParserPlugin()
        assert plugin.meta.name == "openapi_parser"
        assert "api_detect" in plugin.meta.depends_on
        assert "openapi_spec" in plugin.meta.produces

    def test_is_openapi_spec_v3(self):
        spec = {"openapi": "3.0.0", "info": {"title": "Test"}, "paths": {}}
        assert OpenApiParserPlugin._is_openapi_spec(spec)

    def test_is_openapi_spec_v2(self):
        spec = {"swagger": "2.0", "info": {"title": "Test"}, "paths": {}}
        assert OpenApiParserPlugin._is_openapi_spec(spec)

    def test_is_not_openapi_spec(self):
        assert not OpenApiParserPlugin._is_openapi_spec({"random": "data"})
        assert not OpenApiParserPlugin._is_openapi_spec("string")
        assert not OpenApiParserPlugin._is_openapi_spec([1, 2, 3])

    def test_get_spec_version_v3(self):
        spec = {"openapi": "3.1.0"}
        assert "3.1.0" in OpenApiParserPlugin._get_spec_version(spec)

    def test_get_spec_version_v2(self):
        spec = {"swagger": "2.0"}
        assert "2.0" in OpenApiParserPlugin._get_spec_version(spec)

    def test_get_spec_title(self):
        spec = {"info": {"title": "My API"}}
        assert OpenApiParserPlugin._get_spec_title(spec) == "My API"

    def test_get_spec_title_missing(self):
        spec = {}
        assert OpenApiParserPlugin._get_spec_title(spec) == "Untitled API"

    def test_extract_servers_v3(self):
        spec = {
            "servers": [
                {"url": "https://api.example.com/v1"},
                {"url": "https://staging.example.com/v1"},
            ]
        }
        servers = OpenApiParserPlugin._extract_servers(spec, "https://fallback.com")
        assert "https://api.example.com/v1" in servers
        assert len(servers) == 2

    def test_extract_servers_v2(self):
        spec = {
            "host": "api.example.com",
            "basePath": "/v1",
            "schemes": ["https"],
        }
        servers = OpenApiParserPlugin._extract_servers(spec, "https://fallback.com")
        assert "https://api.example.com/v1" in servers

    def test_extract_servers_fallback(self):
        spec = {}
        servers = OpenApiParserPlugin._extract_servers(spec, "https://fallback.com")
        assert servers == ["https://fallback.com"]

    def test_extract_endpoints(self):
        spec = {
            "paths": {
                "/users": {
                    "get": {
                        "summary": "List users",
                        "parameters": [
                            {"name": "page", "in": "query", "type": "integer"},
                            {"name": "limit", "in": "query", "type": "integer"},
                        ],
                    },
                    "post": {
                        "summary": "Create user",
                        "security": [{"bearerAuth": []}],
                    },
                },
                "/users/{id}": {
                    "get": {
                        "summary": "Get user",
                        "parameters": [
                            {"name": "id", "in": "path", "type": "integer"},
                        ],
                    },
                },
            },
        }
        endpoints = OpenApiParserPlugin._extract_endpoints(spec)
        assert len(endpoints) == 3
        get_users = next(e for e in endpoints if e["path"] == "/users" and e["method"] == "get")
        assert len(get_users["parameters"]) == 2
        assert get_users["parameters"][0]["name"] == "page"

    def test_extract_endpoints_with_global_security(self):
        spec = {
            "security": [{"apiKey": []}],
            "paths": {
                "/data": {
                    "get": {"summary": "Get data"},
                },
            },
        }
        endpoints = OpenApiParserPlugin._extract_endpoints(spec)
        assert endpoints[0]["requires_auth"] is True

    def test_extract_endpoints_no_security(self):
        spec = {
            "paths": {
                "/public": {
                    "get": {"summary": "Public endpoint"},
                },
            },
        }
        endpoints = OpenApiParserPlugin._extract_endpoints(spec)
        assert endpoints[0]["requires_auth"] is False

    def test_extract_auth_schemes_v3(self):
        spec = {
            "components": {
                "securitySchemes": {
                    "bearerAuth": {"type": "http", "scheme": "bearer"},
                    "apiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
                }
            }
        }
        schemes = OpenApiParserPlugin._extract_auth_schemes(spec)
        assert len(schemes) == 2
        assert any("bearer" in s.lower() for s in schemes)

    def test_extract_auth_schemes_v2(self):
        spec = {
            "securityDefinitions": {
                "oauth2": {"type": "oauth2"},
            }
        }
        schemes = OpenApiParserPlugin._extract_auth_schemes(spec)
        assert len(schemes) == 1

    def test_extract_request_body(self):
        operation = {
            "requestBody": {
                "required": True,
                "content": {
                    "application/json": {
                        "schema": {"type": "object", "properties": {"name": {"type": "string"}}}
                    }
                }
            }
        }
        result = OpenApiParserPlugin._extract_request_body(operation)
        assert result is not None
        assert result["content_type"] == "application/json"
        assert result["required"] is True

    def test_extract_request_body_missing(self):
        result = OpenApiParserPlugin._extract_request_body({})
        assert result is None

    def test_extract_params_dedup(self):
        """Path-level and operation-level params should be deduplicated."""
        path_params = [{"name": "id", "in": "path", "type": "integer"}]
        operation = {
            "parameters": [
                {"name": "id", "in": "path", "type": "integer"},
                {"name": "fields", "in": "query", "type": "string"},
            ],
        }
        params = OpenApiParserPlugin._extract_params(operation, path_params)
        names = [p["name"] for p in params]
        assert names.count("id") == 1
        assert "fields" in names
