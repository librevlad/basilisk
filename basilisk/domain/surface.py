"""Attack surface descriptors — typed surfaces discovered during recon."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class Surface(BaseModel):
    """A discoverable attack surface on a target."""

    host: str
    surface_type: str = "generic"
    url: str = ""
    method: str = "GET"
    params: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    meta: dict[str, Any] = Field(default_factory=dict)


class LoginSurface(Surface):
    """A login form surface."""

    surface_type: str = "login"
    username_field: str = "username"
    password_field: str = "password"
    csrf_field: str = ""


class UploadSurface(Surface):
    """A file upload surface."""

    surface_type: str = "upload"
    file_field: str = "file"
    allowed_extensions: list[str] = Field(default_factory=list)


class SearchSurface(Surface):
    """A search endpoint surface."""

    surface_type: str = "search"
    query_param: str = "q"


class ApiSurface(Surface):
    """An API surface."""

    surface_type: str = "api"
    endpoints: list[str] = Field(default_factory=list)
    auth_type: str = ""


class GraphqlSurface(Surface):
    """A GraphQL surface."""

    surface_type: str = "graphql"
    introspection_enabled: bool = False
