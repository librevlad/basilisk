"""Tests for entity normalization functions."""

from __future__ import annotations

from basilisk.knowledge.entities import Entity
from basilisk.knowledge.normalize import (
    normalize_host,
    normalize_path,
    normalize_port,
    normalize_tech_name,
)


class TestNormalizeHost:
    """Test hostname normalization."""

    def test_case_insensitive(self):
        assert normalize_host("EXAMPLE.COM") == "example.com"

    def test_strips_protocol(self):
        assert normalize_host("https://foo.com/") == "foo.com"

    def test_strips_http(self):
        assert normalize_host("http://bar.com") == "bar.com"

    def test_strips_trailing_dot(self):
        assert normalize_host("foo.com.") == "foo.com"

    def test_strips_trailing_slash(self):
        assert normalize_host("foo.com/") == "foo.com"

    def test_strips_path_after_host(self):
        assert normalize_host("foo.com/some/path") == "foo.com"

    def test_strips_whitespace(self):
        assert normalize_host("  foo.com  ") == "foo.com"

    def test_already_normal(self):
        assert normalize_host("example.com") == "example.com"

    def test_mixed(self):
        assert normalize_host("  HTTPS://Foo.COM./bar  ") == "foo.com"


class TestNormalizePath:
    """Test path normalization."""

    def test_collapses_slashes(self):
        assert normalize_path("/foo//bar///baz") == "/foo/bar/baz"

    def test_strips_query(self):
        assert normalize_path("/login?user=admin") == "/login"

    def test_strips_fragment(self):
        assert normalize_path("/page#section") == "/page"

    def test_strips_trailing_slash(self):
        assert normalize_path("/admin/") == "/admin"

    def test_root_preserved(self):
        assert normalize_path("/") == "/"

    def test_lowercase(self):
        assert normalize_path("/Admin/Panel") == "/admin/panel"


class TestNormalizePort:
    """Test port normalization."""

    def test_int_passthrough(self):
        assert normalize_port(443) == 443

    def test_string_to_int(self):
        assert normalize_port("80") == 80

    def test_clamp_low(self):
        assert normalize_port(0) == 1

    def test_clamp_high(self):
        assert normalize_port(70000) == 65535


class TestNormalizeTechName:
    """Test technology name normalization."""

    def test_lowercase(self):
        assert normalize_tech_name("Nginx") == "nginx"

    def test_strips_whitespace(self):
        assert normalize_tech_name("  Apache  ") == "apache"


class TestEntityNormalization:
    """Test that Entity factories produce same IDs for different input formats."""

    def test_host_same_id_different_case(self):
        assert Entity.host("FOO.COM").id == Entity.host("foo.com").id

    def test_host_same_id_with_protocol(self):
        assert Entity.host("https://foo.com").id == Entity.host("foo.com").id

    def test_host_same_id_trailing_dot(self):
        assert Entity.host("foo.com.").id == Entity.host("foo.com").id

    def test_service_same_id_different_case(self):
        e1 = Entity.service("FOO.COM", 80)
        e2 = Entity.service("foo.com", 80)
        assert e1.id == e2.id

    def test_endpoint_same_id_different_case(self):
        e1 = Entity.endpoint("FOO.COM", "/Login")
        e2 = Entity.endpoint("foo.com", "/login")
        assert e1.id == e2.id

    def test_endpoint_collapses_slashes(self):
        e1 = Entity.endpoint("foo.com", "/a//b")
        e2 = Entity.endpoint("foo.com", "/a/b")
        assert e1.id == e2.id

    def test_technology_same_id_different_case(self):
        e1 = Entity.technology("FOO.COM", "Nginx", "1.0")
        e2 = Entity.technology("foo.com", "nginx", "1.0")
        assert e1.id == e2.id

    def test_finding_same_id_different_host_case(self):
        e1 = Entity.finding("FOO.COM", "XSS")
        e2 = Entity.finding("foo.com", "XSS")
        assert e1.id == e2.id

    def test_container_same_id_different_host_case(self):
        e1 = Entity.container("FOO.COM", "abc123")
        e2 = Entity.container("foo.com", "abc123")
        assert e1.id == e2.id

    def test_image_same_id_different_host_case(self):
        e1 = Entity.image("FOO.COM", "nginx", "latest")
        e2 = Entity.image("foo.com", "nginx", "latest")
        assert e1.id == e2.id

    def test_normalized_data_stored(self):
        e = Entity.host("HTTPS://Example.COM/")
        assert e.data["host"] == "example.com"
