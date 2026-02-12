"""Tests for DynamicWordlistGenerator."""

from __future__ import annotations

from basilisk.utils.dynamic_wordlist import (
    DynamicWordlistGenerator,
    _extract_domain_parts,
)


class TestExtractDomainParts:
    def test_simple_domain(self):
        parts = _extract_domain_parts("example.com")
        assert "example" in parts

    def test_hyphenated_domain(self):
        parts = _extract_domain_parts("my-company.com")
        assert "my-company" in parts
        assert "my" in parts
        assert "company" in parts

    def test_subdomain(self):
        parts = _extract_domain_parts("api.example.com")
        assert "api" in parts
        assert "example" in parts

    def test_double_tld(self):
        parts = _extract_domain_parts("example.co.uk")
        assert "example" in parts


class TestDynamicWordlistGenerator:
    def setup_method(self):
        self.gen = DynamicWordlistGenerator()

    def test_generate_dirs(self):
        words = self.gen.generate("example.com", scope="dirs")
        assert len(words) > 0
        assert "example" in words
        assert "example-admin" in words
        assert "example-api" in words

    def test_generate_subdomains(self):
        words = self.gen.generate("example.com", scope="subdomains")
        assert len(words) > 0
        # Should contain common prefixes
        assert "dev" in words
        assert "staging" in words
        assert "api" in words

    def test_generate_passwords(self):
        words = self.gen.generate("mysite.com", scope="passwords")
        assert len(words) > 0
        # Should contain domain-based passwords
        assert any("mysite" in w for w in words)

    def test_tech_stack_dirs(self):
        words = self.gen.generate(
            "example.com",
            tech_stack=["WordPress"],
            scope="dirs",
        )
        assert any("wp-admin" in w for w in words)
        assert any("wp-content" in w for w in words)

    def test_tech_stack_laravel(self):
        words = self.gen.generate(
            "example.com",
            tech_stack=["Laravel"],
            scope="dirs",
        )
        assert any(".env" in w for w in words)

    def test_tech_stack_spring(self):
        words = self.gen.generate(
            "example.com",
            tech_stack=["Spring Boot"],
            scope="dirs",
        )
        assert any("actuator" in w for w in words)

    def test_from_subdomains(self):
        words = self.gen.generate(
            "example.com",
            subdomains=["api.example.com", "staging.example.com"],
            scope="dirs",
        )
        assert "api" in words
        assert "staging" in words

    def test_from_paths(self):
        words = self.gen.generate(
            "example.com",
            paths=["/api/v1/users"],
            scope="dirs",
        )
        assert "api" in words
        assert "users" in words

    def test_deduplication(self):
        words = self.gen.generate("example.com", scope="dirs")
        assert len(words) == len(set(words))

    def test_max_length_filter(self):
        words = self.gen.generate("example.com", scope="dirs")
        assert all(len(w) <= 100 for w in words)

    def test_generate_params(self):
        words = self.gen.generate(
            "example.com",
            tech_stack=["PHP"],
            scope="params",
        )
        assert "page" in words
        assert "file" in words

    def test_generate_from_pipeline(self):
        state = {
            "technologies": {
                "example.com": [{"name": "WordPress"}],
            },
            "subdomains": {
                "example.com": ["api.example.com"],
            },
            "discovered_api_paths": {
                "example.com": ["/api/v1"],
            },
        }
        words = self.gen.generate_from_pipeline("example.com", state, scope="dirs")
        assert len(words) > 0
        assert "api" in words

    def test_crawled_words(self):
        words = self.gen.generate(
            "example.com",
            crawled_words=["dashboard", "settings", "profile"],
            scope="dirs",
        )
        assert "dashboard" in words
        assert "settings" in words
        assert "profile" in words
