"""Tests for Settings configuration loading."""

from basilisk.config import (
    AuthSettings,
    BrowserSettings,
    CallbackSettings,
    DnsSettings,
    HttpSettings,
    RateLimitSettings,
    ScanSettings,
    Settings,
    StorageSettings,
)


class TestSettingsDefaults:
    def test_http_defaults(self):
        s = HttpSettings()
        assert s.timeout == 10.0
        assert s.user_agent == "Basilisk/2.0"
        assert s.verify_ssl is False

    def test_dns_defaults(self):
        s = DnsSettings()
        assert s.timeout == 5.0
        assert "8.8.8.8" in s.nameservers

    def test_scan_defaults(self):
        s = ScanSettings()
        assert 80 in s.default_ports
        assert 443 in s.default_ports
        assert s.max_concurrency == 50

    def test_rate_limit_defaults(self):
        s = RateLimitSettings()
        assert s.requests_per_second == 100.0
        assert s.burst == 20

    def test_storage_defaults(self):
        s = StorageSettings()
        assert s.wal_mode is True
        assert s.bulk_chunk_size == 1000

    def test_auth_defaults(self):
        s = AuthSettings()
        assert s.enabled is False
        # username may pick up env vars on some systems, just verify type
        assert isinstance(s.username, str)

    def test_browser_defaults(self):
        s = BrowserSettings()
        assert s.enabled is False

    def test_callback_defaults(self):
        s = CallbackSettings()
        assert s.enabled is False
        assert s.http_port == 8880

    def test_root_settings_defaults(self):
        s = Settings()
        assert isinstance(s.http, HttpSettings)
        assert isinstance(s.dns, DnsSettings)
        assert s.log_level == "INFO"


class TestSettingsLoad:
    def test_load_default(self):
        s = Settings.load()
        assert isinstance(s, Settings)

    def test_load_from_yaml(self, tmp_path):
        config_file = tmp_path / "test_config.yaml"
        config_file.write_text(
            "http:\n"
            "  timeout: 30.0\n"
            "  user_agent: TestAgent\n"
            "dns:\n"
            "  timeout: 10.0\n"
        )
        s = Settings.load(config_file)
        assert s.http.timeout == 30.0
        assert s.http.user_agent == "TestAgent"
        assert s.dns.timeout == 10.0

    def test_load_nonexistent_path(self, tmp_path):
        """Non-existent config should use defaults."""
        s = Settings.load(tmp_path / "nonexistent.yaml")
        assert isinstance(s, Settings)
        assert s.http.timeout == 10.0

    def test_load_empty_yaml(self, tmp_path):
        config_file = tmp_path / "empty.yaml"
        config_file.write_text("")
        s = Settings.load(config_file)
        assert isinstance(s, Settings)

    def test_load_string_path(self, tmp_path):
        config_file = tmp_path / "str_test.yaml"
        config_file.write_text("http:\n  timeout: 15.0\n")
        s = Settings.load(str(config_file))
        assert s.http.timeout == 15.0

    def test_load_partial_config(self, tmp_path):
        """Config with only some fields should merge with defaults."""
        config_file = tmp_path / "partial.yaml"
        config_file.write_text("rate_limit:\n  burst: 50\n")
        s = Settings.load(config_file)
        assert s.rate_limit.burst == 50
        assert s.rate_limit.requests_per_second == 100.0  # default
