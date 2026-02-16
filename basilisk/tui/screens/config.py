"""Config screen — configure plugins, ports, wordlists for the audit."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import (
    Button,
    Checkbox,
    Footer,
    Header,
    Input,
    Label,
    Select,
)

PLUGIN_PRESETS = {
    "recon": [
        ("dns_enum", "DNS Enumeration", True),
        ("subdomain_crtsh", "Subdomains (crt.sh)", True),
        ("subdomain_hackertarget", "Subdomains (HackerTarget)", True),
        ("subdomain_rapiddns", "Subdomains (RapidDNS)", True),
        ("subdomain_bruteforce", "Subdomains (Bruteforce)", False),
        ("reverse_ip", "Reverse IP Lookup", True),
        ("whois", "WHOIS", True),
    ],
    "scanning": [
        ("port_scan", "Port Scan", True),
        ("ssl_check", "SSL/TLS Check", True),
        ("ssl_protocols", "SSL Protocols & Ciphers", True),
        ("ssl_vulns", "SSL Vulnerabilities", True),
        ("ssl_compliance", "TLS Compliance", True),
        ("service_detect", "Service Detection", True),
    ],
    "analysis": [
        ("http_headers", "HTTP Security Headers", True),
        ("tech_detect", "Technology Detection", True),
        ("takeover_check", "Subdomain Takeover", True),
    ],
    "pentesting": [
        ("dir_brute", "Directory Bruteforce", False),
        ("git_exposure", "Git/Env Exposure", True),
        ("backup_finder", "Backup Files", True),
        ("ftp_anon", "Anonymous FTP", True),
        ("misconfig", "Misconfigurations", True),
    ],
}


class ConfigScreen(Screen):
    """Plugin and method configuration screen."""

    BINDINGS = [
        ("a", "select_all", "Select All"),
        ("n", "select_none", "Deselect All"),
        ("escape", "app.pop_screen", "Back"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with Container():
            yield Label("[bold]Audit Configuration[/bold]", id="config-title")

            with Horizontal():
                with VerticalScroll(id="plugins-panel"):
                    for category, plugins in PLUGIN_PRESETS.items():
                        yield Label(
                            f"[bold]{category.upper()}[/bold]",
                            classes="category-header",
                        )
                        for plugin_name, display_name, default in plugins:
                            yield Checkbox(
                                display_name,
                                value=default,
                                id=f"plugin-{plugin_name}",
                            )

                with VerticalScroll(id="settings-panel"):
                    yield Label("[bold]Settings[/bold]", classes="category-header")

                    yield Label("Ports to scan:")
                    yield Input(
                        value="21,22,25,80,443,3306,5432,8080,8443",
                        id="ports-input",
                    )

                    yield Label("Max concurrency:")
                    yield Input(value="50", id="concurrency-input")

                    yield Label("Timeout (seconds):")
                    yield Input(value="30", id="timeout-input")

                    yield Label("Rate limit (req/sec):")
                    yield Input(value="20", id="rate-limit-input")

                    yield Label("Wordlist:")
                    yield Select(
                        [
                            ("Common dirs (250)", "dirs_common"),
                            ("Medium dirs (5000)", "dirs_medium"),
                            ("Sensitive files", "files_common"),
                            ("API endpoints (280)", "api_endpoints"),
                            ("Dirs + API (all)", "dirs_common,api_endpoints"),
                        ],
                        value="dirs_common",
                        id="wordlist-select",
                        allow_blank=False,
                    )

            with Horizontal(id="config-actions"):
                yield Button("Save & Back", id="save-config-btn", variant="primary")
                yield Button("Reset Defaults", id="reset-config-btn", variant="warning")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save-config-btn":
            self.notify("Configuration saved")
            self.app.pop_screen()
        elif event.button.id == "reset-config-btn":
            self._reset_defaults()

    def _reset_defaults(self) -> None:
        for _category, plugins in PLUGIN_PRESETS.items():
            for plugin_name, _, default in plugins:
                cb = self.query_one(f"#plugin-{plugin_name}", Checkbox)
                cb.value = default
        self.query_one("#ports-input", Input).value = "21,22,25,80,443,3306,5432,8080,8443"
        self.query_one("#concurrency-input", Input).value = "50"
        self.query_one("#timeout-input", Input).value = "30"
        self.query_one("#rate-limit-input", Input).value = "20"
        self.notify("Reset to defaults")

    def action_select_all(self) -> None:
        for cb in self.query(Checkbox):
            cb.value = True

    def action_select_none(self) -> None:
        for cb in self.query(Checkbox):
            cb.value = False

    def get_config(self) -> dict:
        """Return current configuration as a dictionary."""
        enabled_plugins = []
        for _category, plugins in PLUGIN_PRESETS.items():
            for plugin_name, _, _ in plugins:
                cb = self.query_one(f"#plugin-{plugin_name}", Checkbox)
                if cb.value:
                    enabled_plugins.append(plugin_name)

        ports_str = self.query_one("#ports-input", Input).value
        ports = [int(p.strip()) for p in ports_str.split(",") if p.strip().isdigit()]

        return {
            "plugins": enabled_plugins,
            "ports": ports,
            "max_concurrency": int(self.query_one("#concurrency-input", Input).value or 50),
            "timeout": float(self.query_one("#timeout-input", Input).value or 30),
            "rate_limit": float(self.query_one("#rate-limit-input", Input).value or 20),
            "wordlist": self.query_one("#wordlist-select", Select).value,
        }
