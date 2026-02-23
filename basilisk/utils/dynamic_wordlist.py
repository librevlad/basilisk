"""Dynamic wordlist generator — context-aware wordlist from target intelligence.

Builds custom wordlists using:
1. Target domain/company name permutations
2. Detected technology stack (tech_detect pipeline data)
3. Discovered subdomains and paths (recon pipeline data)
4. Common year/season/date suffixes
5. CeWL-style word extraction from crawled pages
"""

from __future__ import annotations

import re
from itertools import product

# Season / temporal suffixes
SEASONS = ["spring", "summer", "fall", "autumn", "winter"]
MONTHS = [
    "jan", "feb", "mar", "apr", "may", "jun",
    "jul", "aug", "sep", "oct", "nov", "dec",
    "january", "february", "march", "april", "june",
    "july", "august", "september", "october", "november", "december",
]
YEARS = [str(y) for y in range(2020, 2027)]
COMMON_SUFFIXES = [
    "123", "1234", "12345", "!", "@", "#", "1", "01", "2024", "2025", "2026",
    "admin", "test", "dev", "staging", "prod", "backup", "old", "new",
    "temp", "tmp", "api", "v1", "v2", "internal", "secret",
]

# Common separators for compound words
SEPARATORS = ["", "-", "_", "."]

# Technology-specific paths/files
TECH_WORDLISTS: dict[str, list[str]] = {
    "wordpress": [
        "wp-admin", "wp-login.php", "wp-content", "wp-includes",
        "wp-json", "xmlrpc.php", "wp-config.php.bak", "wp-config.old",
        "wp-cron.php", "wp-mail.php", "wp-settings.php",
        "wp-content/debug.log", "wp-content/uploads",
        "wp-content/backup-db", "wp-content/plugins",
    ],
    "django": [
        "admin", "api", "static", "media", "accounts",
        "__debug__", "settings.py", "manage.py",
        "django-admin", "api-auth", "rest-auth",
        "graphql", "silk", "debug", "djdt",
    ],
    "laravel": [
        ".env", "storage", "public", "artisan",
        "telescope", "horizon", "nova", "api",
        "storage/logs/laravel.log", "bootstrap/cache",
        "vendor", "config/app.php", "routes/web.php",
    ],
    "spring": [
        "actuator", "actuator/health", "actuator/env",
        "actuator/beans", "actuator/mappings", "actuator/configprops",
        "actuator/heapdump", "actuator/threaddump",
        "swagger-ui.html", "v2/api-docs", "v3/api-docs",
        "api-docs", "h2-console", "jolokia",
    ],
    "express": [
        "api", "graphql", "health", "status", "metrics",
        "swagger", "docs", "admin", "debug",
        "package.json", "node_modules",
    ],
    "react": [
        "static/js", "asset-manifest.json", "manifest.json",
        "service-worker.js", "robots.txt", "sitemap.xml",
        "env.js", "config.js",
    ],
    "nginx": [
        "nginx.conf", "server-status", "nginx_status",
        ".htpasswd", ".htaccess", "conf.d",
    ],
    "apache": [
        "server-status", "server-info", ".htaccess",
        ".htpasswd", "httpd.conf", "apache2.conf",
    ],
    "php": [
        "phpinfo.php", "info.php", "php.ini", "composer.json",
        "composer.lock", "vendor/autoload.php",
        "adminer.php", "phpmyadmin",
    ],
    "aspnet": [
        "web.config", "appsettings.json", "elmah.axd",
        "trace.axd", "applicationhost.config",
        "bin", "App_Data", "aspnet_client",
    ],
    "ruby": [
        "Gemfile", "Gemfile.lock", "config.ru",
        "config/database.yml", "config/secrets.yml",
        "config/credentials.yml.enc", "config/master.key",
        "rails/info", "rails/mailers",
    ],
}


class DynamicWordlistGenerator:
    """Generates context-aware wordlists from target intelligence."""

    def __init__(self) -> None:
        self._cache: dict[str, list[str]] = {}

    def generate(
        self,
        domain: str,
        *,
        tech_stack: list[str] | None = None,
        subdomains: list[str] | None = None,
        crawled_words: list[str] | None = None,
        paths: list[str] | None = None,
        scope: str = "dirs",
    ) -> list[str]:
        """Generate a dynamic wordlist for the target.

        Args:
            domain: Target domain (e.g. "example.com")
            tech_stack: Detected technologies (from tech_detect)
            subdomains: Discovered subdomains
            crawled_words: Words extracted from crawled pages
            paths: Already discovered paths
            scope: "dirs" for directory brute, "params" for parameter fuzzing,
                   "subdomains" for subdomain brute, "passwords" for credential testing
        """
        words: list[str] = []

        if scope == "dirs":
            words.extend(self._domain_dirs(domain))
            words.extend(self._tech_dirs(tech_stack or []))
            words.extend(self._crawled_dirs(crawled_words or []))
        elif scope == "subdomains":
            words.extend(self._domain_subdomains(domain))
            words.extend(self._tech_subdomains(tech_stack or []))
        elif scope == "params":
            words.extend(self._tech_params(tech_stack or []))
            words.extend(self._crawled_params(crawled_words or []))
        elif scope == "passwords":
            words.extend(self._domain_passwords(domain))
            words.extend(self._temporal_passwords())

        # Add words derived from existing discoveries
        if subdomains:
            words.extend(self._from_subdomains(subdomains))
        if paths:
            words.extend(self._from_paths(paths))

        # Deduplicate preserving order
        seen: set[str] = set()
        unique: list[str] = []
        for w in words:
            w_clean = w.strip().lower()
            if w_clean and w_clean not in seen and len(w_clean) <= 100:
                seen.add(w_clean)
                unique.append(w_clean)

        return unique

    def generate_from_pipeline(self, domain: str, state: dict, scope: str = "dirs") -> list[str]:
        """Generate wordlist from pipeline state dict."""
        tech_stack = []
        tech_data = state.get("technologies", {}).get(domain, [])
        if isinstance(tech_data, list):
            tech_stack = [t.get("name", t) if isinstance(t, dict) else str(t) for t in tech_data]

        subdomains = state.get("subdomains", {}).get(domain, [])
        paths = state.get("discovered_api_paths", {}).get(domain, [])

        # Crawled words from web_crawler
        crawled_words = state.get("crawled_words", {}).get(domain, [])

        return self.generate(
            domain,
            tech_stack=tech_stack,
            subdomains=subdomains,
            crawled_words=crawled_words,
            paths=paths,
            scope=scope,
        )

    # --- Domain-based generators ---

    @staticmethod
    def _domain_dirs(domain: str) -> list[str]:
        """Generate directory candidates from domain name."""
        parts = _extract_domain_parts(domain)
        words: list[str] = []

        for part in parts:
            words.append(part)
            words.append(f"{part}-admin")
            words.append(f"{part}-api")
            words.append(f"{part}-dev")
            words.append(f"{part}-staging")
            words.append(f"{part}-internal")
            words.append(f"{part}-test")
            words.append(f"{part}-old")
            words.append(f"{part}-backup")
            words.append(f"api/{part}")
            words.append(f"v1/{part}")
            words.append(f"v2/{part}")

        return words

    @staticmethod
    def _domain_subdomains(domain: str) -> list[str]:
        """Generate subdomain candidates from domain name."""
        parts = _extract_domain_parts(domain)
        words: list[str] = []
        prefixes = [
            "dev", "staging", "test", "api", "admin", "internal",
            "mail", "vpn", "portal", "dashboard", "app", "beta",
            "pre", "uat", "qa", "demo", "sandbox", "cdn", "static",
            "assets", "media", "docs", "wiki", "git", "ci", "cd",
            "jenkins", "grafana", "prometheus", "kibana", "elastic",
            "redis", "mongo", "mysql", "postgres", "db",
        ]

        for part in parts:
            for prefix in prefixes:
                words.append(f"{prefix}-{part}")
                words.append(f"{part}-{prefix}")
            for year in YEARS[-3:]:
                words.append(f"{part}{year}")

        words.extend(prefixes)
        return words

    @staticmethod
    def _domain_passwords(domain: str) -> list[str]:
        """Generate password candidates from domain name."""
        parts = _extract_domain_parts(domain)
        words: list[str] = []

        for part in parts:
            words.append(part)
            words.append(part.capitalize())
            words.append(part.upper())
            for suffix in COMMON_SUFFIXES:
                words.append(f"{part}{suffix}")
                words.append(f"{part.capitalize()}{suffix}")
            for year in YEARS[-3:]:
                words.append(f"{part}{year}")
                words.append(f"{part.capitalize()}{year}")
                words.append(f"{part}{year}!")
            for season in SEASONS:
                words.append(f"{part}{season}")
                words.append(f"{season}{part}")

        return words

    @staticmethod
    def _temporal_passwords() -> list[str]:
        """Generate time-based password candidates."""
        words: list[str] = []
        bases = ["password", "pass", "admin", "welcome", "letmein", "changeme"]

        for base, year in product(bases, YEARS[-3:]):
            words.append(f"{base}{year}")
            words.append(f"{base.capitalize()}{year}")
            words.append(f"{base}{year}!")

        for base, season in product(bases, SEASONS):
            words.append(f"{season.capitalize()}{base}")
            words.append(f"{base}{season}")

        for base, month in product(bases, MONTHS[:12]):
            words.append(f"{month.capitalize()}{base}")

        return words

    # --- Tech-based generators ---

    @staticmethod
    def _tech_dirs(tech_stack: list[str]) -> list[str]:
        """Generate directory candidates from detected technologies."""
        words: list[str] = []
        for tech in tech_stack:
            tech_lower = tech.lower()
            for key, paths in TECH_WORDLISTS.items():
                if key in tech_lower:
                    words.extend(paths)
                    break
        return words

    @staticmethod
    def _tech_subdomains(tech_stack: list[str]) -> list[str]:
        """Generate subdomain candidates from detected technologies."""
        words: list[str] = []
        tech_subs = {
            "kubernetes": ["k8s", "kube", "cluster", "ingress", "istio"],
            "docker": ["docker", "registry", "container", "swarm"],
            "jenkins": ["jenkins", "ci", "build", "pipeline"],
            "grafana": ["grafana", "monitoring", "metrics", "dashboard"],
            "elasticsearch": ["elastic", "kibana", "logstash", "elk"],
            "redis": ["redis", "cache", "session"],
            "rabbitmq": ["rabbitmq", "mq", "queue", "amqp"],
        }
        for tech in tech_stack:
            tech_lower = tech.lower()
            for key, subs in tech_subs.items():
                if key in tech_lower:
                    words.extend(subs)
        return words

    @staticmethod
    def _tech_params(tech_stack: list[str]) -> list[str]:
        """Generate parameter candidates from detected technologies."""
        words: list[str] = []
        tech_params = {
            "php": ["page", "file", "include", "require", "path", "dir", "cmd"],
            "java": ["action", "class", "method", "bean", "spring", "type"],
            "aspnet": ["__VIEWSTATE", "__EVENTVALIDATION", "ReturnUrl", "handler"],
            "python": ["template", "render", "debug", "module", "class"],
            "node": ["callback", "jsonp", "redirect_uri", "next"],
        }
        for tech in tech_stack:
            tech_lower = tech.lower()
            for key, params in tech_params.items():
                if key in tech_lower:
                    words.extend(params)
        return words

    # --- Discovery-based generators ---

    @staticmethod
    def _from_subdomains(subdomains: list[str]) -> list[str]:
        """Extract useful words from discovered subdomains."""
        words: list[str] = []
        for sub in subdomains:
            # Extract first label (before first dot)
            label = sub.split(".")[0] if "." in sub else sub
            if len(label) > 2:
                words.append(label)
        return words

    @staticmethod
    def _from_paths(paths: list[str]) -> list[str]:
        """Generate new candidates from discovered paths."""
        words: list[str] = []
        for path in paths:
            segments = [s for s in path.strip("/").split("/") if s]
            for seg in segments:
                if len(seg) > 2 and not seg.startswith("{"):
                    words.append(seg)
                    # Try common variations
                    words.append(f"{seg}/v1")
                    words.append(f"{seg}/v2")
                    words.append(f"{seg}/admin")
        return words

    @staticmethod
    def _crawled_dirs(crawled_words: list[str]) -> list[str]:
        """Generate directory candidates from crawled page content."""
        words: list[str] = []
        for word in crawled_words:
            if 3 <= len(word) <= 30 and re.match(r'^[a-zA-Z][a-zA-Z0-9_-]*$', word):
                words.append(word.lower())
        return words

    @staticmethod
    def _crawled_params(crawled_words: list[str]) -> list[str]:
        """Generate parameter candidates from crawled page content."""
        words: list[str] = []
        for word in crawled_words:
            if 2 <= len(word) <= 30 and re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', word):
                words.append(word)
        return words


def _extract_domain_parts(domain: str) -> list[str]:
    """Extract meaningful parts from a domain name.

    Example: "api.example-corp.com" → ["api", "example", "corp", "example-corp"]
    """
    # Remove TLD
    parts_raw = domain.split(".")
    if len(parts_raw) > 1:
        parts_raw = parts_raw[:-1]  # Remove TLD (.com, .org, etc.)
    if len(parts_raw) > 1 and parts_raw[-1] in ("co", "com", "org", "net", "edu", "gov"):
        parts_raw = parts_raw[:-1]  # Remove second-level TLD (.co.uk)

    parts: list[str] = []
    for raw in parts_raw:
        parts.append(raw)
        # Split on hyphens and underscores
        for sub in re.split(r'[-_]', raw):
            if sub and sub != raw and len(sub) > 1:
                parts.append(sub)

    return list(dict.fromkeys(parts))  # Dedupe preserving order
