# Basilisk

Professional modular security audit framework for domain reconnaissance, analysis, and pentesting.

175 auto-discovered plugins across 10 categories. Two execution modes: classic sequential pipeline and **autonomous state-driven engine** with knowledge graph. Async execution with real-time HTML/JSON reports. TUI dashboard. SQLite storage for large-scale scans.

## Quick Start

```bash
# Install
uv sync && uv pip install -e ".[dev]"

# Full audit (classic pipeline)
basilisk audit example.com

# Autonomous mode (v3.0) — inspects, plans, executes, repeats
basilisk audit example.com --autonomous --max-steps 50

# Single plugin
basilisk run ssl_check example.com

# TUI dashboard
basilisk audit example.com --tui

# List plugins
basilisk plugins
```

## Features

- **175 plugins** in 10 categories, auto-discovered at startup
- **Autonomous engine (v3.0)** — knowledge graph-driven loop: find gaps, match capabilities, score, execute, learn, repeat
- **Classic pipeline** — sequential recon, scanning, analysis, pentesting phases
- **Knowledge graph** — typed entities with deterministic IDs, confidence merging, relation indexes, SQLite persistence
- **Live HTML reports** with auto-refresh during scan, static when complete
- **Fluent API** for programmatic use
- **TUI dashboard** (Textual) with phase progress, finding feed, stats
- **SQLite WAL storage** — handles millions of records
- **Multi-provider aggregation** (all / first / fastest strategies)
- **Rate limiting** — global + per-host token bucket
- **Plugin dependency resolution** via topological sort (Kahn's algorithm)
- **YAML config** with form-based auth, scan paths, custom wordlists

## Autonomous Mode (v3.0)

The autonomous engine replaces the fixed pipeline with a state-driven loop:

1. **Inspect** — examine the knowledge graph for missing information
2. **Plan** — identify knowledge gaps (host without services, HTTP without tech, endpoints without testing, etc.)
3. **Match** — find capabilities that can fill each gap
4. **Score** — rank candidates by `(novelty * knowledge_gain) / (cost + noise + repetition_penalty)`
5. **Execute** — run a batch of plugins concurrently
6. **Learn** — convert results to observations, merge into knowledge graph
7. **Repeat** — until no gaps remain or limits are reached

```bash
# Autonomous audit with step limit
basilisk audit example.com --autonomous --max-steps 100

# Programmatic
from basilisk.core.facade import Audit
state = await Audit("example.com").autonomous(max_steps=50).run()
```

### Knowledge Graph Entities

| Entity | Description | Example |
|--------|-------------|---------|
| Host | Domain or IP | `example.com`, `192.168.1.1` |
| Service | Port + protocol | `443/https`, `22/ssh` |
| Endpoint | URL path | `/api/v1/users` |
| Technology | Software + version | `nginx/1.24`, `jQuery/3.6.0` |
| Credential | Username + password | `admin:admin123` |
| Finding | Security issue | `Missing HSTS header` |
| Vulnerability | Known CVE | `CVE-2023-1234` |

## Plugin Categories

| Category | Count | Examples |
|----------|-------|---------|
| **Recon** | 23 | dns_enum, subdomain_crtsh, whois, web_crawler, email_harvest, github_dorking |
| **Scanning** | 16 | port_scan, ssl_check, tls_cipher_scan, cors_scan, graphql_detect |
| **Analysis** | 21 | http_headers, tech_detect, waf_detect, csp_analyzer, js_secret_scan |
| **Pentesting** | 55 | sqli_basic, xss_basic, ssrf_check, ssti_check, command_injection, xxe_check, jwt_attack |
| **Exploitation** | 18 | cors_exploit, graphql_exploit, nosqli_verify, ssrf_advanced |
| **Crypto** | 8 | hash_crack, padding_oracle, weak_random |
| **Lateral** | 12 | service_brute, ssh_brute, credential_spray |
| **Privesc** | 7 | suid_finder, kernel_suggest |
| **Post-exploit** | 7 | data_exfil, persistence_check |
| **Forensics** | 6 | log_analyzer, memory_dump |

## Usage

### Full Audit

```bash
# Basic audit (all 4 phases)
basilisk audit example.com

# Autonomous mode
basilisk audit example.com --autonomous --max-steps 50

# With custom config
basilisk audit example.com --config config/target.yaml -v

# Specific phases only
basilisk audit example.com --phases scanning,analysis

# Whitelist/exclude plugins
basilisk audit example.com --plugins ssl_check,http_headers
basilisk audit example.com --exclude subdomain_bruteforce,dir_brute

# Custom wordlists
basilisk audit example.com --wordlist common,big

# Skip cache
basilisk audit example.com --no-cache
```

### Single Plugin

```bash
basilisk run ssl_check example.com -v
basilisk run port_scan 192.168.1.1
basilisk run sqli_basic target.local:8080 -v
```

### Programmatic (Fluent API)

```python
from basilisk.core.facade import Audit

# Classic pipeline
state = await Audit("example.com").discover().scan().analyze().pentest().run()

# Autonomous mode
state = await Audit("example.com").autonomous(max_steps=50).run()

# Single plugin
results = await Audit.run_plugin("ssl_check", ["example.com"])
```

### Config File

```yaml
# config/target.yaml
auth:
  strategy: form
  login_url: /login
  username: admin
  password: admin123

scan_paths:
  - /api/v1/users
  - /api/v2/notes
  - /admin

rate_limit:
  requests_per_second: 50

http:
  timeout: 15
```

## Architecture

```
basilisk/
├── cli.py                 # Typer CLI
├── config.py              # Pydantic Settings + YAML
├── models/                # Pydantic v2 contracts (Target, Finding, PluginResult)
├── core/                  # Engine: pipeline, executor, registry, auth, facade
├── knowledge/             # [v3] Knowledge graph: entities, relations, store
├── observations/          # [v3] PluginResult → Observation adapter
├── capabilities/          # [v3] Plugin capability mapping (175 plugins)
├── scoring/               # [v3] Priority scoring engine
├── orchestrator/          # [v3] Autonomous loop: planner, selector, executor
├── events/                # [v3] Async event bus
├── utils/                 # HTTP client, DNS, rate limiter, payloads, WAF bypass
├── storage/               # SQLite WAL (async, bulk ops)
├── tui/                   # Textual dashboard (5 screens, 4 widgets)
├── reporting/             # HTML/JSON/CSV renderers, live reports
└── plugins/               # 175 plugins (auto-discovered)
    ├── recon/        (23)
    ├── scanning/     (16)
    ├── analysis/     (21)
    ├── pentesting/   (55)
    ├── exploitation/ (18)
    ├── crypto/        (8)
    ├── lateral/      (12)
    ├── privesc/       (7)
    ├── post_exploit/  (7)
    └── forensics/     (6)
```

## Writing Plugins

```python
from __future__ import annotations
from typing import ClassVar
from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

class MyPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="my_plugin",
        display_name="My Plugin",
        category=PluginCategory.PENTESTING,
        description="What it does",
        produces=["my_data"],
        timeout=30.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        findings = []
        async with ctx.rate:
            resp = await ctx.http.get(f"https://{target.host}/")
        # ... analysis logic ...
        return PluginResult.success(self.meta.name, target.host, findings=findings)
```

Drop the file into `basilisk/plugins/<category>/` and it will be auto-discovered.

## Signature Databases

| Database | Count | Comparable to |
|----------|-------|---------------|
| Tech fingerprints | 594 | Wappalyzer top-500 |
| CVE version checks | 200+ | retire.js |
| WAF signatures | 125 | wafw00f |
| CMS signatures | 83 | WPScan/CMSmap |
| Subdomain takeover | 80 | can-i-take-over-xyz |
| Favicon hashes | 300+ | Shodan |
| SQLi payloads | 489 | sqlmap (~30%) |
| XSS payloads | 35+ basic, 49 DOM sinks | XSStrike/Dalfox |
| SSTI probes | 32 math + 48 fingerprints | tplmap |
| Command injection | 90 | commix |

## Stack

- **Python 3.12+**
- **Pydantic v2** — data models and validation
- **aiohttp** — async HTTP with connection pooling
- **aiosqlite** — async SQLite (WAL mode)
- **dnspython** — async DNS resolution
- **Textual** — TUI dashboard
- **Typer + Rich** — CLI
- **Jinja2** — HTML report templates
- **cryptography** — SSL certificate parsing

## Development

```bash
# Run tests (1382 tests)
pytest tests/ -v

# Quick check (stop on first failure)
pytest tests/ -x --tb=short

# Lint
ruff check basilisk/ tests/

# Plugin tests only
pytest tests/test_plugins/ -v
```

## License

MIT
