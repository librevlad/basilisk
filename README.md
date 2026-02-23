# Basilisk

Professional modular security framework for autonomous reconnaissance, analysis, and pentesting.

178 auto-discovered plugins across 10 categories. Two execution modes: **autonomous state-driven engine** with knowledge graph and deterministic decision traces, and classic sequential pipeline. Async execution, real-time HTML reports, TUI dashboard, SQLite storage.

## Quick Start

```bash
# Install
uv sync && uv pip install -e ".[dev]"

# Autonomous audit (primary mode)
basilisk auto example.com
basilisk auto example.com --max-steps 50

# Classic pipeline
basilisk audit example.com

# Single plugin
basilisk run ssl_check example.com

# TUI dashboard
basilisk tui

# List plugins
basilisk plugins
```

## Two Execution Modes

### Autonomous Mode (Primary)

The autonomous engine builds a **knowledge graph** about the target and iteratively discovers
knowledge gaps, selects optimal plugins to fill them, executes them, and merges results back
into the graph. Each decision is recorded with full context for reproducibility.

```
Targets --> SEED --> [PLANNER] --> [SELECTOR] --> [SCORER] --> [DECISION]
                        |                                        |
                        |         [APPLY to KG] <-- [OBSERVE] <-- [EXECUTE]
                        |              |
                        '--------------'
```

**Cycle:** find gaps -> match capabilities -> score -> decide -> execute -> observe -> merge -> repeat

**Terminates when:**
- `no_gaps` — all knowledge gaps filled (audit complete)
- `limit_reached` — max_steps or max_duration exceeded
- `no_capabilities` — remaining gaps can't be filled by available plugins
- `no_candidates` — all candidates already executed or on cooldown

```bash
basilisk auto example.com --max-steps 100
```

```python
from basilisk.core.facade import Audit
results = await Audit("example.com").autonomous(max_steps=50).run()
```

### Classic Pipeline

Sequential execution through phases with topological sorting (Kahn's algorithm) for
dependency resolution within each phase. Recon expands target scope automatically.

**Default phases (4):** `recon -> scanning -> analysis -> pentesting`
**Offensive phases (10):** + `exploitation, post_exploit, privesc, lateral, crypto, forensics`

```bash
basilisk audit example.com
basilisk audit example.com --phases scanning,analysis
```

```python
results = await Audit("example.com").discover().scan().analyze().pentest().run()
```

---

## Knowledge Graph

Central world model storing all information about audit targets. Typed entities (nodes) and
relations (edges) form a graph that grows with each autonomous cycle iteration.

### 7 Entity Types

| EntityType | Description | Key Fields | Factory |
|-----------|-------------|------------|---------|
| `HOST` | Domain or IP | `host` | `Entity.host("example.com")` |
| `SERVICE` | Port + protocol | `host`, `port`, `protocol` | `Entity.service("example.com", 443, "tcp")` |
| `ENDPOINT` | URL path | `host`, `path` | `Entity.endpoint("example.com", "/api/v1")` |
| `TECHNOLOGY` | Software + version | `host`, `name`, `version` | `Entity.technology("example.com", "nginx", "1.24")` |
| `CREDENTIAL` | Discovered creds | `host`, `username` | `Entity.credential("example.com", "admin")` |
| `FINDING` | Security issue | `host`, `title` | `Entity.finding("example.com", "Missing HSTS")` |
| `VULNERABILITY` | Known CVE | `host`, `name` | `Entity.vulnerability("example.com", "CVE-2024-1234")` |

### 7 Relation Types

| Relation | Direction | Meaning |
|----------|-----------|---------|
| `EXPOSES` | HOST -> SERVICE | Host exposes a network service |
| `RUNS` | SERVICE -> TECHNOLOGY | Service runs software |
| `HAS_ENDPOINT` | SERVICE -> ENDPOINT | Service has URL endpoint |
| `HAS_VULNERABILITY` | TECHNOLOGY -> VULNERABILITY | Software has known CVE |
| `ACCESSES` | CREDENTIAL -> HOST | Credential grants access |
| `RELATES_TO` | FINDING -> any | Finding relates to entity |
| `PARENT_OF` | HOST -> HOST | Domain is parent of subdomain |

### Deterministic IDs and Deduplication

Entity IDs are SHA256 hashes of key fields — identical inputs always produce the same ID.
When a plugin produces an entity with an existing ID, it's **merged** instead of duplicated:

```
confidence: 1 - (1 - old) * (1 - new)    # probabilistic OR
data:       new keys overwrite old
evidence:   union with dedup
```

### Persistence

Knowledge graph persists to SQLite via `KnowledgeStore` (tables: `kg_entities`, `kg_relations`).
Decision history persists to `decision_history.json`.

---

## Observation Bridge

Translates plugin outputs (`PluginResult`) into structured facts (`Observation`) that update
the knowledge graph. Plugins remain unchanged — the adapter handles conversion automatically.

| Plugin Data Key | Entity Created | Relation |
|----------------|---------------|----------|
| `open_ports` | SERVICE | HOST -> EXPOSES -> SERVICE |
| `services` | SERVICE | HOST -> EXPOSES -> SERVICE |
| `technologies` | TECHNOLOGY | HOST -> RUNS -> TECHNOLOGY |
| `subdomains` | HOST (subdomain) | HOST -> PARENT_OF -> HOST |
| `crawled_urls` / `found_paths` | ENDPOINT | HOST -> HAS_ENDPOINT -> ENDPOINT |
| `api_endpoints` | ENDPOINT (api) | HOST -> HAS_ENDPOINT -> ENDPOINT |
| `credentials` | CREDENTIAL | CREDENTIAL -> ACCESSES -> HOST |
| `findings` | FINDING | FINDING -> RELATES_TO -> HOST |

**Data flow:**
```
Plugin.run() -> PluginResult -> adapt_result() -> list[Observation]
    -> KnowledgeState.apply_observation() -> Entity/Relation in graph
```

---

## Capabilities and Scoring

### Capability Model

Each plugin maps to a `Capability` describing what it needs and what it produces:

```python
Capability(
    plugin_name="port_scan",
    requires_knowledge=["Host"],           # what must exist in graph
    produces_knowledge=["Service"],        # what it adds to graph
    cost_score=3.0,                        # 1-10, execution cost
    noise_score=5.0,                       # 1-10, detectability
)
```

138 plugins are explicitly mapped in `CAPABILITY_MAP`. The rest use auto-inference from `PluginMeta`.

### Scoring Formula

```
priority = (novelty * knowledge_gain + unlock_value + prior_bonus) / (cost + noise + repetition_penalty)
```

| Component | Formula | Purpose |
|-----------|---------|---------|
| `novelty` | `1 / (1 + (obs_count - 1) * 0.3)` | Prefer unexplored entities |
| `knowledge_gain` | `len(produces) * (1 - confidence)` | Prefer low-confidence targets |
| `unlock_value` | `unlockable_paths * 0.3` | Reward capabilities that open attack paths |
| `prior_bonus` | Campaign-aware (0.15 / tech_rate*0.2) | Reward known infrastructure |
| `cost` | capability.cost_score (campaign/tracker adjusted) | Penalize expensive plugins |
| `noise` | capability.noise_score | Penalize noisy plugins |
| `repetition_penalty` | Adaptive from History | Prevent repeat execution |

---

## Gap Detection (Planner)

The Planner examines the knowledge graph and identifies 12 types of knowledge gaps:

| # | Gap | Priority | Condition | Typical Plugins |
|---|-----|----------|-----------|-----------------|
| 1 | `services` | 10.0 | Host without services | port_scan |
| 2 | `dns` | 8.0 | Host without DNS records | dns_enum |
| 3 | `technology` | 7.0 | HTTP host without tech detection | tech_detect, waf_detect |
| 4 | `endpoints` | 6.0 | HTTP host without endpoints | web_crawler, dir_brute |
| 5 | `forms` | 5.5 | Endpoints without form analysis | form_analyzer |
| 6 | `vulnerability_testing` | 5.0 | Endpoints with params untested | sqli_check, xss_check |
| 7 | `host_vulnerability_testing` | 4.5 | HTTP host needs pentesting | git_exposure, jwt_attack |
| 8 | `service_exploitation` | 6.5 | Non-HTTP service untested | redis_exploit, ssh_brute |
| 9 | `credential_exploitation` | 7.5 | Credentials found | credential_spray |
| 10 | `version` | 4.0 | Technology without version | version_detect |
| 11 | `confirmation` | 3.0 | Low confidence entity (<0.5) | Any matching plugin |
| 12 | `attack_path` | path.risk | Attack path preconditions met | Path-specific actions |

---

## Decision Tracing

Every autonomous decision is recorded with full context for auditability and debugging.

**Pre-execution (before plugin runs):**
- Context snapshot (entity/relation/gap counts, elapsed time)
- All evaluated candidates with score breakdowns (max 20)
- Chosen plugin, target, score, and reasoning trace

**Post-execution (after plugin runs):**
- Observation count, new entity count, confidence delta, duration
- `was_productive` flag (new_entities > 0 or confidence_delta > 0.01)

Decisions persist to `decision_history.json`. The History module provides adaptive
repetition penalty — recently unproductive plugins are penalized more heavily.

---

## Safety Controls

```python
SafetyLimits(
    max_steps=100,                  # iteration limit
    max_duration_seconds=3600.0,    # 1 hour time limit
    batch_size=5,                   # plugins per iteration
    cooldown_per_capability=0.0,    # seconds between same capability
)
```

---

## Campaign Memory

Persistent cross-audit learning system. Remembers infrastructure, plugin effectiveness, and
technology stacks across audits. System is opt-in, disabled by default.

```bash
# Enable via CLI
basilisk auto example.com --campaign

# Enable via config
# campaign:
#   enabled: true
```

```python
# Enable via API
results = await Audit("example.com").autonomous().enable_campaign().run()
```

**What it learns:**
- **Target profiles** — services, technologies, endpoints, findings per host
- **Plugin efficacy** — per-plugin success rates with tech-stack breakdown
- **Tech fingerprints** — technology patterns per organization (base domain)

**How it helps:**
- Adjusts plugin cost based on historical success rate (discount proven plugins, penalize ineffective)
- Adds prior bonus for known infrastructure (skip redundant discovery)
- Data stored in `~/.basilisk/campaigns/campaign.db` (SQLite WAL)

---

## Plugin Categories

| Category | Count | Examples |
|----------|-------|---------|
| **Recon** | 23 | dns_enum, subdomain_crtsh, whois, web_crawler, email_harvest |
| **Scanning** | 16 | port_scan, ssl_check, tls_cipher_scan, cors_scan, graphql_detect |
| **Analysis** | 21 | http_headers, tech_detect, waf_detect, csp_analyzer, js_secret_scan |
| **Pentesting** | 57 | sqli_basic, xss_basic, ssrf_check, ssti_check, command_injection, xxe_check |
| **Exploitation** | 21 | cors_exploit, graphql_exploit, redis_exploit, sqli_extract |
| **Crypto** | 8 | hash_crack, padding_oracle, prng_crack, rsa_attack |
| **Lateral** | 12 | kerberoast, pass_the_hash, ntlm_relay, dcsync |
| **Privesc** | 7 | suid_exploit, kernel_exploit, sudo_exploit |
| **Post-exploit** | 7 | credential_harvest, network_enum, user_enum |
| **Forensics** | 6 | log_analyze, memory_analyze, pcap_analyze |

## CLI Reference

### `auto` — Autonomous audit (primary)

```bash
basilisk auto <target> [options]

Options:
  --max-steps, -n N       Max autonomous steps (default: 100)
  --campaign/--no-campaign  Enable persistent campaign memory
  --plugins LIST          Whitelist specific plugins
  --exclude, -x LIST      Exclude plugins by name or prefix
  --config PATH           YAML config file
  --wordlist, -w LIST     Wordlist names
  --project, -p NAME      Save to project
  --format LIST           Output formats: json,csv,html
  -v, --verbose           Debug logging
```

### `audit` — Classic pipeline

```bash
basilisk audit <target> [options]

Options:
  --phases LIST           Comma-separated phases (default: all)
  --plugins LIST          Whitelist specific plugins
  --exclude, -x LIST      Exclude plugins by name or prefix
  --config PATH           YAML config file
  --wordlist, -w LIST     Wordlist names
  --project, -p NAME      Save to project
  --tui                   Launch TUI dashboard
  --no-cache              Ignore cached results
  --format LIST           Output formats: json,csv,html
  -v, --verbose           Debug logging
```

### `run` — Single plugin

```bash
basilisk run <plugin_name> <target> [-v]
```

### `plugins` — List plugins

```bash
basilisk plugins [--category recon] [--provides subdomains]
```

### `htb` — HTB attack chain

```bash
basilisk htb <target_ip> [--mode full|web|ad|recon]
```

### `crack` — Hash cracking

```bash
basilisk crack <hash_value> [-w wordlist]
```

### `tui` — Interactive dashboard

```bash
basilisk tui
```

## Config File

```yaml
# config/target.yaml
auth:
  strategy: form
  login_url: /login
  username: admin
  password: admin123

scan_paths:
  - /api/v1/users
  - /admin

rate_limit:
  requests_per_second: 50

http:
  timeout: 15
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
        # ... analysis ...
        return PluginResult.success(self.meta.name, target.host, findings=findings)
```

Drop the file into `basilisk/plugins/<category>/` — auto-discovered at startup.

For autonomous mode integration, add a capability mapping in `capabilities/mapping.py`:
```python
"my_plugin": {
    "requires": ["Host", "Service:http"],
    "produces": ["Finding"],
    "cost": 3.0,
    "noise": 2.0,
},
```

## Architecture

```
basilisk/
├── cli.py                 # Typer CLI
├── config.py              # Pydantic Settings + YAML
├── models/                # Pydantic v2 contracts (Target, Finding, PluginResult)
├── core/                  # Engine: pipeline, executor, registry, auth, facade
├── knowledge/             # Knowledge graph: entities, relations, state, store
├── observations/          # PluginResult -> Observation adapter
├── capabilities/          # Plugin capability mapping (138 explicit + auto-inference)
├── scoring/               # Priority scoring engine (campaign-aware)
├── decisions/             # Decision model, context snapshots, evaluated options
├── memory/                # Decision history, adaptive repetition penalty
├── campaign/              # Persistent campaign memory (cross-audit learning)
├── orchestrator/          # Autonomous loop: planner, selector, executor, safety, attack paths
├── events/                # Event bus (9 event types, sync/async handlers)
├── data/                  # Fingerprint databases, data loader
├── utils/                 # HTTP client, DNS, rate limiter, payloads, WAF bypass
├── storage/               # SQLite WAL (async, bulk ops, migrations)
├── tui/                   # Textual dashboard (5 screens, 4 widgets)
├── reporting/             # HTML/JSON/CSV renderers, live reports, autonomous reports
└── plugins/               # 178 plugins (auto-discovered)
    ├── recon/        (23)
    ├── scanning/     (16)
    ├── analysis/     (21)
    ├── pentesting/   (57)
    ├── exploitation/ (21)
    ├── crypto/        (8)
    ├── lateral/      (12)
    ├── privesc/       (7)
    ├── post_exploit/  (7)
    └── forensics/     (6)
```

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
| NoSQLi payloads | 92 | — |
| JWT attacks | 95 | — |
| HTTP smuggling | 45 | — |
| Default credentials | 75 | — |

## Stack

- **Python 3.12+** target
- **Pydantic v2** — data models and validation
- **aiohttp** — async HTTP with connection pooling
- **aiosqlite** — async SQLite (WAL mode)
- **dnspython** — async DNS resolution
- **aiolimiter** — token bucket rate limiting
- **Textual** — TUI dashboard
- **Typer + Rich** — CLI
- **Jinja2** — HTML report templates
- **cryptography** — SSL certificate parsing
- **uv** — package manager
- **ruff** — linting (py312, line-length 100)
- **pytest + pytest-asyncio** — testing

## Development

```bash
# Run tests
.venv/Scripts/python.exe -m pytest tests/ -v

# Quick check (stop on first failure)
.venv/Scripts/python.exe -m pytest tests/ -x --tb=short

# Lint
.venv/Scripts/python.exe -m ruff check basilisk/ tests/

# Plugin tests only
.venv/Scripts/python.exe -m pytest tests/test_plugins/ -v
```

## License

MIT
