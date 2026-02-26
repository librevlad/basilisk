# Basilisk

Professional modular security framework for autonomous reconnaissance, analysis, and pentesting.

188 auto-discovered plugins across 10 categories, all wrapped as v4 Scenarios. Unified autonomous engine with knowledge graph, deterministic decision traces, cognitive reasoning, and persistent campaign memory. Training validation benchmarked against 18 vulnerable containers with **68.9% average coverage**.

## Quick Start

```bash
# Install
uv sync && uv pip install -e ".[dev]"

# Autonomous audit (primary mode)
basilisk auto example.com
basilisk auto example.com -n 50              # limit steps
basilisk auto example.com --campaign          # with cross-audit memory

# Single plugin
basilisk run ssl_check example.com

# List plugins / scenarios
basilisk plugins
basilisk scenarios                            # all scenarios (native + legacy)
basilisk scenarios --native                   # only native v4 scenarios

# Training validation
basilisk train training_profiles/dvwa.yaml    # benchmark against known targets

# Hash identification + crack
basilisk crack <hash>
```

## Architecture Overview

```
CLI (cli.py) / Basilisk class (__init__.py)
    |
Engine (engine/autonomous/runner.py)
    |  ScenarioRegistry + ScenarioExecutor (v4 active path)
Orchestrator (loop, planner, selector, scorer)
    |
Scenarios (5 native + 188 legacy-wrapped via bridge/)
    |  depend on ActorProtocol
Actor (CompositeActor, HttpActor, RecordingActor)
    |
Knowledge Graph + Verification + Cognitive Reasoning + KG Persistence
```

## Autonomous Engine

The autonomous engine builds a **knowledge graph** about the target and iteratively discovers
knowledge gaps, selects optimal plugins to fill them, executes them, and merges results back
into the graph. Each decision is recorded with full context for reproducibility.

```
Targets --> SEED --> [PLANNER] --> [SELECTOR] --> [SCORER] --> [DECISION]
                       |                                        |
                       |        [APPLY to KG] <-- [OBSERVE] <-- [EXECUTE]
                       |              |
                       |    [HYPOTHESIZE] --> [REVISE BELIEFS]
                       |              |
                       '--------------'
```

**Cycle:** find gaps -> match capabilities -> score -> decide -> execute -> observe -> merge -> hypothesize -> revise beliefs -> repeat

**Terminates when:**
- `no_gaps` — all knowledge gaps filled (audit complete)
- `limit_reached` — max_steps or max_duration exceeded
- `no_capabilities` — remaining gaps can't be filled by available plugins
- `no_candidates` — all candidates already executed or on cooldown

---

## Knowledge Graph

Central world model storing all information about audit targets. 9 typed entity types and
11 relation types form a graph that grows with each autonomous cycle iteration.

### 9 Entity Types

| EntityType | Description | Key Fields | Factory |
|-----------|-------------|------------|---------|
| `HOST` | Domain or IP | `host` | `Entity.host("example.com")` |
| `SERVICE` | Port + protocol | `host`, `port`, `protocol` | `Entity.service("example.com", 443, "tcp")` |
| `ENDPOINT` | URL path | `host`, `path` | `Entity.endpoint("example.com", "/api/v1")` |
| `TECHNOLOGY` | Software + version | `host`, `name`, `version` | `Entity.technology("example.com", "nginx", "1.24")` |
| `CREDENTIAL` | Discovered creds | `host`, `username` | `Entity.credential("example.com", "admin")` |
| `FINDING` | Security issue | `host`, `title` | `Entity.finding("example.com", "Missing HSTS")` |
| `VULNERABILITY` | Known CVE | `host`, `name` | `Entity.vulnerability("example.com", "CVE-2024-1234")` |
| `CONTAINER` | Docker/K8s container | `host`, `container_id` | `Entity.container("example.com", "abc123")` |
| `IMAGE` | Container image | `host`, `image_name`, `image_tag` | `Entity.image("example.com", "nginx", "1.24")` |

### 11 Relation Types

| Relation | Direction | Meaning |
|----------|-----------|---------|
| `EXPOSES` | HOST -> SERVICE | Host exposes a network service |
| `RUNS` | SERVICE -> TECHNOLOGY | Service runs software |
| `HAS_ENDPOINT` | SERVICE -> ENDPOINT | Service has URL endpoint |
| `HAS_VULNERABILITY` | TECHNOLOGY -> VULNERABILITY | Software has known CVE |
| `ACCESSES` | CREDENTIAL -> HOST | Credential grants access |
| `RELATES_TO` | FINDING -> any | Finding relates to entity |
| `PARENT_OF` | HOST -> HOST | Domain is parent of subdomain |
| `RUNS_CONTAINER` | TECHNOLOGY -> CONTAINER | Runtime runs container |
| `USES_IMAGE` | CONTAINER -> IMAGE | Container uses image |
| `SUPPORTED_BY` | ENTITY -> HYPOTHESIS | Evidence supports hypothesis |
| `DISPROVED_BY` | ENTITY -> HYPOTHESIS | Evidence contradicts hypothesis |

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

## Gap Detection (Planner)

The Planner examines the knowledge graph and identifies 18 types of knowledge gaps:

| # | Gap | Priority | Condition |
|---|-----|----------|-----------|
| 1 | `services` | 10.0 | Host without services |
| 2 | `dns` | 8.0 | Host without DNS records |
| 3 | `technology` | 7.0 | HTTP host without tech detection |
| 4 | `endpoints` | 6.0 | HTTP host without endpoints |
| 5 | `forms` | 5.5 | Endpoints without form analysis |
| 6 | `vulnerability_testing` | 5.0 | Endpoints with params untested |
| 7 | `host_vulnerability_testing` | 4.5 | HTTP host needs pentesting |
| 8 | `service_exploitation` | 6.5 | Non-HTTP service untested |
| 9 | `credential_exploitation` | 7.5 | Credentials found, not exploited |
| 10 | `version` | 4.0 | Technology without version |
| 11 | `confirmation` | 3.0 | Low confidence entity (<0.5) |
| 12 | `finding_verification` | 6.0 | HIGH/CRITICAL finding, confidence < 0.95 |
| 13 | `container_runtime` | 6.0 | Host with Docker/K8s ports |
| 14 | `container_enumeration` | 7.0 | Container runtime without enumeration |
| 15 | `container_config_audit` | 5.5 | Container without config audit |
| 16 | `image_analysis` | 5.0 | Image without vulnerability check |
| 17 | `attack_path` | path.risk | Attack path preconditions met |
| 18 | `hypothesis_validation` | 5.5 | Active hypothesis with uncertain confidence |

---

## Capabilities and Scoring

### Capability Model

Each plugin maps to a `Capability` with 4 action types:

| ActionType | Categories | Purpose |
|------------|-----------|---------|
| `ENUMERATION` | recon, scanning | Discover new entities |
| `EXPERIMENT` | analysis, pentesting | Test hypotheses |
| `EXPLOIT` | exploitation, lateral, privesc | Needs confirmed vulnerability |
| `VERIFICATION` | any with `reduces_uncertainty` | Re-test to confirm/reject findings |

145 plugins explicitly mapped in `CAPABILITY_MAP`. The rest use auto-inference from `PluginMeta`/`ScenarioMeta`.

### Scoring Formula

```
priority = (novelty * knowledge_gain * success_prob + unlock_value + prior_bonus
            + hypothesis_gain + action_type_bonus) * gap_boost
           / (cost + noise + repetition_penalty)
```

| Component | Purpose |
|-----------|---------|
| `novelty` | Prefer unexplored entities |
| `knowledge_gain` | Prefer low-confidence targets |
| `success_prob` | Goal-based success probability |
| `unlock_value` | Reward capabilities opening attack paths |
| `prior_bonus` | Campaign-aware known infrastructure bonus |
| `hypothesis_gain` | Reward plugins that resolve hypotheses |
| `action_type_bonus` | Context-dependent action preference |
| `gap_boost` | Multiplier from gap priority |
| `cost` | Penalize expensive plugins (campaign/tracker adjusted) |
| `noise` | Penalize noisy/detectable plugins |
| `repetition_penalty` | Adaptive penalty from decision history |

---

## Cognitive Reasoning

Deterministic reasoning primitives over the knowledge graph. No AI/LLM — pure pattern logic.

### Hypothesis Engine

Generates testable hypotheses from 5 pattern detectors:

| Detector | Trigger | Hypothesis |
|----------|---------|-----------|
| Shared Stack | Same tech on 2+ hosts | Organization standardizes on X |
| Service Identity | Non-standard port without tech | Port N likely runs X |
| Systematic Vuln | 3+ findings of same type | Systematic vulnerability in category X |
| Unverified Finding | HIGH/CRITICAL, confidence < 0.7 | Vulnerability may exist in X |
| Framework Pattern | Endpoint paths match known framework | Target uses WordPress/Laravel/etc |

### Evidence Aggregator

Belief revision based on source-family independence (6 families: dns, network_scan, http_probe, exploit, config_leak, verification).

- Evidence from 2+ independent source families → independence bonus (+0.05 per family, max +0.15)
- Contradicting evidence → penalty (-0.1)
- Per-step belief revision with confidence clamped to [0.1, 1.0]

---

## Container Security Audit

Integrated subsystem for auditing Docker/K8s infrastructure. Automatically detects container
runtimes, enumerates containers and images, audits configurations, and probes escape vectors.

```
HOST --[EXPOSES]--> SERVICE(:2375)
  \--[RUNS]--> Technology(docker, is_container_runtime=True)
                  \--[RUNS_CONTAINER]--> CONTAINER(abc123, privileged=True)
                                            \--[USES_IMAGE]--> IMAGE(nginx:1.24)
```

7 plugins: `container_discovery` -> `container_enumeration` -> `registry_lookup` -> `image_fingerprint` -> `container_config_audit` -> `container_escape_probe` -> `container_verification`

---

## Training Validation

Benchmarking system for measuring detection coverage against known vulnerable targets. Each
training profile defines a target, Docker compose configuration, authentication, scan paths,
and expected findings.

```bash
basilisk train training_profiles/dvwa.yaml              # run against DVWA
basilisk train training_profiles/juice_shop.yaml        # run against Juice Shop
```

### Benchmark Results (18 containers)

| # | Target | Coverage | Verified | Category |
|---|--------|----------|----------|----------|
| 1 | XVWA | 95.2% (20/21) | 55.0% | PHP vulns |
| 2 | WackoPicko | 93.8% (15/16) | 46.7% | Classic web |
| 3 | DSVW | 90.9% (20/22) | 80.0% | Python vulns |
| 4 | DVWA | 87.5% (14/16) | 28.6% | PHP vulns |
| 5 | bWAPP | 87.5% (35/40) | 68.6% | PHP vulns |
| 6 | VAmPi | 87.5% (7/8) | 0.0% | REST API |
| 7 | Hackazon | 85.7% (12/14) | 25.0% | E-commerce |
| 8 | Mutillidae | 83.3% (25/30) | 56.0% | OWASP Top 10 |
| 9 | Juice Shop | 82.8% (24/29) | 8.3% | Modern JS app |
| 10 | vAPI | 80.0% (8/10) | 0.0% | REST API |
| 11 | Gruyere | 69.2% (9/13) | 22.2% | Python app |
| 12 | NodeGoat | 66.7% (6/9) | 33.3% | Node.js |
| 13 | DVGA | 66.7% (12/18) | 16.7% | GraphQL |
| 14 | BadStore | 63.2% (12/19) | 33.3% | Classic web |
| 15 | Altoro Mutual | 56.2% (9/16) | 33.3% | Banking app |
| 16 | crAPI | 33.3% (4/12) | 0.0% | Microservices API |
| 17 | WebGoat | 23.1% (3/13) | 0.0% | Lesson-based |
| 18 | RailsGoat | 22.2% (2/9) | 0.0% | Ruby on Rails |

**Average coverage: 68.9%** across 18 vulnerable applications.

---

## Decision Tracing

Every autonomous decision is recorded with full context for auditability and debugging.

**Pre-execution (before plugin runs):**
- Context snapshot (entity/relation/gap counts, active hypotheses)
- All evaluated candidates with score breakdowns (max 20)
- Chosen plugin, target, score, reasoning trace, action type
- Related hypothesis IDs and resolution gain

**Post-execution (after plugin runs):**
- Observation count, new entity count, confidence delta, duration
- `was_productive` flag (new_entities > 0 or confidence_delta > 0.01)

14 event types: ENTITY_CREATED, ENTITY_UPDATED, OBSERVATION_APPLIED, PLUGIN_STARTED, PLUGIN_FINISHED, GAP_DETECTED, STEP_COMPLETED, DECISION_MADE, GOAL_ADVANCED, AUDIT_COMPLETED, BELIEF_STRENGTHENED, BELIEF_WEAKENED, HYPOTHESIS_CONFIRMED, HYPOTHESIS_REJECTED.

---

## Campaign Memory

Persistent cross-audit learning. Remembers infrastructure, plugin effectiveness, and
technology stacks across audits. Opt-in, disabled by default.

```bash
basilisk auto example.com --campaign
```

**What it learns:**
- **Target profiles** — services, technologies, endpoints, findings per host
- **Plugin efficacy** — per-plugin success rates with tech-stack breakdown
- **Tech fingerprints** — technology patterns per organization (base domain)

**How it helps:**
- Adjusts plugin cost based on historical success rate
- Adds prior bonus for known infrastructure
- Data stored in `~/.basilisk/campaigns/campaign.db` (SQLite WAL)

---

## Plugin System

### 188 Plugins (10 categories)

| Category | Count | Examples |
|----------|-------|---------|
| **Recon** | 23 | dns_enum, subdomain_crtsh, whois, web_crawler, email_harvest |
| **Scanning** | 19 | port_scan, ssl_check, cors_scan, graphql_detect, container_discovery |
| **Analysis** | 23 | http_headers, tech_detect, waf_detect, csp_analyzer, image_fingerprint |
| **Pentesting** | 60 | sqli_basic, xss_basic, ssrf_check, ssti_check, command_injection, xxe_check |
| **Exploitation** | 23 | cors_exploit, graphql_exploit, redis_exploit, container_escape_probe |
| **Crypto** | 8 | hash_crack, padding_oracle, prng_crack, rsa_attack |
| **Lateral** | 12 | kerberoast, pass_the_hash, ntlm_relay, credential_spray |
| **Privesc** | 7 | suid_exploit, kernel_exploit, sudo_exploit |
| **Post-exploit** | 7 | credential_harvest, network_enum, user_enum |
| **Forensics** | 6 | log_analyze, memory_analyze, pcap_analyze |

All 188 plugins are automatically wrapped as v4 Scenarios via `bridge/legacy_scenario.py`. 5 native v4 scenarios in `scenarios/`.

### Writing a Plugin

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

Drop into `basilisk/plugins/<category>/` — auto-discovered at startup.

---

## Signature Databases

| Database | Count | Comparable to |
|----------|-------|---------------|
| Tech fingerprints | 594 | Wappalyzer top-500 |
| CVE version checks | 200+ | retire.js |
| WAF signatures | 125 | wafw00f |
| CMS signatures | 83 | WPScan/CMSmap |
| Subdomain takeover | 80 | can-i-take-over-xyz |
| Favicon hashes | 300+ | Shodan |
| SQLi payloads | 489 | sqlmap |
| XSS payloads | 35+ basic, 49 DOM | XSStrike/Dalfox |
| SSTI probes | 32 math + 48 fingerprints | tplmap |
| Command injection | 90 | commix |
| NoSQLi payloads | 92 | — |
| JWT attacks | 95 | — |
| HTTP smuggling | 45 | — |
| Default credentials | 75 | — |
| Vulnerable base images | 30 | — |
| VulnRegistry definitions | 100+ | CWE/OWASP |

## Project Structure

```
basilisk/
├── cli.py                         # Typer CLI
├── config.py                      # Pydantic Settings + YAML
├── domain/                        # Typed domain models (Target, Scenario, Finding, Surface)
├── actor/                         # Network abstraction (CompositeActor, HttpActor, RecordingActor)
├── engine/                        # ScenarioRegistry, TargetLoader, AutonomousRunner
├── bridge/                        # v3 -> v4 compatibility (LegacyPluginScenario, adapters)
├── scenarios/                     # 5 native v4 scenarios (dns, port, ssl, sqli, xss)
├── models/                        # Pydantic v2 contracts (Target, Finding, PluginResult)
├── core/                          # Plugin infrastructure (registry, executor, auth, providers)
├── knowledge/                     # Knowledge graph (entities, relations, state, store, vulns)
├── observations/                  # PluginResult -> Observation adapter
├── capabilities/                  # Plugin capability mapping (145 explicit + auto-inference)
├── reasoning/                     # Cognitive reasoning (hypothesis engine, evidence aggregator)
├── scoring/                       # Priority scoring engine (campaign-aware, hypothesis-aware)
├── decisions/                     # Decision model, context snapshots, evaluated options
├── memory/                        # Decision history, adaptive repetition penalty
├── campaign/                      # Persistent campaign memory (cross-audit learning)
├── orchestrator/                  # Autonomous loop, planner, selector, goals, safety, coverage
├── verification/                  # Finding verification (confidence calculator, confirmer)
├── training/                      # Training validation (profiles, runner, validator)
├── events/                        # Event bus (14 event types)
├── utils/                         # HTTP client, DNS, rate limiter, payloads, WAF bypass
├── storage/                       # SQLite WAL (async, bulk ops, migrations)
└── plugins/                       # 188 plugins (auto-discovered)
    ├── recon/        (23)
    ├── scanning/     (19)
    ├── analysis/     (23)
    ├── pentesting/   (60)
    ├── exploitation/ (23)
    ├── crypto/        (8)
    ├── lateral/      (12)
    ├── privesc/       (7)
    ├── post_exploit/  (7)
    └── forensics/     (6)

training_profiles/                 # 18 YAML profiles for training validation
tests/                             # 1974 tests, 90+ files
```

## Stack

- **Python 3.12+** target
- **Pydantic v2** — data models and validation
- **aiohttp** — async HTTP with connection pooling
- **aiosqlite** — async SQLite (WAL mode)
- **dnspython** — async DNS resolution
- **aiolimiter** — token bucket rate limiting
- **aiofiles** — async file I/O (streaming wordlists)
- **Typer + Rich** — CLI
- **cryptography** — SSL certificate parsing
- **uv** — package manager
- **ruff** — linting (py312, line-length 100)
- **pytest + pytest-asyncio** — testing (asyncio_mode = auto)

## Development

```bash
# Run all tests
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
