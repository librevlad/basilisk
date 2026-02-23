# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.2.0] - 2026-02-23

### Added

- **Campaign Memory** (`basilisk/campaign/`): persistent cross-audit learning
  - TargetProfile: remembered services, technologies, findings per host
  - PluginEfficacy: per-plugin success rates with tech-stack breakdown
  - TechFingerprint: technology patterns per base domain
  - CampaignStore: async SQLite persistence (WAL mode, 3 tables)
  - CampaignMemory: in-memory aggregator with scorer query API
  - Scorer integration: campaign-adjusted cost + prior_bonus for known infrastructure
  - CLI: `--campaign/--no-campaign` flag on `auto` command
  - System opt-in, disabled by default, fully backward-compatible
- **Attack Paths** (`orchestrator/attack_paths.py`): multi-step exploit chain scoring
  - `count_unlockable_paths()` and `find_available_paths()` for future value estimation
  - Scorer `unlock_value` component rewards capabilities that open new attack paths
- **Cost Learning** (`orchestrator/cost_tracker.py`): runtime plugin statistics
  - Tracks per-plugin success rate, new entities, findings, runtime
  - Adaptive cost adjustment: high success rate → discount, low → penalty
- **Knowledge Graph Decay** (`knowledge/graph.py`): `apply_decay()` reduces confidence of stale entities over time
- **Exploration Rate** (`orchestrator/loop.py`): discovery vs exploitation balance in autonomous loop
- 2 new Planner gap rules: `_attack_path_gaps`, `_http_endpoints_without_forms`
- 223 new tests (total: 1664)

### Changed

- Reporting refactored: shared helpers extracted into `reporting/__init__.py` and `reporting/data.py`
- Scoring formula extended: `(novelty * knowledge_gain + unlock_value + prior_bonus) / (cost + noise + penalty)`
- Planner: 11 → 12 gap detection rules

### Removed

- `basilisk/utils/baseline.py` (dead code, never imported)
- `basilisk/reporting/utils.py` (replaced by `__init__.py` re-exports)
- `run_audit.py` (one-off script with hardcoded targets)
- 7 unused wordlist files (data hardcoded in plugins): wp_plugins_top50, wp_themes_top20, wp_themes_new, wp_themes_additions, backup_extensions, credentials_extended, api_endpoints_extended

## [3.1.0] - 2026-02-23

### Added

- **Autonomous Engine** — state-driven knowledge graph exploration (replaces fixed pipeline as primary mode)
- **Knowledge Graph** (`knowledge/`): entities, relations, state tracking, SQLite persistence
- **Observation Bridge** (`observations/`): automatic PluginResult → Entity/Relation conversion
- **Capability Mapping** (`capabilities/`): 138 explicit + auto-inference for all plugins
- **Scoring Engine** (`scoring/`): priority formula with novelty, knowledge_gain, cost, noise
- **Decision Tracing** (`decisions/`): full pre/post-execution records with context snapshots
- **Decision Memory** (`memory/`): history log, adaptive repetition penalty, JSON persistence
- **Orchestrator** (`orchestrator/`): planner (11 gap rules), selector, executor, safety limits, timeline
- **Event Bus** (`events/`): 9 event types with async handlers
- 66 new plugins (total: 178 across 10 categories)
- Fluent API: `Audit("target").autonomous(max_steps=50).run()`
- Live HTML report engine with liquid glass design
- 1441 tests

## [2.0.0] - 2025-06-01

### Added

- Plugin architecture with auto-discovery via `pkgutil` + `importlib`
- 109 plugins across 4 categories: recon, scanning, analysis, pentesting
- Multi-provider aggregation with strategies: `all`, `first`, `fastest`
- Async pipeline engine with 4 phases: recon, scanning, analysis, pentesting
- Fluent API facade (`Audit("example.com").discover().scan().analyze().pentest()`)
- Dependency injection via `PluginContext`
- Topological sort (Kahn's algorithm) for plugin dependency resolution
- Textual TUI dashboard with real-time progress (120 FPS, async-native)
- Typer + Rich CLI for headless operation
- SQLite WAL storage optimized for millions of records
- Bulk insert with configurable batch size (default 1000)
- Project management system with CRUD operations
- Report generation: JSON, CSV, HTML (dark theme Jinja2 templates)
- Live HTML report with auto-refresh
- Async HTTP client with connection pooling (aiohttp)
- Async DNS resolver (dnspython)
- Token bucket rate limiting (aiolimiter)
- Streaming wordlist manager with bundled dictionaries (~8K entries)
- Pydantic v2 data models and settings
- Layered configuration: defaults, YAML, CLI flags, environment variables
- 132+ tests with pytest-asyncio (auto mode)
- Ruff linting (py312, line-length 100)

[2.0.0]: https://github.com/librevlad/basilisk/releases/tag/v2.0.0
