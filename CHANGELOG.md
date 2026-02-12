# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
