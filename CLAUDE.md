# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Проект

**Basilisk v2.0.0** — профессиональный модульный фреймворк безопасности для разведки, анализа и пентеста доменов. Плагинная архитектура с автообнаружением, мультипровайдерная агрегация данных, TUI-дашборд в реальном времени, SQLite-хранилище для миллионов записей.

Философия: сделать с хакерскими утилитами то, что Laravel сделал с Symfony — элегантные абстракции поверх мощных инструментов.

## Стек

- Python 3.12+
- **Pydantic v2** — модели данных, контракты, Settings
- **aiohttp** — async HTTP с connection pooling
- **aiosqlite** — async SQLite (WAL mode)
- **dnspython** — async DNS resolution
- **aiolimiter** — token bucket rate limiting
- **aiofiles** — async file I/O (streaming wordlists)
- **Textual** — TUI дашборд (120 FPS, async-native)
- **Typer + Rich** — CLI headless-режим
- **Jinja2** — HTML-шаблоны отчётов
- **cryptography** — парсинг SSL-сертификатов
- **uv** — менеджер пакетов
- **ruff** — линтинг (py312, line-length 100)
- **pytest + pytest-asyncio** — тестирование (asyncio_mode = auto)

## Команды

```bash
# Установка
uv sync                                          # установка зависимостей
uv pip install -e ".[dev]"                       # с dev-зависимостями

# Запуск
.venv/Scripts/python.exe -m basilisk             # TUI дашборд (Windows)
.venv/Scripts/python.exe -m basilisk plugins     # список плагинов
.venv/Scripts/python.exe -m basilisk audit example.com  # полный аудит
.venv/Scripts/python.exe -m basilisk run ssl_check example.com  # один плагин
.venv/Scripts/python.exe -m basilisk version     # версия

# Тесты и линтинг
.venv/Scripts/python.exe -m pytest tests/ -v     # все тесты (132 шт.)
.venv/Scripts/python.exe -m ruff check basilisk/ tests/  # линтинг
.venv/Scripts/python.exe -m ruff check . --fix   # автофикс
```

## Архитектура

```
basilisk/
├── __init__.py                    # версия, фасад
├── __main__.py                    # python -m basilisk
├── cli.py                         # Typer CLI (headless)
├── config.py                      # Pydantic Settings + YAML
│
├── models/                        # Pydantic-модели (контракты)
│   ├── target.py                  # Target, TargetScope, TargetType
│   ├── result.py                  # PluginResult, Finding, Severity
│   ├── project.py                 # Project, ProjectConfig, ProjectStatus
│   └── types.py                   # DnsRecord, SslInfo, PortInfo, HttpInfo, WhoisInfo
│
├── core/                          # Движок фреймворка
│   ├── plugin.py                  # BasePlugin ABC, PluginMeta, PluginCategory
│   ├── registry.py                # PluginRegistry: discover + topo sort
│   ├── pipeline.py                # Pipeline: фазы recon→scan→analyze→pentest
│   ├── executor.py                # AsyncExecutor + PluginContext (DI)
│   ├── providers.py               # ProviderPool: стратегии all/first/fastest
│   ├── project_manager.py         # ProjectManager: CRUD проектов
│   └── facade.py                  # Audit — fluent API фасад
│
├── utils/                         # Утилиты
│   ├── http.py                    # AsyncHttpClient (aiohttp)
│   ├── dns.py                     # DnsClient (dnspython)
│   ├── net.py                     # TCP connect, banner grab, port check
│   ├── rate_limiter.py            # Token bucket (aiolimiter)
│   └── wordlists.py              # WordlistManager: bundle/download/stream
│
├── storage/                       # SQLite WAL (масштаб: миллионы)
│   ├── db.py                      # Schema + PRAGMA + migrations
│   └── repo.py                    # Repository (CRUD, bulk ops, pagination)
│
├── tui/                           # Textual TUI дашборд
│   ├── app.py                     # BasiliskApp — главное приложение
│   ├── screens/                   # 5 экранов: projects, targets, config, dashboard, report
│   ├── widgets/                   # 4 виджета: phase_progress, finding_feed, stats_panel, target_table
│   └── styles/app.tcss            # Textual CSS
│
├── reporting/                     # Генерация отчётов
│   ├── engine.py                  # ReportEngine + ReportRenderer protocol
│   ├── json.py, csv.py, html.py   # Рендереры
│   └── templates/report.html.j2   # HTML-шаблон (dark theme)
│
└── plugins/                       # 18 плагинов (auto-discover)
    ├── recon/                     # dns_enum, subdomain_crtsh, subdomain_hackertarget,
    │                              # subdomain_rapiddns, subdomain_bruteforce, reverse_ip, whois
    ├── scanning/                  # port_scan, ssl_check, service_detect
    ├── analysis/                  # http_headers, tech_detect, takeover_check
    └── pentesting/                # dir_brute, git_exposure, backup_finder, ftp_anon, misconfig

wordlists/bundled/                 # Словари (~8K записей)
├── dirs_common.txt                # 391 директорий
├── dirs_medium.txt                # 5786 директорий
├── files_common.txt               # 294 чувствительных файла
├── api_endpoints.txt              # 278 API-путей
└── subdomains_common.txt          # 1110 поддоменов

tests/                             # 132 теста
├── conftest.py
├── test_models/                   # 43 теста
├── test_core/                     # 29 тестов
├── test_storage/                  # 17 тестов (вкл. bulk 10K)
├── test_utils/                    # 12 тестов
├── test_plugins/                  # 16 тестов (meta + discovery всех 18)
├── test_reporting/                # 5 тестов
└── test_tui/                      # 10 тестов

config/default.yaml                # Конфиг по умолчанию
```

## Ключевые паттерны

### Плагинная система
- Каждый плагин = файл в `plugins/<category>/`, класс наследует `BasePlugin`, имеет `meta: ClassVar[PluginMeta]` и `async def run(target, ctx) -> PluginResult`
- Автообнаружение через `pkgutil` + `importlib`
- Зависимости (`depends_on`) разрешаются топологической сортировкой (Kahn's algorithm)
- `provides` поле для мультипровайдеров (напр. 4 плагина `provides="subdomains"`)

### Мультипровайдеры (ProviderPool)
- `strategy="all"` — запустить все, объединить результаты (для subdomains)
- `strategy="first"` — первый успешный (для whois)
- `strategy="fastest"` — гонка, взять самый быстрый

### PluginContext (DI)
- Инжектирует: config, http, dns, net, rate, db, wordlists, providers, log, pipeline, state, emit callback
- Все плагины получают общий HTTP-клиент, DNS-резолвер, rate limiter

### Fluent API
```python
results = Audit("magnit.ru").discover().scan().analyze().pentest().report(["json", "html"])
results = Audit.run_plugin("ssl_check", ["example.com"])
```

### Storage (SQLite WAL)
- PRAGMA: journal_mode=WAL, synchronous=NORMAL, cache_size=-65536, mmap_size=2GB
- Таблицы: projects, domains, scan_runs, findings, plugin_data
- Bulk insert батчами по 1000 записей
- UNIQUE INDEX с COALESCE для NULL-safe уникальности

### Pipeline
- 4 фазы: recon → scanning → analysis → pentesting
- Recon расширяет target scope (найденные subdomains добавляются как цели)
- Каждая фаза: resolve_order → run_batch → emit findings → save to DB

## Конвенции

- Конфигурация — единый `pyproject.toml` (зависимости, ruff, pytest)
- Ruff: target py312, line-length 100, select E/F/W/I/N/UP/B/A/SIM
- pytest: asyncio_mode = "auto", testpaths = ["tests"]
- Модели данных — Pydantic v2 BaseModel с factory methods
- Сетевые операции — async (aiohttp, aiosqlite, dnspython async)
- Язык кода и комментариев — английский
- `datetime.UTC` (не `timezone.utc`) — ruff UP017
- `collections.abc.AsyncIterator` (не `typing.AsyncIterator`) — ruff UP035
- Windows: используйте `.venv/Scripts/python.exe` для запуска в venv
