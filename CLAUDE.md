# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Проект

**Basilisk v2.0.0** — профессиональный модульный фреймворк безопасности для разведки, анализа и пентеста доменов. Плагинная архитектура с автообнаружением, мультипровайдерная агрегация данных, TUI-дашборд в реальном времени, SQLite-хранилище для миллионов записей.

Философия: сделать с хакерскими утилитами то, что Laravel сделал с Symfony — элегантные абстракции поверх мощных инструментов.

## Быстрые команды

```bash
# Тесты
.venv/Scripts/python.exe -m pytest tests/ -v              # все 883 теста
.venv/Scripts/python.exe -m pytest tests/test_plugins/ -v  # только плагины (324)
.venv/Scripts/python.exe -m pytest tests/ -x --tb=short    # до первого падения

# Линтинг
.venv/Scripts/python.exe -m ruff check basilisk/ tests/
.venv/Scripts/python.exe -m ruff check . --fix

# Запуск
.venv/Scripts/python.exe -m basilisk                       # TUI дашборд
.venv/Scripts/python.exe -m basilisk audit example.com     # полный аудит
.venv/Scripts/python.exe -m basilisk run ssl_check example.com  # один плагин
.venv/Scripts/python.exe -m basilisk plugins               # 112 плагинов

# Установка
uv sync && uv pip install -e ".[dev]"
```

## Стек

- **Python 3.12+** — целевая версия, ruff target py312
- **Pydantic v2** — модели данных, контракты, Settings
- **aiohttp** — async HTTP с connection pooling
- **aiosqlite** — async SQLite (WAL mode)
- **dnspython** — async DNS resolution
- **aiolimiter** — token bucket rate limiting
- **aiofiles** — async file I/O (streaming wordlists)
- **Textual** — TUI дашборд (async-native)
- **Typer + Rich** — CLI headless-режим
- **Jinja2** — HTML-шаблоны отчётов
- **cryptography** — парсинг SSL-сертификатов
- **uv** — менеджер пакетов
- **ruff** — линтинг (py312, line-length 100)
- **pytest + pytest-asyncio** — тестирование (asyncio_mode = auto)

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
│   ├── registry.py                # PluginRegistry: discover + topo sort (Kahn's)
│   ├── pipeline.py                # Pipeline: фазы recon→scan→analyze→pentest
│   ├── executor.py                # AsyncExecutor + PluginContext (DI-контейнер)
│   ├── providers.py               # ProviderPool: стратегии all/first/fastest
│   ├── project_manager.py         # ProjectManager: CRUD проектов
│   ├── facade.py                  # Audit — fluent API фасад
│   ├── auth.py                    # AuthManager, FormLoginStrategy
│   ├── callback.py                # OOB CallbackServer
│   └── exploit_chain.py           # ExploitChainEngine
│
├── utils/                         # Утилиты
│   ├── http.py                    # AsyncHttpClient (aiohttp), resolve_base_url(s)
│   ├── dns.py                     # DnsClient (dnspython)
│   ├── net.py                     # TCP connect, banner grab, port check
│   ├── rate_limiter.py            # Token bucket (aiolimiter), global + per-host
│   ├── wordlists.py               # WordlistManager: bundle/download/stream
│   ├── batch_check.py             # batch_head_check — parallel HEAD probing
│   ├── baseline.py                # Baseline response comparison
│   ├── browser.py                 # BrowserManager (headless Playwright)
│   ├── diff.py                    # ResponseDiffer
│   ├── dynamic_wordlist.py        # DynamicWordlistGenerator
│   ├── http_check.py              # HTTP reachability helpers
│   ├── oob_verifier.py            # OOB interaction verifier
│   ├── payloads.py                # PayloadEngine
│   ├── raw_http.py                # Low-level raw HTTP requests
│   └── waf_bypass.py              # WafBypassEngine
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
│   ├── live_html.py               # Liquid glass live HTML report
│   └── templates/report.html.j2   # HTML-шаблон (dark theme)
│
└── plugins/                       # 112 плагинов (auto-discover)
    ├── recon/        (23)         # dns_enum, subdomain_*, whois, reverse_ip,
    │                              # asn_lookup, web_crawler, email_harvest,
    │                              # github_dorking, robots_parser, sitemap_parser, ...
    ├── scanning/     (13)         # port_scan, ssl_check, service_detect, cdn_detect,
    │                              # cors_scan, graphql_detect, websocket_detect, ...
    ├── analysis/     (21)         # http_headers, tech_detect, takeover_check,
    │                              # js_secret_scan, csp_analyzer, waf_detect, ...
    └── pentesting/   (55)         # git_exposure, dir_brute, sqli_*, xss_*,
                                   # ssrf_*, ssti_*, command_injection, lfi_check,
                                   # jwt_attack, cors_exploit, cache_poison, ...

wordlists/bundled/                 # 13 словарей
tests/                             # 883 теста, 54 файла
├── test_models/                   # 43 теста
├── test_core/                     # 147 тестов
├── test_plugins/                  # 324 теста (110/110 плагинов покрыты)
├── test_utils/                    # 212 тестов
├── test_storage/                  # 18 тестов
├── test_reporting/                # 26 тестов
├── test_tui/                      # 10 тестов
└── test_cli.py, test_config.py    # 24 теста

examples/git/                      # Скрипты массового сканирования
├── git_exposure_scan.py           # Bulk git scanner (PriorityQueue, resume)
├── top10million_ru.csv            # Домены .ru
└── top10milliondomains.csv        # Топ-10M мировых доменов

config/default.yaml                # Конфиг по умолчанию
```

## Ключевые паттерны

### Плагинная система
- Каждый плагин = файл в `plugins/<category>/`, класс наследует `BasePlugin`, имеет `meta: ClassVar[PluginMeta]` и `async def run(target, ctx) -> PluginResult`
- Автообнаружение через `pkgutil` + `importlib` в `PluginRegistry.discover()`
- Зависимости (`depends_on`) разрешаются топологической сортировкой (Kahn's algorithm)
- `provides` поле для мультипровайдеров (напр. 10 плагинов `provides="subdomains"`)
- `default_enabled=False` для тяжёлых плагинов (subdomain_bruteforce)

### Создание нового плагина
```python
# basilisk/plugins/<category>/my_plugin.py
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
        findings: list[Finding] = []
        # ... logic using ctx.http, ctx.dns, ctx.rate ...
        # HIGH/CRITICAL findings MUST have evidence:
        findings.append(Finding.high("Title", evidence="proof", description="..."))
        return PluginResult.success(self.meta.name, target.host, findings=findings)
```
Файл автоматически обнаружится — никакой регистрации не нужно.

### PluginContext (DI-контейнер)
Передаётся в каждый `plugin.run(target, ctx)`. Основные поля:
- `ctx.config` — Settings (Pydantic)
- `ctx.http` — AsyncHttpClient (aiohttp), методы: `.get()`, `.head()`, `.post()`, `.fetch_text()`
- `ctx.dns` — DnsClient
- `ctx.net` — NetUtils (port check, banner grab)
- `ctx.rate` — RateLimiter, использование: `async with ctx.rate:` или `async with ctx.rate.host(hostname):`
- `ctx.wordlists` — WordlistManager
- `ctx.providers` — ProviderPool
- `ctx.pipeline` — dict[str, PluginResult] предыдущих результатов (напр. `ctx.pipeline["port_scan:host"]`)
- `ctx.state` — dict для shared state между плагинами
- `ctx.emit(finding, target_host)` — callback для TUI live-feed
- `ctx.should_stop` — True когда < 2с до таймаута, плагин должен вернуть partial result

### Мультипровайдеры (ProviderPool)
- `strategy="all"` — запустить все, объединить результаты (для subdomains)
- `strategy="first"` — первый успешный (для whois)
- `strategy="fastest"` — гонка, взять самый быстрый

### Fluent API (facade.py)
```python
results = await Audit("example.com").discover().scan().analyze().pentest().report(["json", "html"]).run()
results = await Audit.run_plugin("ssl_check", ["example.com"])
```

### Инициализация контекста (паттерн из facade.py:135-241)
```python
settings = Settings.load()
registry = PluginRegistry(); registry.discover()
http = AsyncHttpClient(timeout=settings.http.timeout, ...)
dns = DnsClient(nameservers=settings.dns.nameservers, ...)
net = NetUtils(timeout=settings.scan.port_timeout)
rate = RateLimiter(rate=settings.rate_limit.requests_per_second, ...)
ctx = PluginContext(config=settings, http=http, dns=dns, net=net, rate=rate, ...)
```

### Storage (SQLite WAL)
- PRAGMA: journal_mode=WAL, synchronous=NORMAL, cache_size=-65536, mmap_size=2GB
- Таблицы: projects, domains, scan_runs, findings, plugin_data
- Bulk insert батчами по 1000 записей

### Pipeline
- 4 фазы: recon → scanning → analysis → pentesting
- Recon расширяет target scope (найденные subdomains добавляются как цели)
- Каждая фаза: resolve_order → run_batch → emit findings → save to DB

## Конвенции кода

### Стиль
- Ruff: target py312, line-length 100, select E/F/W/I/N/UP/B/A/SIM
- `datetime.UTC` (не `timezone.utc`) — ruff UP017
- `collections.abc.AsyncIterator` (не `typing.AsyncIterator`) — ruff UP035
- `from __future__ import annotations` — в каждом файле
- Язык кода, комментариев, docstrings — **английский**
- Язык общения с пользователем — **русский**

### Модели данных
- Pydantic v2 BaseModel с factory methods (Target.domain(), Finding.high(), PluginResult.success())
- Finding severity: INFO(0), LOW(1), MEDIUM(2), HIGH(3), CRITICAL(4)
- HIGH/CRITICAL findings **обязаны** иметь `evidence` — иначе quality warning

### Сетевые операции
- Всё async: aiohttp, aiosqlite, dnspython async
- Rate limiting через `async with ctx.rate:` перед каждым запросом
- `resolve_base_urls(target, ctx)` для определения HTTP/HTTPS base URL хоста
- `batch_head_check()` для массовой проверки URL (parallel HEAD requests)

### Тестирование
- pytest: asyncio_mode = "auto", testpaths = ["tests"]
- Тесты плагинов: meta + discovery + функциональные mock-тесты для всех 110 плагинов
- Mock сетевые вызовы через `unittest.mock.AsyncMock`
- Всегда запускать `ruff check` перед коммитом

### Windows
- Используйте `.venv/Scripts/python.exe` (не `python` напрямую)
- Пути: прямые и обратные слеши работают, но в subprocess предпочтительны прямые
- `signal.signal(SIGINT, handler)` вместо `loop.add_signal_handler` (не работает на Windows)

## Workflow при разработке

1. **Перед началом**: прочитать существующий код через Read/Grep, понять паттерны
2. **Написание кода**: следовать существующим паттернам, не добавлять лишнего
3. **Ruff check**: запускается автоматически после каждого Edit/Write .py файлов (hook)
4. **Тесты**: `pytest tests/ -x --tb=short` для быстрой проверки
5. **Коммит**: только по запросу пользователя

## Текущее состояние и план на будущее

> **ВАЖНО**: Прочитай `AUDIT_NOTES.md` в корне проекта — там полный журнал аудита,
> исправленных багов, и детальный план live-тестирования всех 112 плагинов.

> **Приоритет**: серверные уязвимости, не требующие участия жертвы (SQLi, CMDi, SSRF, SSTI, LFI, XXE, etc.)
> Клиентские уязвимости (XSS, CSRF, Clickjacking) — вторичные.

### Что сделано (v2.0.0 refactoring)
- [x] Глубокий аудит всей кодовой базы (3 параллельных ревью)
- [x] 5 критических багов исправлено (race condition, progress math, etc.)
- [x] DI-контейнер улучшен (типизация, requires_http, ProviderPool setup/teardown)
- [x] DRY: централизованы SECRET_PATTERNS (utils/secrets.py), extract_plugin_stats (reporting/utils.py), resolve_base_url консолидация
- [x] Фасад: decomposed Audit.run() God Method → 7 приватных методов
- [x] Subdomain-плагины: аудит, исправление 4 сломанных, 2 новых провайдера (certspotter, anubis)
- [x] Recon batch (18 плагинов): live-тест, 8 файлов исправлено, 24 теста добавлено
- [x] Analysis/Scanning batch (10 плагинов): live-тест, сравнение с проф-инструментами, 7 багов исправлено, 39 тестов
- [x] Тесты: 883 (было 664), 110/110 плагинов покрыты, ruff чисто
- [x] Базы сигнатур расширены до уровня профессиональных инструментов (3 раунда)

### Базы сигнатур (текущее состояние)

| База | Файл | Кол-во | Аналог |
|------|------|--------|--------|
| TECH_FINGERPRINTS | data/fingerprints.py | 594 | Wappalyzer top-500 |
| _VULNERABLE_VERSIONS (CVE) | analysis/version_detect.py | 200+ | retire.js |
| WAF_SIGNATURES | analysis/waf_detect.py | 125 | wafw00f 100+ |
| CMS_SIGNATURES | analysis/cms_detect.py | 83 | WPScan/CMSmap |
| TAKEOVER_FINGERPRINTS | data/fingerprints.py | 80 | can-i-take-over-xyz |
| CSP_BYPASS_DOMAINS | data/fingerprints.py | 52 | Google CSP Evaluator (3.5x) |
| KNOWN_FAVICONS + MMH3 | analysis/favicon_hash.py | 300+ | Shodan |
| CLOUD_SIGNATURES | analysis/cloud_detect.py | 33 | — |
| CDN_SIGNATURES | scanning/cdn_detect.py | 40 | — |
| WEAK_CIPHERS | scanning/tls_cipher_scan.py | 55 | testssl.sh |
| XSS payloads | pentesting/xss_*.py | 35+ basic, 49 DOM sinks | XSStrike/Dalfox |
| SQLi payloads | utils/payloads.py | 489 | sqlmap (~30%) |
| SSTI probes | pentesting/ssti_*.py | 32 math + 48 fingerprints | tplmap |
| SSRF bypasses | pentesting/ssrf_check.py | 40 IP + 31 cloud meta | — |
| XXE payloads | pentesting/xxe_check.py | 22 file + 12 SSRF + 5 blind | — |
| JWT attacks | pentesting/jwt_attack.py | 18 none + 60 secrets + 17 kid | — |
| HTTP smuggling | pentesting/http_smuggling.py | 45 TE obfuscations | — |
| NoSQLi payloads | pentesting/nosqli_check.py | 92 total | — |
| Command injection | pentesting/command_injection.py | 90 | commix |
| Path traversal | pentesting/path_traversal.py | 62 | — |
| Default credentials | pentesting/default_creds.py | 75 | — |
| WP plugins/themes | pentesting/wp_deep_scan.py | 86 + 52 | WPScan |
| Actuator endpoints | pentesting/actuator_exploit.py | 31 + 22 OpenAPI + 15 GraphQL | — |

### Что нужно сделать (план в AUDIT_NOTES.md)

#### Следующий шаг: Live-аудит плагинов по батчам
Методология проверена на subdomain-плагинах: прочитать код → протестировать живьём →
сравнить с профессиональными инструментами → исправить сломанное → написать тесты.

Порядок батчей:
1. ~~**Батч 1: Recon** (12 плагинов)~~ — ВЫПОЛНЕНО 2026-02-12
2. ~~**Батч 2/3: Analysis + Scanning** (10 плагинов)~~ — ВЫПОЛНЕНО 2026-02-13
3. **Батч 3 остаток: Analysis** (11 плагинов) — waf_bypass, js_api_extract, js_secret_scan, openapi_parser, api_detect, security_txt, meta_extract, link_extractor, form_analyzer, cloud_detect, prometheus_scrape
4. **Батч 2 остаток: Scanning** (7 плагинов) — ssl_check (God Plugin!), tls_cipher_scan, redirect_chain, graphql_detect, websocket_detect, dnssec_check, ipv6_scan
5. **Батч 4: Pentesting** (55 плагинов, разбить на подбатчи) — sqli, xss, ssrf, ssti, etc.

#### Архитектурные задачи (отложены)
- Разделение ssl_check.py (2563 строки → 4-5 плагинов)
- Экстернализация payload data (payloads.py 1933 строки, waf_bypass.py 1331 строка → YAML)
- Миграции БД (нет версионирования schema)
- CORS/CSP overlap между http_headers и dedicated плагинами
- ASN lookup дублирование (asn_lookup.py + whois.py)

#### Ожидаемые паттерны проблем
- Сломанные внешние API (rate limits, auth requirements) — как было с HackerTarget, AlienVault, VirusTotal
- Тихие провалы (`except Exception: pass`) — нужно добавить информативные сообщения
- Дублирование findings между плагинами (ssl_check ↔ tls_cipher_scan, lfi_check ↔ path_traversal)
- Устаревшие fingerprints/сигнатуры
