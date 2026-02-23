# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Проект

**Basilisk v3.2.0** — профессиональный модульный фреймворк безопасности для разведки, анализа и пентеста доменов. Два режима: классический pipeline и автономный движок на knowledge graph с детерминированными decision traces. Плагинная архитектура с автообнаружением, мультипровайдерная агрегация данных, TUI-дашборд в реальном времени, SQLite-хранилище для миллионов записей. Persistent campaign memory для кросс-аудитного обучения.

Философия: сделать с хакерскими утилитами то, что Laravel сделал с Symfony — элегантные абстракции поверх мощных инструментов.

## Быстрые команды

```bash
# Тесты
.venv/Scripts/python.exe -m pytest tests/ -v              # все 1664 тестов
.venv/Scripts/python.exe -m pytest tests/test_plugins/ -v  # только плагины (324)
.venv/Scripts/python.exe -m pytest tests/ -x --tb=short    # до первого падения

# Линтинг
.venv/Scripts/python.exe -m ruff check basilisk/ tests/
.venv/Scripts/python.exe -m ruff check . --fix

# Запуск
.venv/Scripts/python.exe -m basilisk auto example.com                # автономный аудит (основной)
.venv/Scripts/python.exe -m basilisk auto example.com -n 50          # с лимитом шагов
.venv/Scripts/python.exe -m basilisk auto example.com --campaign     # с campaign memory
.venv/Scripts/python.exe -m basilisk audit example.com               # классический pipeline
.venv/Scripts/python.exe -m basilisk run ssl_check example.com       # один плагин
.venv/Scripts/python.exe -m basilisk plugins                         # 178 плагинов
.venv/Scripts/python.exe -m basilisk tui                             # TUI дашборд

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
│   ├── facade.py                  # Audit — fluent API фасад (+autonomous mode)
│   ├── auth.py                    # AuthManager, FormLoginStrategy
│   ├── callback.py                # OOB CallbackServer
│   ├── attack_graph.py            # AttackGraph для exploit chain визуализации
│   └── exploit_chain.py           # ExploitChainEngine
│
├── knowledge/                     # [v3] Knowledge Graph
│   ├── entities.py                # Entity, EntityType — типизированные узлы
│   ├── relations.py               # Relation, RelationType — типизированные связи
│   ├── graph.py                   # KnowledgeGraph: dedup, merge, query, neighbors
│   ├── state.py                   # [v3.1] KnowledgeState: delta-tracking wrapper
│   └── store.py                   # KnowledgeStore: SQLite persistence
│
├── observations/                  # [v3] PluginResult → Observation мост
│   ├── observation.py             # Observation model
│   └── adapter.py                 # adapt_result(): PluginResult → list[Observation]
│
├── capabilities/                  # [v3] Маппинг плагинов на capabilities
│   ├── capability.py              # Capability model (requires/produces/cost/noise)
│   └── mapping.py                 # CAPABILITY_MAP для 175 плагинов
│
├── decisions/                     # [v3.1] Decision tracing
│   └── decision.py                # Decision, ContextSnapshot, EvaluatedOption
│
├── memory/                        # [v3.1] Decision memory
│   └── history.py                 # History: decision log, repetition penalty, persistence
│
├── scoring/                       # [v3] Scoring engine
│   └── scorer.py                  # Scorer: multi-component formula + campaign-aware cost
│
├── orchestrator/                  # [v3] Автономный движок
│   ├── planner.py                 # Planner: 12 правил обнаружения knowledge gaps
│   ├── selector.py                # Selector: match gaps → capabilities, pick batch
│   ├── executor.py                # OrchestratorExecutor: обёртка над core executor
│   ├── loop.py                    # AutonomousLoop: цикл + decision tracing + KnowledgeState
│   ├── attack_paths.py            # [v3.2] Multi-step attack path scoring
│   ├── cost_tracker.py            # [v3.2] Runtime plugin cost learning
│   ├── safety.py                  # SafetyLimits: max_steps, max_duration, cooldown
│   └── timeline.py                # Timeline: структурированный лог выполнения
│
├── campaign/                      # [v3.2] Persistent campaign memory
│   ├── models.py                  # TargetProfile, PluginEfficacy, TechFingerprint
│   ├── store.py                   # CampaignStore: async SQLite (3 tables, WAL mode)
│   ├── memory.py                  # CampaignMemory: in-memory aggregator, scorer query API
│   └── extractor.py               # Extract profiles/efficacy/fingerprints from KG
│
├── events/                        # [v3] Event Bus
│   └── bus.py                     # EventBus: subscribe/emit + DECISION_MADE event
│
├── utils/                         # Утилиты
│   ├── http.py                    # AsyncHttpClient (aiohttp), resolve_base_url(s)
│   ├── dns.py                     # DnsClient (dnspython)
│   ├── net.py                     # TCP connect, banner grab, port check
│   ├── rate_limiter.py            # Token bucket (aiolimiter), global + per-host
│   ├── wordlists.py               # WordlistManager: bundle/download/stream
│   ├── batch_check.py             # batch_head_check — parallel HEAD probing
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
└── plugins/                       # 178 плагинов (auto-discover)
    ├── recon/        (23)         # dns_enum, subdomain_*, whois, reverse_ip,
    │                              # asn_lookup, web_crawler, email_harvest,
    │                              # github_dorking, robots_parser, sitemap_parser, ...
    ├── scanning/     (16)         # port_scan, ssl_check, service_detect, cdn_detect,
    │                              # cors_scan, graphql_detect, websocket_detect, ...
    ├── analysis/     (21)         # http_headers, tech_detect, takeover_check,
    │                              # js_secret_scan, csp_analyzer, waf_detect, ...
    ├── pentesting/   (57)         # git_exposure, dir_brute, sqli_*, xss_*,
    │                              # ssrf_*, ssti_*, command_injection, lfi_check,
    │                              # jwt_attack, cors_exploit, cache_poison, ...
    ├── exploitation/ (21)         # cors_exploit, graphql_exploit, nosqli_verify, ...
    ├── crypto/        (8)         # hash_crack, padding_oracle, weak_random, ...
    ├── lateral/      (12)         # service_brute, ssh_brute, credential_spray, ...
    ├── privesc/       (7)         # suid_finder, kernel_suggest, ...
    ├── post_exploit/  (7)         # data_exfil, persistence_check, ...
    └── forensics/     (6)         # log_analyzer, memory_dump, ...

wordlists/bundled/                 # 6 словарей
tests/                             # 1664 тестов, 80+ файлов
├── test_models/                   # 43 теста
├── test_core/                     # 167 тестов
├── test_plugins/                  # 324 теста (110/110 плагинов покрыты)
├── test_utils/                    # 212 тестов
├── test_storage/                  # 18 тестов
├── test_reporting/                # 26 тестов
├── test_tui/                      # 10 тестов
├── test_knowledge/                # 56 тестов (entities, graph, state, store)
├── test_observations/             # 26 тестов (adapter)
├── test_capabilities/             # 8 тестов (mapping)
├── test_decisions/                # 12 тестов (decision model)
├── test_memory/                   # 19 тестов (history, repetition penalty)
├── test_scoring/                  # 22 теста (scorer + breakdown + multistep)
├── test_orchestrator/             # 73 теста (loop, planner, selector, safety, attack_paths, cost_tracker)
├── test_events/                   # 5 тестов (bus)
├── test_campaign/                 # 61 тест (models, store, memory, extractor, integration)
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
# Классический pipeline
results = await Audit("example.com").discover().scan().analyze().pentest().report(["json", "html"]).run()
# Автономный режим (v3)
results = await Audit("example.com").autonomous(max_steps=50).run()
# Автономный с campaign memory (v3.2)
results = await Audit("example.com").autonomous(max_steps=50).enable_campaign().run()
# Один плагин
results = await Audit.run_plugin("ssl_check", ["example.com"])
```

### Автономный движок (v3 + v3.1 decision tracing + v3.2 campaign memory)
- `KnowledgeGraph` — in-memory граф с entities, relations, dedup, confidence merge, decay
- `KnowledgeState` — [v3.1] delta-tracking wrapper, `apply_observation()` → `ObservationOutcome`
- `Planner` — 13 правил обнаружения gaps (host_without_services, attack_paths, ...)
- `Selector` — match gaps → capabilities, pick batch (budget-constrained)
- `Scorer` — формула + `score_breakdown` dict + campaign-aware cost + prior_bonus
- `AttackPaths` — [v3.2] multi-step exploit chain scoring, unlock_value
- `CostTracker` — [v3.2] runtime plugin success/failure statistics, adaptive cost adjustment
- `CampaignMemory` — [v3.2] persistent cross-audit learning (SQLite, opt-in)
- `Decision` — [v3.1] полная запись: context snapshot, evaluated options, reasoning trace, outcome
- `History` — [v3.1] лог решений, repetition penalty (decay + unproductive multiplier), JSON persistence
- `AutonomousLoop` — seed → find_gaps → match → score → **build decision** → execute → apply → repeat
- `SafetyLimits` — max_steps, max_duration_seconds, batch_size, cooldown tracking
- `adapter.py` — конвертация `PluginResult` → `list[Observation]` → entities/relations в граф
- `mapping.py` — все 178 плагинов маппятся на requires/produces/cost/noise

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
- Таблицы: projects, domains, scan_runs, findings, plugin_data, kg_entities, kg_relations
- Bulk insert батчами по 1000 записей
- KnowledgeStore сохраняет knowledge graph в SQLite после автономного прогона

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
5. **Коммит**: только по запросу пользователя, всегда в формате Conventional Commits
6. **Ветки**: вся работа ведётся на feature-ветках от develop (см. Git Flow ниже)

---

## Git Flow + Conventional Commits

### Структура веток

```
master          ← стабильные релизы, каждый merge = тег версии
  └── develop   ← интеграционная ветка, сюда мержатся feature branches
       ├── feature/<name>   ← от develop, для каждой задачи
       └── hotfix/<name>    ← от master, критические фиксы → master + develop
```

| Ветка | Создаётся от | Мержится в | Назначение |
|-------|-------------|------------|------------|
| `master` | — | — | Стабильные релизы. Только merge из develop/hotfix |
| `develop` | `master` | `master` (при релизе) | Интеграция. Default branch на GitHub |
| `feature/<name>` | `develop` | `develop` | Одна задача = одна ветка |
| `hotfix/<name>` | `master` | `master` + `develop` | Критические фиксы в продакшене |
| `release/<version>` | `develop` | `master` + `develop` | Опционально, при подготовке релиза |

### Conventional Commits

Формат каждого коммита:
```
<type>(<scope>): <description>

[optional body]

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
```

**Типы:**
| Тип | Когда использовать | Bump |
|-----|--------------------|------|
| `feat` | Новая функциональность | minor |
| `fix` | Исправление бага | patch |
| `refactor` | Рефакторинг без изменения поведения | — |
| `test` | Добавление/изменение тестов | — |
| `docs` | Документация (CLAUDE.md, README, etc.) | — |
| `chore` | Конфиги, зависимости, CI | — |
| `perf` | Оптимизация производительности | patch |
| `style` | Форматирование, линтинг (без логики) | — |
| `ci` | CI/CD конфигурация | — |

**Scopes** (один из):
`plugins`, `orchestrator`, `knowledge`, `pipeline`, `tui`, `cli`, `storage`, `reporting`,
`utils`, `models`, `core`, `scoring`, `observations`, `capabilities`, `decisions`, `memory`,
`events`, `data`, `config`, `campaign`

**Примеры:**
```
feat(plugins): add redis_exploit plugin
fix(orchestrator): prevent infinite loop when no gaps found
refactor(knowledge): extract entity merge logic into separate method
test(plugins): add functional tests for xss_advanced
docs: update CLAUDE.md with git flow rules
chore: bump aiohttp to 3.9.5
```

### Правила для Claude Code (ОБЯЗАТЕЛЬНЫЕ)

**При каждом коммите:**
1. Формат — строго Conventional Commits (type, scope, description)
2. Scope берётся из списка выше; если изменения затрагивают несколько — использовать основной
3. Description — на английском, императив, lowercase, без точки в конце
4. Body — опционально, если нужен контекст
5. Всегда заканчивать `Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>`

**При создании ветки:**
1. Всегда от `develop` (кроме hotfix — от master)
2. Имя: `feature/<short-kebab-case>` или `hotfix/<short-kebab-case>`
3. Пример: `feature/redis-exploit`, `hotfix/fix-ssl-crash`

**При создании PR:**
1. Target branch = `develop` (кроме hotfix → target = master)
2. Title = тот же формат что commit message (type(scope): description)
3. После merge — удалить feature-ветку

**Lifecycle задачи:**
```bash
# 1. Создать ветку
git checkout develop && git pull origin develop
git checkout -b feature/my-feature

# 2. Работать, коммитить
git add <files>
git commit -m "feat(scope): description

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"

# 3. Push + PR
git push -u origin feature/my-feature
gh pr create --base develop --title "feat(scope): description" --body "..."

# 4. После merge — cleanup
git checkout develop && git pull origin develop
git branch -d feature/my-feature
```

**Release flow:**
```bash
# На develop, когда готов релиз:
git checkout master && git pull origin master
git merge develop
git tag -a v3.2.0 -m "v3.2.0"
git push origin master --tags
```

**Hotfix flow:**
```bash
git checkout master && git checkout -b hotfix/fix-critical-bug
# ... fix ...
git commit -m "fix(core): prevent crash on empty input"
# PR → master, после merge:
git checkout develop && git merge master
```

---

## Автономный движок — обзор

Автономный движок — основной режим работы Basilisk. Вместо жёсткого pipeline он строит
**knowledge graph** о цели и итеративно обнаруживает пробелы в знаниях (gaps), выбирает
оптимальные плагины для их заполнения, выполняет их и обогащает граф результатами.
Каждое решение детерминированно записывается с полным контекстом.

### Цикл работы

```
                          ┌─────────────────────────────────────────────────┐
                          │                 AUTONOMOUS LOOP                  │
                          │                                                 │
  Targets ──► SEED ──►    │  ┌─────────┐    ┌──────────┐    ┌───────────┐  │
  (hosts)   (create       │  │ PLANNER │───►│ SELECTOR │───►│  SCORER   │  │
             Host         │  │ 13 gap  │    │ match +  │    │ rank by   │  │
             entities)    │  │ rules   │    │ pick     │    │ priority  │  │
                          │  └────┬────┘    └──────────┘    └─────┬─────┘  │
                          │       │                               │        │
                          │       │    ┌───────────────┐          │        │
                          │       │    │   DECISION    │◄─────────┘        │
                          │       │    │ context snap  │                   │
                          │       │    │ eval options  │                   │
                          │       │    │ reasoning     │                   │
                          │       │    └───────┬───────┘                   │
                          │       │            │                           │
                          │       │    ┌───────▼───────┐                   │
                          │       │    │   EXECUTE     │                   │
                          │       │    │ plugin.run()  │                   │
                          │       │    └───────┬───────┘                   │
                          │       │            │                           │
                          │       │    ┌───────▼───────┐                   │
                          │       │    │   OBSERVE     │                   │
                          │       │    │ adapt_result  │                   │
                          │       │    │ → Observation │                   │
                          │       │    └───────┬───────┘                   │
                          │       │            │                           │
                          │       │    ┌───────▼───────┐                   │
                          │       ◄────│ APPLY to KG   │                   │
                          │            │ entities +    │                   │
                          │            │ relations     │                   │
                          │            └───────────────┘                   │
                          └─────────────────────────────────────────────────┘
```

### Условия завершения (termination_reason)

| Reason | Описание |
|--------|----------|
| `no_gaps` | Все пробелы в знаниях заполнены — аудит завершён |
| `limit_reached` | Превышен `max_steps` или `max_duration_seconds` |
| `no_capabilities` | Оставшиеся gaps не могут быть заполнены доступными плагинами |
| `no_candidates` | Все кандидаты отфильтрованы (уже выполнены или на cooldown) |
| `all_executed` | Весь батч уже был выполнен ранее |

### Ключевые принципы
- **Детерминированные ID**: `Entity.make_id()` и `Decision.make_id()` — SHA256 от ключевых полей
- **Probabilistic confidence merge**: `1 - (1-old)*(1-new)` — каждое наблюдение увеличивает уверенность
- **Decision traces**: каждое решение записывается ДО выполнения, outcome — ПОСЛЕ
- **Gap-driven**: движок работает пока есть knowledge gaps; нет gaps = аудит завершён

### Fluent API
```python
results = await Audit("example.com").autonomous(max_steps=50).run()      # автономный
results = await Audit("example.com").autonomous().enable_campaign().run() # с campaign memory
results = await Audit("example.com").discover().scan().analyze().pentest().run()  # pipeline
results = await Audit.run_plugin("ssl_check", ["example.com"])           # один плагин
```

---

## Knowledge Graph

Центральное хранилище всей информации о целях аудита. Типизированные узлы (Entity) и
связи (Relation) образуют граф, который обогащается с каждой итерацией автономного цикла.

### EntityType — 7 типов узлов

| EntityType | Key Fields (для make_id) | Типичные data fields | Factory method |
|-----------|-------------------------|---------------------|---------------|
| `HOST` | `host` | `host`, `type`, `dns_records`, `ssl_info` | `Entity.host("example.com")` |
| `SERVICE` | `host`, `port`, `protocol` | `host`, `port`, `protocol`, `service`, `banner` | `Entity.service("example.com", 443, "tcp")` |
| `ENDPOINT` | `host`, `path` | `host`, `path`, `has_params`, `is_api`, `is_upload`, `is_graphql`, `is_admin`, `scan_path` | `Entity.endpoint("example.com", "/api/v1")` |
| `TECHNOLOGY` | `host`, `name`, `version` | `host`, `name`, `version`, `is_cms`, `is_waf` | `Entity.technology("example.com", "nginx", "1.24")` |
| `CREDENTIAL` | `host`, `username` | `host`, `username`, `password`, `source` | `Entity.credential("example.com", "admin")` |
| `FINDING` | `host`, `title` | `host`, `title`, `severity`, `description`, `evidence` | `Entity.finding("example.com", "XSS in /search")` |
| `VULNERABILITY` | `host`, `name` | `host`, `name`, `severity`, `cve` | `Entity.vulnerability("example.com", "CVE-2024-1234")` |

### RelationType — 7 типов связей

| RelationType | Семантика | Направление | Пример |
|-------------|-----------|-------------|--------|
| `EXPOSES` | Хост предоставляет сервис | HOST -> SERVICE | example.com EXPOSES :443/tcp |
| `RUNS` | Сервис использует технологию | SERVICE -> TECHNOLOGY | :443 RUNS nginx/1.24 |
| `HAS_ENDPOINT` | Сервис имеет endpoint | SERVICE -> ENDPOINT | :443 HAS_ENDPOINT /api/v1 |
| `HAS_VULNERABILITY` | Технология имеет уязвимость | TECHNOLOGY -> VULNERABILITY | nginx HAS_VULNERABILITY CVE-... |
| `ACCESSES` | Credential даёт доступ | CREDENTIAL -> HOST | admin:pass ACCESSES example.com |
| `RELATES_TO` | Finding связан с entity | FINDING -> any | XSS RELATES_TO example.com |
| `PARENT_OF` | Домен является родителем | HOST -> HOST | example.com PARENT_OF sub.example.com |

### Генерация ID и дедупликация

```python
Entity.make_id(EntityType.HOST, host="example.com")
# -> sha256("host:host=example.com")[:16] -> "a1b2c3d4e5f6g7h8"
```

Детерминированные ID обеспечивают автоматическую дедупликацию: entity с тем же ID
мержится вместо дублирования.

### Confidence merge (probabilistic OR)

```
merged = 1.0 - (1.0 - existing.confidence) * (1.0 - new.confidence)
```
При merge также: `data` — новые ключи перезаписывают, `evidence` — объединение с дедупликацией,
`observation_count` — суммируется, `last_seen` — берётся максимальное.

### Graph Query API (`knowledge/graph.py`)

| Метод | Описание |
|-------|----------|
| `add_entity(entity)` | Добавить entity; если ID уже есть — merge |
| `add_relation(relation)` | Добавить связь; дедупликация по `(source_id, target_id, type)` |
| `get(entity_id)` | Получить entity по ID |
| `query(entity_type, **filters)` | Фильтр entities по типу и data-полям |
| `neighbors(entity_id, relation_type)` | Исходящие связи (FROM entity) |
| `reverse_neighbors(entity_id, relation_type)` | Входящие связи (TO entity) |
| `hosts()` / `services()` / `endpoints()` / `technologies()` / `findings()` | Shortcut-методы |
| `record_execution(fingerprint)` / `was_executed(fingerprint)` | Трекинг выполнений |
| `to_targets()` | Конвертация Host entities -> list[Target] |

### KnowledgeState — delta-tracking wrapper (`knowledge/state.py`)

Обёртка над `KnowledgeGraph`, отслеживающая delta при каждом apply:

```python
state = KnowledgeState(graph, planner)
outcome = state.apply_observation(obs)
# -> ObservationOutcome(entity_id, was_new, confidence_before, confidence_after)

snapshot = state.snapshot(step=5, elapsed=42.0, gap_count=3)
# -> ContextSnapshot(entity_count, relation_count, host_count, ...)

gaps = state.find_gaps()  # делегирует в planner.find_gaps(graph)
```

### KnowledgeStore — SQLite persistence (`knowledge/store.py`)

Две таблицы: `kg_entities` и `kg_relations`. Entity сохранение через upsert.
Загрузка: `store.load() -> KnowledgeGraph`.

---

## Observation Bridge

Мост между плагинами (`PluginResult`) и knowledge graph (`Entity`/`Relation`).

### Модель Observation (`observations/observation.py`)

```python
class Observation(BaseModel):
    entity_type: EntityType
    entity_data: dict[str, Any]
    key_fields: dict[str, str]       # ключевые поля для Entity.make_id()
    relation: Relation | None        # связь с родительским entity
    evidence: str = ""
    confidence: float = 1.0
    source_plugin: str = ""
    timestamp: datetime
```

### Маппинг data keys -> Entity + Relation (`observations/adapter.py`)

`adapt_result(result)` обрабатывает все ключи из `result.data`:

| Data Key | Entity Type | Relation |
|----------|-------------|----------|
| *(всегда)* | HOST | — |
| `open_ports` | SERVICE | EXPOSES (HOST->SERVICE) |
| `services` | SERVICE | EXPOSES (HOST->SERVICE) |
| `technologies` | TECHNOLOGY | RUNS (HOST->TECHNOLOGY) |
| `cms` | TECHNOLOGY (`is_cms=True`) | RUNS |
| `waf` | TECHNOLOGY (`is_waf=True`) | RUNS |
| `subdomains` | HOST (`type="subdomain"`) | PARENT_OF |
| `crawled_urls` / `found_paths` / `urls` | ENDPOINT | HAS_ENDPOINT |
| `api_endpoints` | ENDPOINT (`is_api=True`) | HAS_ENDPOINT |
| `upload_endpoints` | ENDPOINT (`is_upload=True`) | HAS_ENDPOINT |
| `forms` | ENDPOINT | HAS_ENDPOINT |
| `credentials` | CREDENTIAL | ACCESSES (CREDENTIAL->HOST) |
| `ssl_info` / `records` | HOST (enriched) | — |
| `result.findings` | FINDING | RELATES_TO (FINDING->HOST) |

### Полный pipeline данных

```
Plugin.run() -> PluginResult
    -> adapt_result(result) -> list[Observation]
        -> KnowledgeState.apply_observation(obs) -> ObservationOutcome
            -> Entity в граф (add/merge)
            -> Relation в граф (add/dedup)
```

---

## Capabilities и Scoring

### Модель Capability (`capabilities/capability.py`)

```python
class Capability(BaseModel):
    name: str                              # display name
    plugin_name: str                       # имя плагина в registry
    category: str                          # PluginCategory
    requires_knowledge: list[str] = []     # что нужно в графе для запуска
    produces_knowledge: list[str] = []     # что плагин добавит в граф
    cost_score: float = 1.0               # 1-10
    noise_score: float = 1.0              # 1-10
    execution_time_estimate: float = 10.0  # секунды
```

### Синтаксис requires_knowledge

| Паттерн | Значение | Пример плагинов |
|---------|----------|-----------------|
| `"Host"` | Нужен любой хост | dns_enum, whois |
| `"Service:http"` | Нужен HTTP-сервис | tech_detect, http_headers |
| `"Service:ssh"` | Нужен SSH-сервис | ssh_brute |
| `"Endpoint:params"` | Endpoint с параметрами | sqli_check, xss_check |
| `"Technology:waf"` | Обнаружен WAF | waf_bypass |
| `"Technology:cms"` | Обнаружена CMS | wp_deep_scan |
| `"Credential"` | Найдены credentials | credential_spray |

### CAPABILITY_MAP (`capabilities/mapping.py`)

138 плагинов явно маппятся. Для остальных — auto-inference из `PluginMeta`:
- `requires`: `["Host"]` + `"Service:http"` если `meta.requires_http`
- `produces`: из `meta.produces` или `["Finding"]`
- `cost_score`: `min(meta.timeout / 10.0, 10.0)`
- `noise_score`: из `meta.risk_level`

### Формула скоринга (`scoring/scorer.py`)

```
priority = (novelty * knowledge_gain + unlock_value + prior_bonus) / (cost + noise + repetition_penalty)
```

| Компонент | Формула |
|-----------|---------|
| `novelty` | `1.0 / (1.0 + (observation_count - 1) * 0.3)` |
| `knowledge_gain` | `len(produces) * (1.0 - confidence)`, min 0.1 |
| `unlock_value` | `count_unlockable_paths() * 0.3` — будущая ценность от attack paths |
| `prior_bonus` | Campaign-aware: 0.15 для известной инфры, `tech_rate * 0.2` для стека |
| `cost` | `cap.cost_score` (1-10), campaign/cost_tracker adjusted |
| `noise` | `cap.noise_score` (1-10) |
| `repetition_penalty` | Adaptive из History или binary 5.0 из графа |

**Cost sources** (приоритет):
1. `CostTracker` — runtime plugin statistics (текущий аудит)
2. `CampaignMemory` — cross-audit learned cost (если нет CostTracker)
3. `cap.cost_score` — статический cost из capability map (fallback)

**Adaptive repetition penalty** (с History):
```
penalty = base_penalty * time_decay * (unproductive_multiplier if unproductive else 1.0)
```

### Добавление маппинга для нового плагина

В `capabilities/mapping.py` добавить в `CAPABILITY_MAP`:
```python
"my_plugin": {
    "requires": ["Host", "Service:http"],
    "produces": ["Finding", "Vulnerability"],
    "cost": 3.0,
    "noise": 2.0,
},
```

---

## Gap Detection — Planner

Planner (`orchestrator/planner.py`) анализирует knowledge graph и обнаруживает пробелы
в знаниях — `KnowledgeGap(entity, missing, priority, description)`.

### 12 правил обнаружения gaps

| # | Правило | missing | Приоритет | Условие |
|---|---------|---------|-----------|---------|
| 1 | `_host_without_services` | `"services"` | **10.0** | Host без EXPOSES-связей |
| 2 | `_host_without_dns` | `"dns"` | **8.0** | Host без `dns_records`, type != "ip" |
| 3 | `_http_service_without_tech` | `"technology"` | **7.0** | HTTP-хост без RUNS-связей |
| 4 | `_http_service_without_endpoints` | `"endpoints"` | **6.0** | HTTP-хост без HAS_ENDPOINT |
| 5 | `_http_endpoints_without_forms` | `"forms"` | **5.5** | HTTP-хост с endpoints, но без `forms_checked` |
| 6 | `_endpoint_without_testing` | `"vulnerability_testing"` | **5.0** | Endpoint с `has_params`/`is_api`/`scan_path` |
| 7 | `_http_host_without_vuln_testing` | `"host_vulnerability_testing"` | **4.5** | HTTP-хост (каждый step, dedup через fingerprints) |
| 8 | `_service_without_exploitation` | `"service_exploitation"` | **6.5** | Non-HTTP сервис без `service_tested` |
| 9 | `_credential_without_exploitation` | `"credential_exploitation"` | **7.5** | Существует Credential |
| 10 | `_technology_without_version` | `"version"` | **4.0** | Technology без `version` |
| 11 | `_low_confidence_entity` | `"confirmation"` | **3.0** | Entity с `confidence < 0.5` |
| 12 | `_attack_path_gaps` | `"attack_path"` | **path.risk** | Attack path preconditions met, actions available |

### Gap satisfaction flags

| Флаг | Предотвращает повторное срабатывание | Устанавливается когда |
|------|--------------------------------------|----------------------|
| `services_checked` | `_host_without_services` | Плагин produces "Service" |
| `tech_checked` | `_http_service_without_tech` | Плагин produces "Technology" |
| `endpoints_checked` | `_http_service_without_endpoints` | Плагин produces "Endpoint" |
| `forms_checked` | `_http_endpoints_without_forms` | form_analyzer / web_crawler / link_extractor |
| `version_checked` | `_technology_without_version` | Плагин produces для TECHNOLOGY |

---

## Selector и механика цикла

### Selector.match() (`orchestrator/selector.py`)

Для каждого gap перебирает capabilities и проверяет:
1. **produces_match**: capability производит то, что требует gap
2. **requirements_met**: prerequisites удовлетворены графом
3. **IP/domain exclusion**: domain-only плагины не запускаются на IP/localhost
4. **Dedup**: один `(plugin, target)` не дублируется

### Selector.pick() — выбор батча

Greedy top-N с дедупликацией:
- Для `ENDPOINT`: ключ = `(plugin_name, host)` — один pentesting-плагин на хост
- Для остальных: ключ = `(plugin_name, entity.id)`
- Budget = `safety.batch_size` (default 5)

### Пошаговый lifecycle итерации

```
 1. safety.can_continue(step)          -> проверка лимитов
 2. state.find_gaps()                  -> обнаружение knowledge gaps
 3. selector.match(gaps, graph)        -> поиск кандидатов
 4. scorer.rank(candidates)            -> скоринг
 5. filter: was_executed + cooldown    -> отсечение выполненных
 6. selector.pick(scored, budget)      -> выбор батча (greedy top-N)
 7. for each chosen:
    a. _build_decision()              -> Decision ДО выполнения
    b. history.record(decision)       -> запись в memory
    c. emit DECISION_MADE event
    d. graph.record_execution(fp)     -> fingerprint
    e. create async task              -> executor.execute(cap, entity, graph)
 8. asyncio.gather(*tasks)            -> параллельное выполнение
 9. for each result:
    a. state.apply_observation(obs)   -> обновление графа
    b. emit ENTITY events
    c. update decision outcome
10. _mark_gap_satisfied(sc)           -> satisfaction flags
11. emit STEP_COMPLETED event
```

---

## Decision Tracing

### Decision model (`decisions/decision.py`)

**Pre-execution** (заполняются ДО запуска плагина):
- `id` — SHA256(step:timestamp:plugin:target)[:16]
- `step`, `goal` (gap.missing), `goal_priority`, `triggering_entity_id`
- `context` — ContextSnapshot (entity_count, relation_count, host/service/finding_count, gap_count)
- `evaluated_options` — все кандидаты (max 20) с score_breakdown
- `chosen_capability`, `chosen_plugin`, `chosen_target`, `chosen_score`
- `reasoning_trace` — "Gap: X. Selected Y (score=Z) from N candidates."

**Post-execution** (заполняются ПОСЛЕ):
- `outcome_observations`, `outcome_new_entities`, `outcome_confidence_delta`, `outcome_duration`
- `was_productive` — new_entities > 0 or confidence_delta > 0.01

### History — decision memory (`memory/history.py`)

- `record(decision)` — запись решения
- `update_outcome(decision_id, ...)` — обновление post-execution полей
- `repetition_penalty(plugin, entity_id)` — adaptive penalty
- `save(path)` / `load(path)` — JSON persistence (`decision_history.json`)

### EventBus — 9 типов событий (`events/bus.py`)

| EventType | Когда |
|-----------|-------|
| `ENTITY_CREATED` | Новый entity добавлен в граф |
| `ENTITY_UPDATED` | Entity обновлён (merge) |
| `OBSERVATION_APPLIED` | Observation применён к графу |
| `PLUGIN_STARTED` / `PLUGIN_FINISHED` | Начало/конец выполнения плагина |
| `GAP_DETECTED` | Обнаружены knowledge gaps |
| `STEP_COMPLETED` | Шаг цикла завершён |
| `DECISION_MADE` | Принято решение о запуске |

### SafetyLimits (`orchestrator/safety.py`)

```python
class SafetyLimits(BaseModel):
    max_steps: int = 100
    max_duration_seconds: float = 3600.0    # 1 час
    batch_size: int = 5
    cooldown_per_capability: float = 0.0
```

### Timeline (`orchestrator/timeline.py`)

Структурированный лог: `TimelineEntry` с step, timestamp, capability, target_entity,
knowledge_gained, confidence_delta, duration. `summary()` -> human-readable лог.

---

## Campaign Memory (v3.2)

Persistent cross-audit learning. Запоминает инфраструктуру, эффективность плагинов и
технологические стеки между аудитами. Opt-in, по умолчанию выключена.

### Хранилище

```
~/.basilisk/campaigns/campaign.db     ← SQLite (WAL mode)
├── target_profiles   (per-host)      ← запомненные сервисы, технологии, findings
├── plugin_efficacy   (global)        ← per-plugin success rates с tech-stack breakdown
└── tech_fingerprints (per-domain)    ← паттерны технологий по организациям
```

### Модели (`campaign/models.py`)

| Модель | Ключ | Назначение |
|--------|------|-----------|
| `TargetProfile` | `host` | Сервисы, технологии, endpoints, findings per host |
| `PluginEfficacy` | `plugin_name` | Success rate, new entities, runtime, tech_stack_stats |
| `TechFingerprint` | `base_domain` | Технологии по организации (nginx, php, wordpress) |

### Интеграция со Scorer

- **Campaign cost**: `adjusted_cost()` → discount для проверенных плагинов, penalty для бесполезных
- **Prior bonus**: 0.15 для известной инфраструктуры (host+port), `tech_rate * 0.2` для стека
- Приоритет: CostTracker > CampaignMemory > static cost_score

### Активация

```bash
basilisk auto example.com --campaign          # CLI
```
```python
Audit("example.com").autonomous().enable_campaign().run()  # API
```
```yaml
campaign:
  enabled: true                              # config YAML
```

---

## Классический Pipeline

Pipeline (`core/pipeline.py`) — последовательное выполнение плагинов по фазам.

### Фазы
- **По умолчанию** (4): `recon -> scanning -> analysis -> pentesting`
- **Offensive** (10): + `exploitation, post_exploit, privesc, lateral, crypto, forensics`

### Порядок выполнения
1. Топологическая сортировка (Kahn's algorithm, `depends_on`)
2. Recon расширяет target scope (subdomains -> новые цели)
3. Каждая фаза: resolve_order -> run_batch -> emit findings -> save to DB

### Inter-phase intelligence injection

| После фазы | Инъекция | Что делает |
|-------------|----------|------------|
| `recon` | `_inject_crawl_data()` | `ctx.state["crawled_urls"]`, `ctx.state["discovered_forms"]` |
| `recon` | `_check_http_reachability()` | HEAD-проверка хостов -> `ctx.state["http_scheme"]` |
| `analysis` | `_inject_waf_data()` | `ctx.state["waf_map"]` |
| `analysis` | `_inject_api_paths()` | `ctx.state["discovered_api_paths"]` |

---

## Базы сигнатур

| База | Файл | Кол-во | Аналог |
|------|------|--------|--------|
| TECH_FINGERPRINTS | data/fingerprints.py | 594 | Wappalyzer top-500 |
| _VULNERABLE_VERSIONS | analysis/version_detect.py | 200+ | retire.js |
| WAF_SIGNATURES | analysis/waf_detect.py | 125 | wafw00f 100+ |
| CMS_SIGNATURES | analysis/cms_detect.py | 83 | WPScan/CMSmap |
| TAKEOVER_FINGERPRINTS | data/fingerprints.py | 80 | can-i-take-over-xyz |
| CSP_BYPASS_DOMAINS | data/fingerprints.py | 52 | Google CSP Evaluator |
| KNOWN_FAVICONS + MMH3 | analysis/favicon_hash.py | 300+ | Shodan |
| SQLi payloads | utils/payloads.py | 489 | sqlmap |
| SSTI probes | pentesting/ssti_*.py | 32 + 48 | tplmap |
| SSRF bypasses | pentesting/ssrf_check.py | 40 + 31 | — |
| XSS payloads | pentesting/xss_*.py | 35 + 49 DOM | XSStrike/Dalfox |
| NoSQLi payloads | pentesting/nosqli_check.py | 92 | — |
| Command injection | pentesting/command_injection.py | 90 | commix |
| JWT attacks | pentesting/jwt_attack.py | 18 + 60 + 17 | — |
| HTTP smuggling | pentesting/http_smuggling.py | 45 | — |
| Default credentials | pentesting/default_creds.py | 75 | — |
| WP plugins/themes | pentesting/wp_deep_scan.py | 86 + 52 | WPScan |
