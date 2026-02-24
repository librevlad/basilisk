# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Проект

**Basilisk v4.0.0** — профессиональный модульный фреймворк безопасности для разведки, анализа и пентеста доменов. Автономный движок на knowledge graph с детерминированными decision traces. Unified v4 execution path: ScenarioRegistry (188 legacy-wrapped + 5 native scenarios), ScenarioExecutor, KG persistence. SQLite-хранилище для миллионов записей. Persistent campaign memory для кросс-аудитного обучения. Container security audit подсистема. Cognitive reasoning: hypothesis engine + evidence fusion + belief revision. Training validation для бенчмаркинга. Actor-based network abstraction.

Философия: сделать с хакерскими утилитами то, что Laravel сделал с Symfony — элегантные абстракции поверх мощных инструментов.

## Быстрые команды

```bash
# Тесты
.venv/Scripts/python.exe -m pytest tests/ -v              # все 1974 теста
.venv/Scripts/python.exe -m pytest tests/test_plugins/ -v  # только плагины
.venv/Scripts/python.exe -m pytest tests/ -x --tb=short    # до первого падения

# Линтинг
.venv/Scripts/python.exe -m ruff check basilisk/ tests/
.venv/Scripts/python.exe -m ruff check . --fix

# Запуск
.venv/Scripts/python.exe -m basilisk auto example.com                # автономный аудит (основной)
.venv/Scripts/python.exe -m basilisk auto example.com -n 50          # с лимитом шагов
.venv/Scripts/python.exe -m basilisk auto example.com --campaign     # с campaign memory
.venv/Scripts/python.exe -m basilisk run ssl_check example.com       # один плагин
.venv/Scripts/python.exe -m basilisk plugins                         # список плагинов
.venv/Scripts/python.exe -m basilisk scenarios                        # все scenarios (native + legacy)
.venv/Scripts/python.exe -m basilisk scenarios --native               # только native v4 scenarios
.venv/Scripts/python.exe -m basilisk train profile.yaml              # training validation
.venv/Scripts/python.exe -m basilisk crack <hash>                    # hash identification + crack

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
- **Typer + Rich** — CLI
- **cryptography** — парсинг SSL-сертификатов
- **uv** — менеджер пакетов
- **ruff** — линтинг (py312, line-length 100)
- **pytest + pytest-asyncio** — тестирование (asyncio_mode = auto)

## Архитектура

```
basilisk/
├── __init__.py                    # версия, Basilisk class (fluent API)
├── __main__.py                    # python -m basilisk
├── cli.py                         # Typer CLI: auto, run, plugins, train, crack, version
├── config.py                      # Pydantic Settings + YAML
│
├── domain/                        # [v4] Typed domain models
│   ├── target.py                  # BaseTarget (ABC), LiveTarget, TrainingTarget, ExpectedFinding
│   ├── scenario.py                # Scenario (ABC), ScenarioMeta, ScenarioResult
│   ├── surface.py                 # Surface — discovered audit surface
│   └── finding.py                 # Finding, Proof — structured vulnerability report
│
├── actor/                         # [v4] Network abstraction layer
│   ├── base.py                    # ActorProtocol — runtime-checkable protocol
│   ├── composite.py               # CompositeActor (HTTP + DNS + Net + Browser)
│   ├── http_actor.py              # HTTP-only actor
│   └── recording.py               # Record/replay actor for testing
│
├── engine/                        # [v4] Execution engine
│   ├── scenario_registry.py       # ScenarioRegistry: discover native + wrap legacy
│   ├── target_loader.py           # TargetLoader: CLI/API specs → Target objects
│   └── autonomous/
│       └── runner.py              # AutonomousRunner: wraps orchestrator, returns RunResult
│
├── bridge/                        # [v4] v3 → v4 compatibility layer
│   ├── legacy_scenario.py         # LegacyPluginScenario: wraps BasePlugin as Scenario
│   ├── context_adapter.py         # ContextAdapter: Actor → PluginContext bridge
│   └── result_adapter.py          # ResultAdapter: PluginResult → Finding/Surface
│
├── scenarios/                     # [v4] Native v4 scenario implementations
│   ├── recon/dns_scenario.py      # DNS enumeration
│   ├── scanning/port_scenario.py  # Port scanning
│   ├── scanning/ssl_scenario.py   # SSL/TLS analysis
│   ├── pentesting/sqli_scenario.py # SQL injection
│   └── pentesting/xss_scenario.py  # XSS scanning
│
├── verification/                  # [v4] Finding verification engine
│   ├── confidence.py              # ConfidenceCalculator: multi-source confidence merging
│   ├── confirmer.py               # FindingConfirmer: suggest verification plugins
│   └── revalidator.py             # FindingRevalidator: coordinate re-testing
│
├── training/                      # [v4] Training validation
│   ├── profile.py                 # TrainingProfile: expected findings + auth config
│   ├── runner.py                  # TrainingRunner: autonomous loop vs known targets
│   ├── validator.py               # FindingTracker, ValidationReport
│   ├── planner_wrapper.py         # TrainingPlanner: tracks gap detection accuracy
│   └── scorer_wrapper.py          # TrainingScorer: tracks ranking accuracy
│
├── models/                        # Pydantic-модели (v3 contracts, used by plugins)
│   ├── target.py                  # Target, TargetScope, TargetType
│   ├── result.py                  # PluginResult, Finding, Severity
│   └── types.py                   # DnsRecord, SslInfo, PortInfo, HttpInfo, WhoisInfo
│
├── core/                          # Plugin infrastructure
│   ├── plugin.py                  # BasePlugin ABC, PluginMeta, PluginCategory
│   ├── registry.py                # PluginRegistry: discover + topo sort (Kahn's)
│   ├── executor.py                # AsyncExecutor + PluginContext (DI-контейнер)
│   ├── providers.py               # ProviderPool: стратегии all/first/fastest
│   ├── auth.py                    # AuthManager, FormLoginStrategy
│   └── callback.py                # OOB CallbackServer
│
├── knowledge/                     # Knowledge Graph
│   ├── entities.py                # Entity, EntityType — типизированные узлы
│   ├── relations.py               # Relation, RelationType — типизированные связи
│   ├── graph.py                   # KnowledgeGraph: dedup, merge, query, neighbors
│   ├── state.py                   # KnowledgeState: delta-tracking wrapper
│   ├── store.py                   # KnowledgeStore: SQLite persistence
│   └── vulns/
│       ├── definitions.yaml       # 100+ vulnerability type definitions (CWE/OWASP)
│       └── registry.py            # VulnRegistry: loads/queries vuln definitions
│
├── observations/                  # PluginResult → Observation мост
│   ├── observation.py             # Observation model
│   └── adapter.py                 # adapt_result(): PluginResult → list[Observation]
│
├── capabilities/                  # Маппинг плагинов на capabilities
│   ├── capability.py              # Capability model + ActionType enum
│   └── mapping.py                 # CAPABILITY_MAP + build_capabilities_from_scenarios()
│
├── reasoning/                     # Cognitive reasoning primitives
│   ├── hypothesis.py              # HypothesisEngine: 5 pattern detectors, evidence tracking
│   └── belief.py                  # EvidenceAggregator: source-family independence, belief revision
│
├── decisions/                     # Decision tracing
│   └── decision.py                # Decision, ContextSnapshot, EvaluatedOption
│
├── memory/                        # Decision memory
│   └── history.py                 # History: decision log, repetition penalty, persistence
│
├── scoring/                       # Scoring engine
│   └── scorer.py                  # Scorer: multi-component formula + hypothesis_gain + action_type_bonus
│
├── orchestrator/                  # Автономный движок (internal, wrapped by engine/)
│   ├── planner.py                 # Planner: 18 правил обнаружения knowledge gaps
│   ├── selector.py                # Selector: match gaps → capabilities, pick batch
│   ├── executor.py                # OrchestratorExecutor: обёртка над core executor (legacy)
│   ├── scenario_executor.py       # [v4] ScenarioExecutor: dispatches to scenarios (active path)
│   ├── loop.py                    # AutonomousLoop: цикл + decision tracing + KnowledgeState
│   ├── goals.py                   # GoalEngine: 5-goal progression, success_probability
│   ├── attack_paths.py            # Multi-step attack path scoring
│   ├── cost_tracker.py            # Runtime plugin cost learning
│   ├── coverage_tracker.py        # [v4] Per-host, per-vuln-category coverage tracking
│   ├── safety.py                  # SafetyLimits: max_steps, max_duration, cooldown
│   └── timeline.py                # Timeline: структурированный лог выполнения
│
├── campaign/                      # Persistent campaign memory
│   ├── models.py                  # TargetProfile, PluginEfficacy, TechFingerprint
│   ├── store.py                   # CampaignStore: async SQLite (3 tables, WAL mode)
│   ├── memory.py                  # CampaignMemory: in-memory aggregator, scorer query API
│   └── extractor.py               # Extract profiles/efficacy/fingerprints from KG
│
├── events/                        # Event Bus
│   └── bus.py                     # EventBus: subscribe/emit + 14 event types
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
└── plugins/                       # 188 плагинов (auto-discover)
    ├── recon/        (23)         # dns_enum, subdomain_*, whois, reverse_ip, ...
    ├── scanning/     (19)         # port_scan, ssl_check, service_detect, ...
    ├── analysis/     (23)         # http_headers, tech_detect, takeover_check, ...
    ├── pentesting/   (60)         # git_exposure, dir_brute, sqli_*, xss_*, ...
    ├── exploitation/ (23)         # cors_exploit, graphql_exploit, ...
    ├── crypto/        (8)         # hash_crack, padding_oracle, weak_random, ...
    ├── lateral/      (12)         # service_brute, ssh_brute, credential_spray, ...
    ├── privesc/       (7)         # suid_finder, kernel_suggest, ...
    ├── post_exploit/  (7)         # data_exfil, persistence_check, ...
    └── forensics/     (6)         # log_analyzer, memory_dump, ...

wordlists/bundled/                 # 6 словарей
training_profiles/                 # YAML profiles for training validation

tests/                             # 1974 теста, 90+ файлов
├── test_models/                   # 43 теста
├── test_core/                     # 167 тестов
├── test_plugins/                  # 345 тестов (188 плагинов покрыты)
├── test_utils/                    # 212 тестов
├── test_storage/                  # 14 тестов
├── test_knowledge/                # 71 тест (entities, graph, state, store, vulns)
├── test_observations/             # 43 теста (adapter, container adapter)
├── test_capabilities/             # 36 тестов (mapping, container capabilities)
├── test_decisions/                # 12 тестов (decision model)
├── test_memory/                   # 19 тестов (history, repetition penalty)
├── test_scoring/                  # 22 теста (scorer + breakdown + multistep)
├── test_orchestrator/             # 111 тестов (loop, planner, selector, safety, goals, coverage)
├── test_events/                   # 5 тестов (bus)
├── test_campaign/                 # 61 тест (models, store, memory, extractor, integration)
├── test_reasoning/                # 42 теста (hypothesis engine, evidence aggregator)
├── test_actor/                    # [v4] 3 теста (composite, http, recording)
├── test_bridge/                   # [v4] 3 теста (legacy scenario, context/result adapters)
├── test_domain/                   # [v4] 4 теста (target, scenario, finding, surface)
├── test_engine/                   # [v4] 3 теста (scenario registry, target loader, runner)
├── test_scenarios/                # [v4] 5 тестов (dns, port, ssl, sqli, xss)
├── test_training/                 # [v4] 5 тестов (planner/scorer wrappers, profile, validator)
├── test_verification/             # [v4] 3 теста (confidence, confirmer, revalidator)
└── test_cli.py, test_config.py    # 24 теста

examples/                          # Примеры использования
config/default.yaml                # Конфиг по умолчанию
```

## Ключевые паттерны

### Basilisk Class (fluent API)
```python
from basilisk import Basilisk

# Автономный аудит (основной способ)
result = await Basilisk("example.com").run()
result = await Basilisk("example.com", max_steps=50).run()
result = await Basilisk("10.10.10.1", "10.10.10.2").run()

# С campaign memory
result = await Basilisk("example.com").campaign().run()

# С фильтрацией плагинов
result = await Basilisk("example.com").plugins("sqli_*", "xss_*").exclude("heavy_*").run()

# С callbacks
result = await Basilisk("example.com").on_finding(callback).on_step(callback).run()
```

### Плагинная система
- Каждый плагин = файл в `plugins/<category>/`, класс наследует `BasePlugin`, имеет `meta: ClassVar[PluginMeta]` и `async def run(target, ctx) -> PluginResult`
- Автообнаружение через `pkgutil` + `importlib` в `PluginRegistry.discover()`
- Зависимости (`depends_on`) разрешаются топологической сортировкой (Kahn's algorithm)
- `provides` поле для мультипровайдеров (напр. 10 плагинов `provides="subdomains"`)
- `default_enabled=False` для тяжёлых плагинов (subdomain_bruteforce)
- Все 188 плагинов автоматически оборачиваются как v4 Scenarios через `bridge/legacy_scenario.py`

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
- `ctx.emit(finding, target_host)` — callback для live-feed
- `ctx.should_stop` — True когда < 2с до таймаута, плагин должен вернуть partial result

### Actor Protocol (v4)
Protocol-based interface для всех сетевых операций. Все v4 Scenarios зависят от `ActorProtocol`, а не от конкретных реализаций.
- `CompositeActor` — полный actor (HTTP + DNS + Net + Browser)
- `HttpActor` — минимальный HTTP-only actor
- `RecordingActor` — record/replay для детерминированного тестирования

### Автономный движок
- `KnowledgeGraph` — in-memory граф с 9 entity types, 11 relation types, dedup, confidence merge, decay, hypothesis storage
- `KnowledgeState` — delta-tracking wrapper, `apply_observation()` → `ObservationOutcome` (+ source_family)
- `Planner` — 18 правил обнаружения gaps (host_without_services, container_*, attack_paths, hypothesis_validation, ...)
- `Selector` — match gaps → capabilities, pick batch (budget-constrained)
- `Scorer` — формула + `score_breakdown` dict + campaign-aware cost + prior_bonus + hypothesis_gain + action_type_bonus
- `GoalEngine` — 5-goal progression + `goal_progress_delta()`
- `HypothesisEngine` — 5 pattern detectors, hypothesis lifecycle, resolution_gain scoring
- `EvidenceAggregator` — source-family independence, contradiction penalty, per-step belief revision
- `AttackPaths` — multi-step exploit chain scoring, unlock_value, container_exploitation path
- `CostTracker` — runtime plugin success/failure statistics, adaptive cost adjustment
- `CoverageTracker` — [v4] per-host, per-vuln-category tracking (VulnCategoryStatus)
- `CampaignMemory` — persistent cross-audit learning (SQLite, opt-in)
- `Decision` — полная запись: context snapshot, evaluated options, reasoning trace, outcome + hypothesis context
- `History` — лог решений, repetition penalty (decay + unproductive multiplier), JSON persistence
- `AutonomousLoop` — seed → find_gaps → match → score → **build decision** → execute → apply → **hypothesize** → **revise beliefs** → repeat
- `SafetyLimits` — max_steps, max_duration_seconds, batch_size, cooldown tracking
- `adapter.py` — конвертация `PluginResult` → `list[Observation]` → entities/relations в граф
- `mapping.py` — все 188 плагинов маппятся на requires/produces/cost/noise/action_type/expected_state_delta

### v4 Layers

```
CLI (cli.py) / Basilisk class (__init__.py)
    ↓
Engine (engine/autonomous/runner.py)
    ↓  ScenarioRegistry + ScenarioExecutor (v4 active path)
Orchestrator (loop, planner, selector, scorer)
    ↓
Scenarios (scenarios/ 5 native + bridge/legacy_scenario.py 188 wrapped)
    ↓  depend on ActorProtocol
Actor (actor/ — CompositeActor, RecordingActor, ...)
    ↓
Knowledge Graph + Verification + Training + KG Persistence (knowledge.db)
```

### Storage (SQLite WAL)
- PRAGMA: journal_mode=WAL, synchronous=NORMAL, cache_size=-65536, mmap_size=2GB
- Таблицы: domains, scan_runs, findings, plugin_data, kg_entities, kg_relations
- Bulk insert батчами по 1000 записей
- KnowledgeStore сохраняет knowledge graph в SQLite после автономного прогона

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
- Тесты плагинов: meta + discovery + функциональные mock-тесты для всех плагинов
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
`plugins`, `orchestrator`, `knowledge`, `cli`, `storage`, `utils`, `models`, `core`,
`scoring`, `observations`, `capabilities`, `decisions`, `memory`, `events`, `config`,
`campaign`, `reasoning`, `actor`, `bridge`, `domain`, `engine`, `scenarios`,
`verification`, `training`

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
git tag -a v4.0.0 -m "v4.0.0"
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

Автономный движок — единственный режим работы Basilisk. Он строит
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
             Host         │  │ 18 gap  │    │ match +  │    │ rank by   │  │
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

---

## Knowledge Graph

Центральное хранилище всей информации о целях аудита. Типизированные узлы (Entity) и
связи (Relation) образуют граф, который обогащается с каждой итерацией автономного цикла.

### EntityType — 9 типов узлов

| EntityType | Key Fields (для make_id) | Типичные data fields | Factory method |
|-----------|-------------------------|---------------------|---------------|
| `HOST` | `host` | `host`, `type`, `dns_records`, `ssl_info` | `Entity.host("example.com")` |
| `SERVICE` | `host`, `port`, `protocol` | `host`, `port`, `protocol`, `service`, `banner` | `Entity.service("example.com", 443, "tcp")` |
| `ENDPOINT` | `host`, `path` | `host`, `path`, `has_params`, `is_api`, `is_upload`, `is_graphql`, `is_admin`, `scan_path` | `Entity.endpoint("example.com", "/api/v1")` |
| `TECHNOLOGY` | `host`, `name`, `version` | `host`, `name`, `version`, `is_cms`, `is_waf`, `is_container_runtime` | `Entity.technology("example.com", "nginx", "1.24")` |
| `CREDENTIAL` | `host`, `username` | `host`, `username`, `password`, `source` | `Entity.credential("example.com", "admin")` |
| `FINDING` | `host`, `title` | `host`, `title`, `severity`, `description`, `evidence` | `Entity.finding("example.com", "XSS in /search")` |
| `VULNERABILITY` | `host`, `name` | `host`, `name`, `severity`, `cve` | `Entity.vulnerability("example.com", "CVE-2024-1234")` |
| `CONTAINER` | `host`, `container_id` | `host`, `container_id`, `image`, `privileged`, `mounts`, `capabilities` | `Entity.container("example.com", "abc123")` |
| `IMAGE` | `host`, `image_name`, `image_tag` | `host`, `image_name`, `image_tag` | `Entity.image("example.com", "nginx", "1.24")` |

### RelationType — 11 типов связей

| RelationType | Семантика | Направление | Пример |
|-------------|-----------|-------------|--------|
| `EXPOSES` | Хост предоставляет сервис | HOST -> SERVICE | example.com EXPOSES :443/tcp |
| `RUNS` | Сервис использует технологию | SERVICE -> TECHNOLOGY | :443 RUNS nginx/1.24 |
| `HAS_ENDPOINT` | Сервис имеет endpoint | SERVICE -> ENDPOINT | :443 HAS_ENDPOINT /api/v1 |
| `HAS_VULNERABILITY` | Технология имеет уязвимость | TECHNOLOGY -> VULNERABILITY | nginx HAS_VULNERABILITY CVE-... |
| `ACCESSES` | Credential даёт доступ | CREDENTIAL -> HOST | admin:pass ACCESSES example.com |
| `RELATES_TO` | Finding связан с entity | FINDING -> any | XSS RELATES_TO example.com |
| `PARENT_OF` | Домен является родителем | HOST -> HOST | example.com PARENT_OF sub.example.com |
| `RUNS_CONTAINER` | Runtime запускает контейнер | TECHNOLOGY -> CONTAINER | docker RUNS_CONTAINER abc123 |
| `USES_IMAGE` | Контейнер использует образ | CONTAINER -> IMAGE | abc123 USES_IMAGE nginx:1.24 |
| `SUPPORTED_BY` | Доказательство подтверждает гипотезу | ENTITY -> HYPOTHESIS | evidence supports hypothesis |
| `DISPROVED_BY` | Доказательство опровергает гипотезу | ENTITY -> HYPOTHESIS | evidence contradicts hypothesis |

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
| `hosts()` / `services()` / `endpoints()` / `technologies()` / `findings()` / `containers()` / `images()` | Shortcut-методы |
| `record_execution(fingerprint)` / `was_executed(fingerprint)` | Трекинг выполнений |
| `to_targets()` | Конвертация Host entities -> list[Target] |
| `add_hypothesis(hyp)` / `get_hypothesis(id)` | CRUD для гипотез |
| `active_hypotheses()` / `all_hypotheses()` | Запрос гипотез по статусу |
| `hypotheses_for_entity(entity_id)` | Гипотезы, связанные с entity |

### KnowledgeState — delta-tracking wrapper (`knowledge/state.py`)

Обёртка над `KnowledgeGraph`, отслеживающая delta при каждом apply:

```python
state = KnowledgeState(graph, planner)
outcome = state.apply_observation(obs)
# -> ObservationOutcome(entity_id, was_new, confidence_before, confidence_after, source_family)

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
| `container_runtimes` | TECHNOLOGY (`is_container_runtime=True`) | RUNS (HOST->TECHNOLOGY) |
| `containers` | CONTAINER + IMAGE | RUNS_CONTAINER (TECHNOLOGY->CONTAINER), USES_IMAGE (CONTAINER->IMAGE) |
| `images` | IMAGE | — |
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
class ActionType(StrEnum):
    ENUMERATION = "enumeration"     # recon, scanning — discover new entities
    EXPERIMENT = "experiment"       # analysis, pentesting — test hypotheses
    EXPLOIT = "exploit"             # exploitation — needs confirmed vulnerability
    VERIFICATION = "verification"   # re-test to confirm/reject findings

class Capability(BaseModel):
    name: str                              # display name
    plugin_name: str                       # имя плагина в registry
    category: str                          # PluginCategory
    requires_knowledge: list[str] = []     # что нужно в графе для запуска
    produces_knowledge: list[str] = []     # что плагин добавит в граф
    cost_score: float = 1.0               # 1-10
    noise_score: float = 1.0              # 1-10
    execution_time_estimate: float = 10.0  # секунды
    reduces_uncertainty: list[str] = []    # knowledge confirmed
    risk_domain: str = "general"           # recon|web|network|auth|crypto|forensics|general
    action_type: ActionType = ENUMERATION  # what the capability does
    expected_state_delta: dict = {}        # predicted world change
```

### ActionType auto-inference (`capabilities/mapping.py`)

| Категория плагина | ActionType | Условие |
|-------------------|------------|---------|
| recon, scanning | ENUMERATION | По умолчанию |
| analysis, pentesting, crypto | EXPERIMENT | По умолчанию |
| exploitation, lateral, privesc, post_exploit | EXPLOIT | По умолчанию |
| любая | VERIFICATION | Если `reduces_uncertainty` не пуст (override) |

### Синтаксис requires_knowledge

| Паттерн | Значение | Пример плагинов |
|---------|----------|-----------------|
| `"Host"` | Нужен любой хост | dns_enum, whois |
| `"Service:http"` | Нужен HTTP-сервис | tech_detect, http_headers |
| `"Service:ssh"` | Нужен SSH-сервис | ssh_brute |
| `"Endpoint:params"` | Endpoint с параметрами | sqli_check, xss_check |
| `"Technology:waf"` | Обнаружен WAF | waf_bypass |
| `"Technology:cms"` | Обнаружена CMS | wp_deep_scan |
| `"Technology:docker"` | Обнаружен Docker runtime | container_enumeration, registry_lookup |
| `"Container"` | Найден контейнер | container_config_audit, container_escape_probe |
| `"Image"` | Найден образ контейнера | image_fingerprint |
| `"Credential"` | Найдены credentials | credential_spray |

### CAPABILITY_MAP (`capabilities/mapping.py`)

145 плагинов явно маппятся. Для остальных — auto-inference из `PluginMeta`/`ScenarioMeta`:
- `requires`: `["Host"]` + `"Service:http"` если `meta.requires_http`
- `produces`: из `meta.produces` или `["Finding"]`
- `cost_score`: `min(meta.timeout / 10.0, 10.0)`
- `noise_score`: из `meta.risk_level`

### Формула скоринга (`scoring/scorer.py`)

```
priority = (novelty * knowledge_gain * success_prob + unlock_value + prior_bonus
            + hypothesis_gain + action_type_bonus) * gap_boost / (cost + noise + repetition_penalty)
```

| Компонент | Формула |
|-----------|---------|
| `novelty` | `1.0 / (1.0 + (observation_count - 1) * 0.3)` |
| `knowledge_gain` | `len(produces) * (1.0 - confidence)`, min 0.1 |
| `success_prob` | `GoalEngine.success_probability()` — вероятность успеха на текущей стадии |
| `unlock_value` | `count_unlockable_paths() * 0.3` — будущая ценность от attack paths |
| `prior_bonus` | Campaign-aware: 0.15 для известной инфры, `tech_rate * 0.2` для стека |
| `hypothesis_gain` | `HypothesisEngine.resolution_gain(plugin, entity_id)` — max 1.0 |
| `action_type_bonus` | Бонус за тип действия в текущем контексте (0.0-0.2) |
| `gap_boost` | `1.0 + gap.priority * 0.1` — множитель от приоритета gap |
| `cost` | `cap.cost_score` (1-10), campaign/cost_tracker adjusted |
| `noise` | `cap.noise_score` (1-10) |
| `repetition_penalty` | Adaptive из History или binary 5.0 из графа |

**hypothesis_gain**:
- 0.3 per matching `validation_plugins` in hypothesis
- 0.15 per matching `target_entity_ids`
- Higher when hypothesis is uncertain (confidence near 0.5)

**action_type_bonus**:
| ActionType | Условие | Бонус |
|------------|---------|-------|
| EXPERIMENT | `entity.confidence < 0.7` | +0.1 (предпочитать эксперименты при неопределённости) |
| EXPLOIT | `entity.confidence >= 0.8` | +0.15 (предпочитать эксплойты при подтверждённых данных) |
| VERIFICATION | severity high/critical | +0.2 (всегда ценно для опасных находок) |

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

### 18 правил обнаружения gaps

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
| 12 | `_finding_without_verification` | `"finding_verification"` | **6.0** | HIGH/CRITICAL finding, confidence < 0.95 |
| 13 | `_host_without_container_check` | `"container_runtime"` | **6.0** | Host с Docker/K8s портами (2375,2376,2377,5000,10250) или is_container_runtime tech |
| 14 | `_container_runtime_without_enumeration` | `"container_enumeration"` | **7.0** | Technology(is_container_runtime) без `containers_enumerated` |
| 15 | `_container_without_config_audit` | `"container_config_audit"` | **5.5** | Container без `config_audited` (1 gap per host) |
| 16 | `_container_without_image_analysis` | `"image_analysis"` | **5.0** | Image без `vulnerabilities_checked` |
| 17 | `_attack_path_gaps` | `"attack_path"` | **path.risk** | Attack path preconditions met, actions available |
| 18 | `_hypothesis_validation` | `"hypothesis_validation"` | **5.5** | Active hypothesis с confidence в [0.3, 0.7] |

### Gap satisfaction flags

| Флаг | Предотвращает повторное срабатывание | Устанавливается когда |
|------|--------------------------------------|----------------------|
| `services_checked` | `_host_without_services` | Плагин produces "Service" |
| `tech_checked` | `_http_service_without_tech` | Плагин produces "Technology" |
| `endpoints_checked` | `_http_service_without_endpoints` | Плагин produces "Endpoint" |
| `forms_checked` | `_http_endpoints_without_forms` | form_analyzer / web_crawler / link_extractor |
| `version_checked` | `_technology_without_version` | Плагин produces для TECHNOLOGY |
| `container_runtime_checked` | `_host_without_container_check` | Плагин produces "Technology:container_runtime" |
| `containers_enumerated` | `_container_runtime_without_enumeration` | Плагин produces "Container" на Technology(is_container_runtime) |
| `config_audited` | `_container_without_config_audit` | container_config_audit на Container |
| `vulnerabilities_checked` | `_container_without_image_analysis` | image_fingerprint на Image |

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
    a. state.apply_observation(obs)   -> обновление графа (+ source_family)
    b. emit ENTITY events
    c. update decision outcome
10. hypothesis_engine.generate_hypotheses(graph)  -> новые гипотезы
11. evidence_aggregator.record_evidence(...)      -> запись evidence per entity
12. evidence_aggregator.revise_beliefs()          -> belief revision
    - emit BELIEF_STRENGTHENED / BELIEF_WEAKENED
13. hypothesis_engine.update_from_observation()   -> обновление confidence гипотез
    - emit HYPOTHESIS_CONFIRMED / HYPOTHESIS_REJECTED
14. evidence_aggregator.reset_step()              -> сброс aggregator для след. шага
15. _mark_gap_satisfied(sc)           -> satisfaction flags
16. emit STEP_COMPLETED event
```

---

## Decision Tracing

### Decision model (`decisions/decision.py`)

**Pre-execution** (заполняются ДО запуска плагина):
- `id` — SHA256(step:timestamp:plugin:target)[:16]
- `step`, `goal` (gap.missing), `goal_priority`, `triggering_entity_id`
- `context` — ContextSnapshot (entity_count, relation_count, host/service/finding_count, gap_count, active_hypothesis_count, confirmed_hypothesis_count)
- `evaluated_options` — все кандидаты (max 20) с score_breakdown
- `chosen_capability`, `chosen_plugin`, `chosen_target`, `chosen_score`
- `reasoning_trace` — "Gap: X. Selected Y (score=Z) from N candidates."
- `related_hypothesis_ids` — гипотезы, связанные с target entity
- `hypothesis_resolution_gain` — ожидаемый вклад в разрешение гипотез (0.0-1.0)
- `action_type` — тип действия capability (enumeration/experiment/exploit/verification)

**Post-execution** (заполняются ПОСЛЕ):
- `outcome_observations`, `outcome_new_entities`, `outcome_confidence_delta`, `outcome_duration`
- `was_productive` — new_entities > 0 or confidence_delta > 0.01

### History — decision memory (`memory/history.py`)

- `record(decision)` — запись решения
- `update_outcome(decision_id, ...)` — обновление post-execution полей
- `repetition_penalty(plugin, entity_id)` — adaptive penalty
- `save(path)` / `load(path)` — JSON persistence (`decision_history.json`)

### EventBus — 14 типов событий (`events/bus.py`)

| EventType | Когда |
|-----------|-------|
| `ENTITY_CREATED` | Новый entity добавлен в граф |
| `ENTITY_UPDATED` | Entity обновлён (merge) |
| `OBSERVATION_APPLIED` | Observation применён к графу |
| `PLUGIN_STARTED` / `PLUGIN_FINISHED` | Начало/конец выполнения плагина |
| `GAP_DETECTED` | Обнаружены knowledge gaps |
| `STEP_COMPLETED` | Шаг цикла завершён |
| `DECISION_MADE` | Принято решение о запуске |
| `GOAL_ADVANCED` / `AUDIT_COMPLETED` | Прогресс целей / аудит завершён |
| `BELIEF_STRENGTHENED` / `BELIEF_WEAKENED` | Уверенность в entity повышена/понижена belief revision |
| `HYPOTHESIS_CONFIRMED` / `HYPOTHESIS_REJECTED` | Гипотеза подтверждена (≥0.85) / отклонена (≤0.15) |

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

## Container Security Audit

Подсистема автономного аудита контейнерной инфраструктуры. Обнаруживает Docker/K8s среды,
перечисляет контейнеры и образы, аудитирует конфигурацию, проверяет escape-векторы и
верифицирует находки. Полностью интегрирована в автономный движок через knowledge graph,
planner rules, goals и attack paths.

### Архитектура данных

```
HOST --[EXPOSES]--> SERVICE(:2375)
  \--[RUNS]--> Technology(docker, is_container_runtime=True)
                  \--[RUNS_CONTAINER]--> CONTAINER(abc123, privileged=True, ...)
                                            \--[USES_IMAGE]--> IMAGE(nginx:1.24)
```

### 7 плагинов

| Плагин | Категория | Зависит от | Produces | Описание |
|--------|-----------|------------|----------|----------|
| `container_discovery` | scanning | — | `container_runtimes` | Проба Docker API (2375/2376), K8s API (6443/10250) |
| `container_enumeration` | scanning | `container_discovery` | `containers`, `images` | GET /containers/json, /images/json через Docker API |
| `registry_lookup` | scanning | — | `registries` | Проба /v2/, /v2/_catalog на портах 5000/443 |
| `image_fingerprint` | analysis | `container_enumeration` | `image_vulns` | 30 vulnerable base images, :latest tag, stale images |
| `container_config_audit` | analysis | `container_enumeration` | `container_misconfigs` | 11 проверок: privileged, docker.sock, CAP_SYS_ADMIN, ... |
| `container_escape_probe` | exploitation | `container_config_audit` | `container_escapes` | 6 escape-векторов, проверка CVE (runc, containerd, dirty pipe) |
| `container_verification` | exploitation | config_audit + escape_probe | `verified_container_findings` | Re-probe на confidence 0.85 |

### Attack path: container_exploitation

```python
AttackPath(
    name="container_exploitation",
    preconditions=["Technology:docker"],
    actions=["container_enumeration", "container_config_audit",
             "container_escape_probe", "image_fingerprint"],
    expected_gain=["Finding", "Vulnerability", "Container"],
    risk=6.0,
    unlock=["privilege_escalation", "lateral_movement"],
)
```

---

## Campaign Memory

Persistent cross-audit learning. Запоминает инфраструктуру, эффективность плагинов и
технологические стеки между аудитами. Opt-in, по умолчанию выключена.

### Хранилище

```
~/.basilisk/campaigns/campaign.db     ← SQLite (WAL mode)
├── target_profiles   (per-host)      ← запомненные сервисы, технологии, findings
├── plugin_efficacy   (global)        ← per-plugin success rates с tech-stack breakdown
└── tech_fingerprints (per-domain)    ← паттерны технологий по организациям
```

### Активация

```bash
basilisk auto example.com --campaign          # CLI
```
```python
await Basilisk("example.com").campaign().run()  # API
```
```yaml
campaign:
  enabled: true                              # config YAML
```

---

## Cognitive Reasoning

Детерминированные reasoning-примитивы поверх knowledge graph. Без AI/LLM — чистая логика
на паттернах и статистике. Три компонента: Hypothesis Engine, Evidence Aggregator, ActionType.

### Hypothesis Engine (`reasoning/hypothesis.py`)

Формирует тестируемые гипотезы из паттернов в knowledge graph.

**5 детекторов паттернов:**

| Детектор | Триггер | Генерирует |
|----------|---------|-----------|
| `_detect_shared_stack` | Одна технология на 2+ хостах | "Организация стандартизирует X" |
| `_detect_service_identity` | Сервис на нестандартном порту, без tech | "Порт N вероятно запускает X" |
| `_detect_systematic_vuln` | 3+ findings одного типа | "Систематическая уязвимость категории X" |
| `_detect_unverified_findings` | HIGH/CRITICAL finding, confidence < 0.7 | "Уязвимость может существовать в X" |
| `_detect_framework_pattern` | Пути endpoints совпадают с известным фреймворком | "Цель использует WordPress/Laravel/etc" |

### Evidence Aggregator (`reasoning/belief.py`)

Belief revision на основе source-family independence.

**6 source families:**

| Family | Плагины |
|--------|---------|
| `dns` | dns_enum, whois, reverse_ip, ... |
| `network_scan` | port_scan, service_detect, banner_grab, ... |
| `http_probe` | tech_detect, waf_detect, http_headers, ... |
| `exploit` | sqli_*, xss_*, ssrf_*, ssti_*, command_injection, ... |
| `config_leak` | container_config_audit, git_exposure, sensitive_files, ... |
| `verification` | ssti_verify, container_verification, nosqli_verify, ... |

**Логика belief revision:**
- Track `(plugin, family, delta)` per entity per step
- После шага: entity с evidence из 2+ source families → independence bonus (+0.05 per family, max +0.15)
- Contradicting evidence → penalty (-0.1)
- Confidence clamped to [0.1, 1.0]

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
| VULNERABLE_BASE_IMAGES | analysis/image_fingerprint.py | 30 | — |
| Container escape CVEs | exploitation/container_escape_probe.py | 3 | — |
| VulnRegistry definitions | knowledge/vulns/definitions.yaml | 100+ | — |
