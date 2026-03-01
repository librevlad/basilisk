# CLAUDE.md

## Проект

**Basilisk v4.0.0** — модульный фреймворк безопасности. Автономный движок на knowledge graph с детерминированными decision traces. Unified v4: ScenarioRegistry (188 legacy-wrapped + 5 native), ScenarioExecutor, KG persistence. SQLite-хранилище. Campaign memory. Container security audit. Cognitive reasoning. Training validation. Actor-based network abstraction.

## Быстрые команды

```bash
.venv/Scripts/python.exe -m pytest tests/ -v              # все тесты
.venv/Scripts/python.exe -m pytest tests/ -x --tb=short    # до первого падения
.venv/Scripts/python.exe -m ruff check basilisk/ tests/
.venv/Scripts/python.exe -m ruff check . --fix
.venv/Scripts/python.exe -m basilisk auto example.com      # автономный аудит
.venv/Scripts/python.exe -m basilisk run ssl_check example.com
.venv/Scripts/python.exe -m basilisk plugins
.venv/Scripts/python.exe -m basilisk train profile.yaml
uv sync && uv pip install -e ".[dev]"
```

## Стек

Python 3.12+, Pydantic v2, aiohttp, aiosqlite (WAL), dnspython, aiolimiter, aiofiles, Typer+Rich CLI, cryptography, uv, ruff (py312, line-length 100), pytest+pytest-asyncio (asyncio_mode=auto).

## Архитектура

```
basilisk/
├── __init__.py, __main__.py, cli.py, config.py
├── domain/          # [v4] BaseTarget, Scenario, Surface, Finding+Proof
├── actor/           # [v4] ActorProtocol, CompositeActor, HttpActor, RecordingActor
├── engine/          # [v4] ScenarioRegistry, TargetLoader, AutonomousRunner
├── bridge/          # [v4] LegacyPluginScenario, ContextAdapter, ResultAdapter
├── scenarios/       # [v4] 5 native: dns, port, ssl, sqli, xss
├── verification/    # [v4] ConfidenceCalculator, FindingConfirmer, FindingRevalidator
├── training/        # [v4] TrainingProfile/Runner/Validator, PlannerWrapper, ScorerWrapper
├── models/          # Pydantic: Target, PluginResult, Finding, DnsRecord, SslInfo, etc.
├── core/            # BasePlugin, PluginRegistry (Kahn's topo sort), AsyncExecutor+PluginContext, ProviderPool, AuthManager
├── knowledge/       # KnowledgeGraph (9 entity types, 11 relation types), KnowledgeState, KnowledgeStore, VulnRegistry
├── observations/    # Observation model, adapt_result(): PluginResult → Observations → KG
├── capabilities/    # Capability+ActionType, CAPABILITY_MAP (145 explicit + auto-inference)
├── reasoning/       # HypothesisEngine (5 detectors), EvidenceAggregator (6 source families)
├── decisions/       # Decision, ContextSnapshot, EvaluatedOption
├── memory/          # History: decision log, repetition penalty, JSON persistence
├── scoring/         # Scorer: multi-component priority formula
├── orchestrator/    # Planner (18 gap rules), Selector, ScenarioExecutor, AutonomousLoop, GoalEngine, AttackPaths, CostTracker, CoverageTracker, SafetyLimits, Timeline
├── campaign/        # CampaignStore (SQLite), CampaignMemory, extractor
├── events/          # EventBus: 14 event types
├── utils/           # http, dns, net, rate_limiter, wordlists, batch_check, browser, payloads, waf_bypass, etc.
├── storage/         # SQLite WAL: Schema+PRAGMA+migrations, Repository (CRUD, bulk, pagination)
└── plugins/         # 188 auto-discovered: recon(23), scanning(19), analysis(23), pentesting(60), exploitation(23), crypto(8), lateral(12), privesc(7), post_exploit(7), forensics(6)

tests/               # ~1974 теста, 90+ файлов, зеркальная структура
```

### v4 Layer Stack

```
CLI / Basilisk class → Engine (AutonomousRunner) → Orchestrator (loop/planner/selector/scorer)
→ Scenarios (5 native + 188 legacy via bridge) → Actor (ActorProtocol) → KG + Verification + Training
```

## Ключевые паттерны

### Fluent API
```python
result = await Basilisk("example.com").run()
result = await Basilisk("example.com", max_steps=50).run()
result = await Basilisk("example.com").campaign().run()
result = await Basilisk("example.com").plugins("sqli_*").exclude("heavy_*").run()
```

### Создание плагина
```python
# basilisk/plugins/<category>/my_plugin.py — автообнаружение, регистрация не нужна
from __future__ import annotations
from typing import ClassVar
from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

class MyPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="my_plugin", display_name="My Plugin",
        category=PluginCategory.PENTESTING, description="What it does",
        produces=["my_data"], timeout=30.0,
    )
    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        # HIGH/CRITICAL findings MUST have evidence
        findings.append(Finding.high("Title", evidence="proof", description="..."))
        return PluginResult.success(self.meta.name, target.host, findings=findings)
```

### PluginContext (DI)
`ctx.config`, `ctx.http` (.get/.head/.post/.fetch_text), `ctx.dns`, `ctx.net`, `ctx.rate` (async with), `ctx.wordlists`, `ctx.providers`, `ctx.pipeline` (dict[str, PluginResult]), `ctx.state` (shared dict), `ctx.emit(finding, host)`, `ctx.should_stop`.

### Capability mapping для нового плагина
```python
# capabilities/mapping.py → CAPABILITY_MAP
"my_plugin": {"requires": ["Host", "Service:http"], "produces": ["Finding"], "cost": 3.0, "noise": 2.0}
```

Requires syntax: `"Host"`, `"Service:http"`, `"Service:ssh"`, `"Endpoint:params"`, `"Technology:waf"`, `"Technology:cms"`, `"Technology:docker"`, `"Container"`, `"Image"`, `"Credential"`.

## Конвенции кода

- Ruff: target py312, line-length 100, select E/F/W/I/N/UP/B/A/SIM
- `datetime.UTC` (не `timezone.utc`), `collections.abc.AsyncIterator` (не `typing.AsyncIterator`)
- `from __future__ import annotations` — в каждом файле
- Код/комментарии/docstrings — **английский**, общение с пользователем — **русский**
- Pydantic v2 с factory methods: `Target.domain()`, `Finding.high()`, `PluginResult.success()`
- Finding severity: INFO(0)→LOW(1)→MEDIUM(2)→HIGH(3)→CRITICAL(4). HIGH/CRITICAL **обязаны** иметь `evidence`
- Всё async. Rate limiting: `async with ctx.rate:` перед запросами
- Тесты: mock сети через `AsyncMock`. Всегда `ruff check` перед коммитом
- Windows: `.venv/Scripts/python.exe`, `signal.signal(SIGINT, handler)` (не `loop.add_signal_handler`)

## Workflow

1. Прочитать существующий код, понять паттерны
2. Следовать существующим паттернам, не добавлять лишнего
3. Ruff check запускается автоматически (hook)
4. `pytest tests/ -x --tb=short`
5. Коммит только по запросу, Conventional Commits
6. Ветки от develop (feature branches)

---

## Git Flow + Conventional Commits

**Ветки:** `master` (релизы) ← `develop` (интеграция) ← `feature/<name>` (задачи). Hotfix: `master` → `hotfix/<name>` → `master` + `develop`.

**Формат коммита:**
```
<type>(<scope>): <description>

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
```

**Типы:** feat|fix|refactor|test|docs|chore|perf|style|ci

**Scopes:** plugins, orchestrator, knowledge, cli, storage, utils, models, core, scoring, observations, capabilities, decisions, memory, events, config, campaign, reasoning, actor, bridge, domain, engine, scenarios, verification, training

**Правила:**
- Description — английский, императив, lowercase, без точки
- Ветки от `develop`: `feature/<kebab-case>`. Hotfix от `master`: `hotfix/<kebab-case>`
- PR target = `develop` (hotfix → `master`)

---

## Автономный движок

Gap-driven цикл: Planner → Selector → Scorer → Decision → Execute → Observe → Apply to KG → Hypothesize → Revise beliefs → repeat.

**Termination:** `no_gaps` | `limit_reached` | `no_capabilities` | `no_candidates` | `all_executed`

**Принципы:** детерминированные ID (SHA256), probabilistic confidence merge `1-(1-old)*(1-new)`, decision traces (pre/post execution), gap-driven termination.

## Knowledge Graph

9 entity types: HOST, SERVICE, ENDPOINT, TECHNOLOGY, CREDENTIAL, FINDING, VULNERABILITY, CONTAINER, IMAGE. Factory methods: `Entity.host()`, `.service()`, `.endpoint()`, `.technology()`, `.credential()`, `.finding()`, `.vulnerability()`, `.container()`, `.image()`.

11 relation types: EXPOSES (HOST→SERVICE), RUNS (SERVICE→TECH), HAS_ENDPOINT, HAS_VULNERABILITY, ACCESSES, RELATES_TO, PARENT_OF, RUNS_CONTAINER, USES_IMAGE, SUPPORTED_BY, DISPROVED_BY.

ID: `Entity.make_id(EntityType, **key_fields)` → SHA256[:16]. Dedup by ID, merge on collision.

## Observation Bridge

`adapt_result(PluginResult)` → `list[Observation]` → `KnowledgeState.apply_observation()` → Entity+Relation в граф.

Key data mappings: `open_ports`/`services`→SERVICE+EXPOSES, `technologies`/`cms`/`waf`→TECHNOLOGY+RUNS, `subdomains`→HOST+PARENT_OF, `crawled_urls`/`found_paths`/`urls`/`api_endpoints`→ENDPOINT+HAS_ENDPOINT, `credentials`→CREDENTIAL+ACCESSES, `containers`→CONTAINER+RUNS_CONTAINER+IMAGE+USES_IMAGE, `findings`→FINDING+RELATES_TO.

## Scoring

```
priority = (novelty * knowledge_gain * success_prob + unlock_value + prior_bonus
            + hypothesis_gain + action_type_bonus) * gap_boost / (cost + noise + repetition_penalty)
```

ActionType bonuses: EXPERIMENT +0.1 (confidence<0.7), EXPLOIT +0.15 (confidence≥0.8), VERIFICATION +0.2 (high/critical).
Cost sources: CostTracker (runtime) → CampaignMemory (cross-audit) → cap.cost_score (static).

## Planner — 18 gap rules

| Rule | missing | Priority |
|------|---------|----------|
| host_without_services | services | 10.0 |
| host_without_dns | dns | 8.0 |
| http_without_tech | technology | 7.0 |
| credential_without_exploitation | credential_exploitation | 7.5 |
| container_runtime_without_enum | container_enumeration | 7.0 |
| http_without_endpoints | endpoints | 6.0 |
| service_without_exploitation | service_exploitation | 6.5 |
| finding_without_verification | finding_verification | 6.0 |
| host_without_container_check | container_runtime | 6.0 |
| http_endpoints_without_forms | forms | 5.5 |
| container_without_config_audit | container_config_audit | 5.5 |
| hypothesis_validation | hypothesis_validation | 5.5 |
| endpoint_without_testing | vulnerability_testing | 5.0 |
| container_without_image_analysis | image_analysis | 5.0 |
| http_host_without_vuln_testing | host_vulnerability_testing | 4.5 |
| technology_without_version | version | 4.0 |
| low_confidence_entity | confirmation | 3.0 |
| attack_path_gaps | attack_path | path.risk |

Gap satisfaction flags: `services_checked`, `tech_checked`, `endpoints_checked`, `forms_checked`, `version_checked`, `container_runtime_checked`, `containers_enumerated`, `config_audited`, `vulnerabilities_checked`.

## Reasoning

**HypothesisEngine** — 5 detectors: shared_stack, service_identity, systematic_vuln, unverified_findings, framework_pattern.

**EvidenceAggregator** — 6 source families: dns, network_scan, http_probe, exploit, config_leak, verification. Belief revision: 2+ independent families → +0.05/family (max +0.15), contradiction → -0.1.

## Container Security

7 plugins: container_discovery → container_enumeration → registry_lookup, image_fingerprint, container_config_audit → container_escape_probe → container_verification. Attack path `container_exploitation` unlocks privilege_escalation + lateral_movement.

## Campaign Memory (opt-in)

`~/.basilisk/campaigns/campaign.db`: target_profiles, plugin_efficacy, tech_fingerprints. Activate: `--campaign` flag or `.campaign()` API.
