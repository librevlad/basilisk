# Basilisk v3.0.0 — Audit Notes

## v3.0.0 — State-Driven Autonomous Engine (2026-02-19)

Замена фиксированного pipeline (`recon → scanning → analysis → pentesting`) автономным
движком на knowledge graph. Плагины не изменяются — adapter слой конвертирует `PluginResult`
в `Observation` для knowledge graph.

### Новые модули

| Модуль | Файлы | Описание |
|--------|-------|----------|
| `knowledge/` | entities, relations, graph, store | Knowledge Graph: 7 типов entities, 7 типов relations, dedup, confidence merge, SQLite persistence |
| `observations/` | observation, adapter | Мост PluginResult → Observation. Обрабатывает open_ports, technologies, subdomains, endpoints, credentials, findings и др. |
| `capabilities/` | capability, mapping | Маппинг 175 плагинов → requires/produces/cost/noise. Auto-inference для немаппированных |
| `scoring/` | scorer | Формула: `(novelty * knowledge_gain) / (cost + noise + repetition_penalty)` |
| `orchestrator/` | planner, selector, executor, loop, safety, timeline | Автономный цикл: find_gaps → match → score → pick → execute → apply → repeat |
| `events/` | bus | Event bus: entity_created, plugin_started/finished, gap_detected, step_completed |

### Gap Detection Rules (planner.py)

1. `host_without_services` — Host без Service relations → нужен port_scan
2. `host_without_dns` — Host без dns_data → нужен dns_enum
3. `http_without_tech` — Service:http без Technology → нужен tech_detect
4. `http_without_endpoints` — Service:http без Endpoint → нужен web_crawler
5. `endpoint_without_testing` — Endpoint с params без Finding → нужен sqli/xss
6. `technology_without_version` — Technology без version → нужен version_detect
7. `low_confidence_entity` — Entity с confidence < 0.5 → recheck

### Confidence Merge

`confidence = 1 - (1-old) * (1-new)` — probabilistic OR. Два наблюдения с 0.5 → 0.75.

### Интеграция

- `facade.py`: `.autonomous(max_steps=N)` fluent method, `_run_autonomous()` ветка
- `cli.py`: `--autonomous` / `-A` + `--max-steps` флаги
- `KnowledgeStore`: сохранение графа в SQLite после автономного прогона (если задан проект)
- `LoopResult.plugin_results` → `PipelineState` для обратной совместимости с reporting

### Тесты

131 новых тестов в 11 файлах. Всего: 1382 (все проходят).

| Файл | Тесты |
|------|-------|
| test_knowledge/test_entities.py | 14 |
| test_knowledge/test_graph.py | 22 |
| test_knowledge/test_store.py | 9 |
| test_observations/test_adapter.py | 26 |
| test_capabilities/test_mapping.py | 8 |
| test_scoring/test_scorer.py | 9 |
| test_orchestrator/test_planner.py | 14 |
| test_orchestrator/test_selector.py | 9 |
| test_orchestrator/test_loop.py | 10 |
| test_orchestrator/test_safety.py | 5 |
| test_events/test_bus.py | 5 |

---

# v2.0.0 — Audit Notes (2026-02-12)

## Проведённый аудит

Глубокий аудит всей кодовой базы: core, utils, reporting, TUI, 110 плагинов, 664 теста.
3 параллельных ревью: архитектура ядра, утилиты/отчёты, экосистема плагинов.

## Исправлено в этом рефакторинге

### Критические баги
- [x] **Race condition ctx._deadline** — executor.py:98 — параллельные плагины перезаписывали deadline друг друга. Fix: `ctx.scoped(timeout)` создаёт shallow copy.
- [x] **run_plugin() без rate limiter** — facade.py:383 — PluginContext без rate/wordlists, краш на `async with ctx.rate`. Fix: добавлены RateLimiter + WordlistManager.
- [x] **Progress math +=total** — pipeline.py:152 — `phase.completed += phase.total` вместо `+= len(scope)`. Fix: правильный инкремент.
- [x] **str(Exception) вместо str(e)** — dashboard.py:132 — показывало `<class 'Exception'>`. Fix: `except Exception as e: ... str(e)`.
- [x] **_gather_fastest возвращает первый failed** — providers.py:150 — FIRST_COMPLETED мог вернуть exception. Fix: loop до первого успеха.

### DI-контейнер (Laravel Service Container)
- [x] **Типизация PluginContext** — 7 полей `Any` → реальные типы с `| None`
- [x] **requires_http в PluginMeta** — замена хардкода `_NON_HTTP_PLUGINS` (19 имён) на декларативное поле
- [x] **ProviderPool setup/teardown** — провайдеры не вызывали setup()/teardown()

### DRY
- [x] **SECRET_PATTERNS** — дублировались в 4 файлах → единый `utils/secrets.py`
- [x] **_extract_plugin_stats** — идентичная копия в html.py и live_html.py → `reporting/utils.py`
- [x] **DiffResult конфликт имён** — два класса в baseline.py и diff.py → rename в baseline.py
- [x] **resolve_base_url** — `resolve_base_url` перенесён в utils/http.py рядом с `resolve_base_urls`, http_check.py стал реэкспортом (52 импортера сохранены)
- [x] **BasePlugin.baseline_request()** — 0 вызовов, удалён

### Фасад
- [x] **Audit.run() 170-строк** — декомпозиция на 4 приватных метода

---

## Отложено на будущее

### HIGH PRIORITY

#### Разделение ssl_check.py (2563 строки)
Один плагин делает: SSL handshake, certificate parsing, chain validation, cipher analysis, protocol check, HSTS check, CT log check, OCSP stapling, key strength, vulnerability checks (BEAST, CRIME, POODLE, Heartbleed, ROBOT).
**План**: Разбить на 4-5 плагинов:
- `ssl_basic.py` — handshake + certificate info + chain
- `ssl_ciphers.py` — cipher suites + protocol versions
- `ssl_vulns.py` — known vulnerabilities (BEAST, POODLE, etc.)
- `ssl_compliance.py` — HSTS, CT, OCSP, key strength
- Общая логика → `utils/ssl_helpers.py`

#### ~~Тесты для плагинов~~ — ВЫПОЛНЕНО
~~85 из 110 без функциональных тестов~~ → 110/110 плагинов покрыты (883 теста).
Добавлены 5 файлов тестов: test_recon_scanning_new.py (32), test_analysis_new.py (22),
test_pentesting_new1.py (44), test_pentesting_new2.py (42), test_analysis_batch2.py (39).

### MEDIUM PRIORITY

#### Экстернализация payload data
- `utils/payloads.py` — 1933 строки, ~1700 строк статических данных (XSS vectors, SQLi payloads, SSTI templates)
- `utils/waf_bypass.py` — 1331 строка, ~730 строк WAF-профилей
**План**: Вынести в YAML/JSON файлы в `data/` директорию, загружать лениво.

#### Миграции БД
Сейчас: schema создаётся при open_db, нет версионирования.
**План**: Простая система — `storage/migrations/`, номерные файлы `001_initial.sql`, таблица `_migrations` с applied timestamps.

#### CORS/CSP overlap
- `http_headers.py` делает базовый CORS/CSP анализ
- `cors_check.py` и `csp_check.py` делают глубокий анализ
- Дублирование findings. Нужно: http_headers пропускает CORS/CSP если есть dedicated плагины.

#### ASN lookup дублирование
- `asn_lookup.py` — dedicated ASN плагин
- `whois.py` — тоже делает ASN lookup внутри
- Нужно: whois использует результат asn_lookup через `depends_on`

### LOW PRIORITY

#### ExploitChainEngine
- Создан в `core/exploit_chain.py`, инстанцируется в facade.py
- Ни один плагин не использует его API
- Оставить до появления плагинов с exploit chaining

#### TUI stubs
- Config screen: изменения не персистятся
- Report screen: export — заглушка
- Dashboard: нет cancel button для остановки аудита

#### dns_enum.py двойной wildcard detection
- `_detect_wildcard()` вызывается дважды в некоторых путях
- Минорный performance hit

---

## Subdomain-плагины (аудит 2026-02-12)

### Статус провайдеров (11 плагинов)
| Плагин | Статус | Примечания |
|--------|--------|------------|
| subdomain_crtsh | OK | Работает, иногда 429 при rate limit |
| subdomain_rapiddns | OK | HTML-скрапинг, стабильный |
| subdomain_wayback | OK | CDX API, возвращает мало subdomain, но много URL |
| subdomain_certspotter | **NEW** | Бесплатный CT API, без ключа |
| subdomain_anubis | **NEW** | jldc.me агрегатор, бесплатный, без ключа |
| subdomain_bruteforce | OK | Локальный brute по словарю |
| subdomain_hackertarget | FIXED | Не ловил "API count exceeded" |
| subdomain_alienvault | FIXED | Не обрабатывал 429/403 |
| subdomain_dnsdumpster | DEGRADED | API требует ключ (401), HTML fallback ограничен |
| subdomain_virustotal | DEGRADED | /ui/ за reCAPTCHA, v3 API требует ключ |
| subdomain_takeover_active | N/A | Не провайдер subdomains, а checker |

### Исправления
- [x] HackerTarget: добавлена проверка "api count exceeded" в error detection
- [x] AlienVault: graceful handling 429/403 с информативным сообщением
- [x] DNSDumpster: комментарий что API требует ключ, улучшен HTML fallback
- [x] VirusTotal: убран мёртвый HTML fallback (reCAPTCHA), добавлена поддержка v3 API с ключом
- [x] Создан subdomain_certspotter (бесплатный CT API)
- [x] Создан subdomain_anubis (бесплатный агрегатор)
- [x] 16 новых тестов в test_subdomain_plugins.py

---

## ПЛАН: Live-аудит всех плагинов по категориям

Методология (проверена на subdomain-плагинах):
1. Прочитать код каждого плагина
2. Протестировать живьём на реальном домене (hackerone.com / example.com)
3. Сравнить с профессиональными аналогами (если есть)
4. Исправить сломанное, добавить недостающее
5. Написать mock-тесты для каждого плагина
6. Обновить эту секцию с результатами

### Батч 1: Recon (оставшиеся 12, без subdomain-*) — ВЫПОЛНЕНО 2026-02-12

**Зависят от внешних API:**
- [x] `shodan_lookup` — OK, graceful "API key not configured" message
- [x] `github_dorking` — OK, graceful "GitHub token not configured" message
- [x] `cloud_bucket_enum` — OK, нашёл 2 бакета для hackerone.com (AWS S3)
- [x] `s3_bucket_finder` — TIMEOUT (30s), дублирует cloud_bucket_enum → **default_enabled=False**

**Используют HTTP к целевому домену:**
- [x] `web_crawler` — OK, 84 URLs + 7 JS files на hackerone.com
- [x] `robots_parser` — OK, отлично работает
- [x] `sitemap_parser` — OK, 2000 URLs из 4 sitemaps
- [x] `email_harvest` — OK, 1 email, json.loads → resp.json()

**DNS/сетевые:**
- [x] `dns_enum` — OK, 10 findings, **FIXED**: MEDIUM findings без evidence (CAA/SPF/DMARC/MX)
- [x] `dns_zone_transfer` — OK, zone transfer denied (expected), **FIXED**: specific exception types
- [x] `reverse_ip` — NO RESULTS (requires IPs, expected), **FIXED**: "API count exceeded" detection
- [x] `whois` — OK (не тестировался live, код ревью прошёл)
- [x] `asn_lookup` — OK, AS13335 Cloudflare, **FIXED**: informative error messages (429, HTTP status)
- [ ] `whois` — RDAP + whois, проверить ASN дублирование с asn_lookup
- [ ] `asn_lookup` — BGPView API, проверить доступность

**Сравнение с инструментами:** subfinder, amass, theHarvester, dnsrecon

### Батч 2: Scanning (13 плагинов)

**SSL/TLS (тяжёлые, приоритетные):**
- [ ] `ssl_check` — 2563 строки God Plugin, сравнить с testssl.sh/sslyze
- [ ] `tls_cipher_scan` — пересечение с ssl_check? проверить
- [ ] `ssl_cert_chain` (analysis) — пересечение с ssl_check? проверить

**HTTP-анализ (частично выполнено):**
- [x] `cors_scan` — OK, 12 checks (> CORScanner's 8-10). No issues on hackerone.com (expected)
- [x] `http_methods_scan` — OK, GET/HEAD detected. Код ревью: redirect codes в allowed — acceptable
- [x] `cookie_scan` — OK, **FIXED**: Secure flag case-sensitive comparison bug + dead code cleanup
- [ ] `redirect_chain` — проверить loop detection, max hops

**Service detection (частично выполнено):**
- [x] `port_scan` — OK, 4 TCP open ports on hackerone.com (80, 443, 8080, 8443)
- [x] `service_detect` — NO RESULTS (expected: depends_on port_scan, не работает через run_plugin)
- [x] `cdn_detect` — OK, detected cloudflare + fastly

**Специализированные:**
- [ ] `graphql_detect` — introspection, проверить detection rate
- [ ] `websocket_detect` — проверить detection методы
- [ ] `dnssec_check` — проверить валидацию chain of trust
- [ ] `ipv6_scan` — AAAA records + connectivity

**Сравнение с инструментами:** nmap, testssl.sh, sslyze, CORScanner, nikto

### Батч 3: Analysis (21 плагин) — ЧАСТИЧНО ВЫПОЛНЕНО 2026-02-13

**Security headers (пересечение!):**
- [x] `http_headers` — OK, 27 findings на hackerone.com. 20+ headers checked, ~80% securityheaders.com
- [x] `csp_analyzer` — OK, 8 findings. 54 bypass domains (3.5x > Google CSP Evaluator!). **FIXED**: MEDIUM findings без evidence
- [x] `waf_detect` — OK, Cloudflare CDN detected. **FIXED**: HuaweiCloud WAF false positive (x-request-id too generic)
- [ ] `waf_bypass` — техники обхода, сравнить с wafw00f

**JS-анализ:**
- [ ] `js_api_extract` — endpoint extraction из JS, secrets (уже на utils/secrets.py)
- [ ] `js_secret_scan` — secrets в JS (уже на utils/secrets.py), проверить overlap с js_api_extract
- [x] `comment_finder` — OK, нашёл 3 HIGH + 2 MEDIUM sensitive comments на hackerone.com

**CMS/Tech:**
- [x] `tech_detect` — OK, 11 techs на hackerone.com (Cloudflare, Fastly, Drupal, jQuery, PHP, etc.). 87 сигнатур vs Wappalyzer 6000+
- [x] `cms_detect` — OK, **FIXED**: не находил Drupal через x-drupal-* headers. Header value lowercasing баг
- [x] `version_detect` — OK, **FIXED**: jQuery version "." regex bug (fingerprints.py version_pattern)

**Специализированные:**
- [x] `takeover_check` — OK, 65 fingerprints. **FIXED**: NS/MX/CNAME records used str(DnsRecord) repr instead of .value
- [ ] `openapi_parser` — Swagger/OpenAPI discovery + parsing
- [ ] `api_detect` — REST/GraphQL/SOAP endpoint обнаружение
- [ ] `security_txt` — /.well-known/security.txt
- [x] `favicon_hash` — OK, hash detected. **FIXED**: corrupted Drupal MD5 hash entry (line 18: "1979b1885f tried5e61269")
- [ ] `meta_extract` — HTML meta tags
- [ ] `link_extractor` — links + resources
- [ ] `form_analyzer` — form fields, CSRF tokens, action URLs
- [ ] `cloud_detect` — cloud provider по IP/headers
- [ ] `prometheus_scrape` — /metrics endpoint intelligence
- [ ] `ssl_cert_chain` — certificate chain validation

**Сравнение с профессиональными инструментами (10 плагинов):**

| Плагин | vs | Coverage | Highlights |
|--------|-----|---------|------------|
| tech_detect (509 lines) | Wappalyzer (6000+ techs) | 87 techs + implies | Multi-signal: headers, body, cookies, meta generator, fingerprint DB |
| waf_detect (773 lines) | wafw00f (100+ WAFs) | 73 WAFs/CDNs | Better confidence scoring, CDN differentiation |
| http_headers (770 lines) | securityheaders.com | 20+ headers | ~80% equivalent, needs Permissions-Policy validation |
| csp_analyzer (648 lines) | Google CSP Evaluator | 54 bypass domains | 3.5x more bypass domains! Nonce reuse, A-F grading |
| takeover_check (395 lines) | can-i-take-over-xyz | 65 fingerprints | NS/MX takeover checks (unique!), confidence scoring |
| cms_detect (238 lines) | WPScan/CMSmap | 20 CMS | Meta generator + body + header matching |
| comment_finder (338 lines) | Burp passive scanner | 8 pattern categories | HTML + inline JS + external JS scanning |
| favicon_hash (180 lines) | Shodan favicon | 82 MD5 + 30 MMH3 | Technology identification via favicon hash |
| version_detect (444 lines) | retire.js (1000+ CVEs) | 28 CVE records | Header + body + meta + error page + fingerprint DB |
| cors_scan (438 lines) | CORScanner | 12 tests | More tests than CORScanner (8-10), better bypass coverage |

**Найденные и исправленные баги (7 штук):**
1. `favicon_hash:18` — corrupted MD5 hash "1979b1885f tried5e61269" → valid 32-char hex
2. `takeover_check:287,339,375` — str(DnsRecord) returns full repr, not hostname → `.value` attribute
3. `version_detect` + `fingerprints.py:212` — jQuery version_pattern `[\d.]+` matches bare "." → `\d[\d.]+`
4. `csp_analyzer:287,318,397,408` — MEDIUM findings without evidence → added evidence strings
5. `cms_detect:184` — `v.lower()` on header values loses case info for body matching → removed lowercasing
6. `cms_detect:28` — Drupal not detected via x-drupal-cache header → added to signatures
7. `waf_detect:265` — HuaweiCloud WAF false positive from generic x-request-id header → x-huawei-waf

**Тесты:** 39 новых тестов в `test_analysis_batch2.py`. Всего тестов: 883

### Батч 4: Pentesting (55 плагинов) — самый большой

**Injection (ключевые, сравнить с профинструментами):**
- [ ] `sqli_basic` — error-based SQLi, сравнить с sqlmap (~30% coverage)
- [ ] `sqli_advanced` — blind/time-based SQLi
- [ ] `xss_basic` — reflected XSS, сравнить с XSStrike/Dalfox
- [ ] `xss_advanced` — DOM XSS, context-aware
- [ ] `ssti_check` — template injection detection
- [ ] `ssti_verify` — template injection verification/exploitation
- [ ] `command_injection` — OS command injection
- [ ] `nosqli_check` — NoSQL injection detection
- [ ] `nosqli_verify` — NoSQL injection verification
- [ ] `lfi_check` — LFI / path traversal
- [ ] `path_traversal` — overlap с lfi_check? проверить
- [ ] `xxe_check` — XML external entity injection
- [ ] `crlf_injection` — CRLF injection → header injection

**SSRF:**
- [ ] `ssrf_check` — basic SSRF detection
- [ ] `ssrf_advanced` — advanced SSRF exploitation
- [ ] `cloud_metadata_ssrf` — AWS/GCP/Azure metadata SSRF

**Auth/Access:**
- [ ] `idor_check` — IDOR detection
- [ ] `idor_exploit` — deep IDOR enumeration
- [ ] `api_logic_engine` — auto IDOR/BOLA
- [ ] `jwt_attack` — JWT none/weak key/kid injection
- [ ] `oauth_attack` — OAuth/OIDC misconfigs
- [ ] `csrf_check` — CSRF protection bypass
- [ ] `cors_exploit` — CORS misconfiguration exploitation

**Brute/Discovery:**
- [ ] `dir_brute` — directory bruteforce, сравнить с ffuf/gobuster
- [ ] `admin_finder` — admin panel paths
- [ ] `admin_brute` — admin panel bruteforce
- [ ] `param_discover` — hidden parameter discovery
- [ ] `param_pollution` — HPP
- [ ] `sensitive_files` — .env, .git, backup files
- [ ] `backup_finder` — backup files (.bak, .old, ~)
- [ ] `debug_endpoints` — /debug, /trace, /actuator, etc.

**Service-specific:**
- [ ] `wordpress_scan` — WP enumeration
- [ ] `wp_deep_scan` — WP deep analysis
- [ ] `wp_brute` — WP login bruteforce
- [ ] `git_exposure` — .git exposure + secret scanning
- [ ] `ftp_anon` — anonymous FTP
- [ ] `ssh_brute` — SSH bruteforce
- [ ] `service_brute` — generic service default creds
- [ ] `credential_spray` — credential spraying
- [ ] `default_creds` — default credentials

**Advanced:**
- [ ] `http_smuggling` — request smuggling (CL.TE / TE.CL)
- [ ] `cache_poison` — web cache poisoning
- [ ] `host_header_inject` — host header attacks
- [ ] `open_redirect` — open redirect detection
- [ ] `error_disclosure` — error message information leaks
- [ ] `password_reset_poison` — password reset flow poisoning
- [ ] `deserialization_check` — insecure deserialization
- [ ] `prototype_pollution` — JS prototype pollution
- [ ] `pp_exploit` — prototype pollution exploitation
- [ ] `race_condition` — single-packet race conditions
- [ ] `actuator_exploit` — Spring actuator exploitation
- [ ] `graphql_exploit` — GraphQL exploitation
- [ ] `port_vuln_check` — known port vulnerabilities
- [ ] `email_spoofing` — SPF/DKIM/DMARC checks
- [ ] `subdomain_takeover_active` — active takeover attempts

**Сравнение с инструментами:** sqlmap, XSStrike, Dalfox, ffuf, gobuster, nuclei, Burp Suite, WPScan, tplmap, commix

### Приоритеты выполнения

1. **Батч 1 (Recon)** — быстрый, 12 плагинов, большинство простые
2. **Батч 3 (Analysis)** — средний, 21 плагин, много overlap-проверок
3. **Батч 2 (Scanning)** — включает ssl_check God Plugin (отдельная задача)
4. **Батч 4 (Pentesting)** — самый большой (55), разбить на подбатчи по 10-15

### Ожидаемые паттерны проблем (по опыту subdomain-аудита)

- **Сломанные внешние API**: Shodan, GitHub, VirusTotal, HackerTarget — rate limits, auth requirements
- **Тихие провалы**: `except Exception: pass` без информативных сообщений
- **Дублирование**: ssl_check ↔ tls_cipher_scan ↔ ssl_cert_chain, lfi_check ↔ path_traversal, cors_scan ↔ cors_exploit, http_headers ↔ csp_analyzer
- **Устаревшие fingerprints**: tech_detect, cms_detect, waf_detect — нужна проверка актуальности сигнатур
- ~~Отсутствие тестов~~: 110/110 плагинов покрыты mock-тестами

---

## Расширение баз сигнатур (2026-02-13) — ВЫПОЛНЕНО

3 раунда массового расширения. Все базы доведены до уровня проф-инструментов.

### Раунд 1: Ключевые detection-базы
| База | Файл | Было | Стало |
|------|------|------|-------|
| TECH_FINGERPRINTS | data/fingerprints.py | 87 | 594 |
| _VULNERABLE_VERSIONS (CVE) | analysis/version_detect.py | 28 | 200+ |
| WAF_SIGNATURES | analysis/waf_detect.py | 73 | 125 |
| TAKEOVER_FINGERPRINTS | data/fingerprints.py | 48 | 80 |
| KNOWN_FAVICONS + MMH3 | analysis/favicon_hash.py | 112 | 300+ |
| CSP_BYPASS_DOMAINS | data/fingerprints.py | 15 | 52 |
| CMS_SIGNATURES | analysis/cms_detect.py | 20 | 83 |
| CLOUD_SIGNATURES | analysis/cloud_detect.py | 8 | 33 |
| CDN_SIGNATURES | scanning/cdn_detect.py | 19 | 40 |

### Раунд 2: Pentesting payloads
| База | Файл | Было | Стало |
|------|------|------|-------|
| DISCLOSURE_PATTERNS | pentesting/error_disclosure.py | 14 | 43 |
| ERROR_TRIGGERS | pentesting/error_disclosure.py | 20 | 38 |
| TRAVERSAL_PAYLOADS | pentesting/path_traversal.py | 18 | 62 |
| NoSQLi total payloads | pentesting/nosqli_check.py | 30 | 92 |
| PP_PAYLOADS | pentesting/prototype_pollution.py | 14 | 62 |
| RESET_PATHS/POISON_HEADERS | pentesting/password_reset_poison.py | 18/8 | 44/18 |
| XSS payloads | pentesting/xss_basic.py | 7 | 35 |
| Command injection | pentesting/command_injection.py | 34 | 90 |
| CRLF_PAYLOADS | pentesting/crlf_injection.py | 14 | 34 |
| REDIRECT_PAYLOADS | pentesting/open_redirect.py | 15 | 42 |
| DEFAULT_CRED_CHECKS | pentesting/default_creds.py | 25 | 75 |
| BACKUP_EXTENSIONS | pentesting/backup_finder.py | 27 | 53 |
| DEBUG_PATHS | pentesting/debug_endpoints.py | 52 | 85 |
| _COOKIE_TECH | analysis/tech_detect.py | 24 | 53 |

### Раунд 2.5: Advanced attack payloads
| База | Файл | Было | Стало |
|------|------|------|-------|
| IP_BYPASS_VARIANTS | pentesting/ssrf_check.py | 11 | 40 |
| CLOUD_METADATA (SSRF) | pentesting/ssrf_check.py | 6 | 31 |
| PROTOCOL_SCHEMES | pentesting/ssrf_check.py | 4 | 13 |
| XXE_FILE_READ | pentesting/xxe_check.py | 8 | 22 |
| XXE_SSRF | pentesting/xxe_check.py | 4 | 12 |
| MATH_PROBES (SSTI) | pentesting/ssti_check.py | 10 | 32 |
| ENGINE_FINGERPRINTS (SSTI) | pentesting/ssti_check.py | 22 | 48 |
| BLIND_SSTI_PAYLOADS | pentesting/ssti_check.py | 7 | 20 |
| ALG_NONE_VARIANTS (JWT) | pentesting/jwt_attack.py | 6 | 18 |
| FALLBACK_WEAK_SECRETS (JWT) | pentesting/jwt_attack.py | 28 | 60+ |
| TE_OBFUSCATIONS | pentesting/http_smuggling.py | 20 | 45 |

### Раунд 3: Оставшиеся малые базы
| База | Файл | Было | Стало |
|------|------|------|-------|
| TOP_CREDENTIALS | pentesting/admin_brute.py | 15 | 43 |
| LOGIN_PAGES | pentesting/admin_brute.py | 10 | 28 |
| LOGIN_KEYWORDS | pentesting/admin_finder.py | 9 | 23 |
| WP_PLUGINS_TOP50 | pentesting/wp_deep_scan.py | 49 | 86 |
| WP_THEMES_TOP30 | pentesting/wp_deep_scan.py | 30 | 52 |
| AWS_METADATA_PATHS | pentesting/cloud_metadata_ssrf.py | 6 | 20 |
| AZURE_METADATA_PATHS | pentesting/cloud_metadata_ssrf.py | 2 | 12 |
| GCP_METADATA_PATHS | pentesting/cloud_metadata_ssrf.py | 3 | 15 |
| SENSITIVE_ENV_KEYS | pentesting/actuator_exploit.py | 14 | 50 |
| ACTUATOR_ENDPOINTS | pentesting/actuator_exploit.py | 10 | 31 |
| OPENAPI_PATHS | pentesting/actuator_exploit.py | 6 | 22 |
| GRAPHQL_PATHS | pentesting/actuator_exploit.py | 3 | 15 |
| IDOR_PATHS | pentesting/idor_check.py | 12 | 30 |
| QS_IDOR_PATHS | pentesting/idor_check.py | 6 | 18 |
| JSON_AGGREGATION (NoSQLi) | pentesting/nosqli_check.py | 14 | 28 |
| VERIFY_PROBES (SSTI) | pentesting/ssti_verify.py | 8 | 28 |
| DOM_SOURCES (XSS) | pentesting/xss_advanced.py | 11 | 24 |
| DOM_SINKS (XSS) | pentesting/xss_advanced.py | 21 | 49 |
| CSP_BYPASSES (XSS) | pentesting/xss_advanced.py | 5 | 13 types |
| SRV_SERVICES | recon/dns_enum.py | 24 | 53 |
| SPF_WEAK_PATTERNS | recon/dns_enum.py | 3 | 12 |
| WEAK_CIPHERS | scanning/tls_cipher_scan.py | 7 | 55 |

---

## Архитектурные заметки

### Паттерны Laravel в Basilisk
| Laravel | Basilisk | Файл |
|---------|----------|------|
| Service Container | PluginContext | core/executor.py |
| Facades | Audit fluent API | core/facade.py |
| Service Providers | BasePlugin.setup() | core/plugin.py |
| Pipeline | Pipeline phases | core/pipeline.py |
| Events | ctx.emit() + on_finding | core/executor.py |
| Eloquent | ResultRepository | storage/repo.py |
| Socialite | ProviderPool | core/providers.py |
| Artisan | Typer CLI | cli.py |
| Blade | Jinja2 templates | reporting/templates/ |
| Middleware | Pipeline phase hooks | core/pipeline.py |

### Ключевые инварианты
- Плагин НИКОГДА не создаёт сетевые клиенты — всё через ctx
- HIGH/CRITICAL findings ОБЯЗАНЫ иметь evidence (enforced в make_finding)
- Recon фаза расширяет scope (subdomains), остальные — нет
- Pipeline context (`ctx.pipeline`) передаёт данные между плагинами
- `ctx.state["http_scheme"]` — кэш реachability после recon фазы
