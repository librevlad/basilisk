# Basilisk v2.0.0 — Audit Notes (2026-02-12)

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
- [ ] **resolve_base_url** — оставлено как есть: `resolve_base_url` (singular) и `resolve_base_urls` (plural) — разная семантика, 50+ импортеров, перемещение нецелесообразно
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

#### Тесты для плагинов (85 из 110 без функциональных тестов)
Есть только meta + discovery тесты. Нужны mock-тесты для каждого плагина:
- HTTP-плагины: mock aiohttp responses
- DNS-плагины: mock dnspython
- Шаблон: `tests/test_plugins/test_<name>.py`

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
- [ ] `cors_scan` — сравнить с CORScanner, проверить bypass-методы
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

### Батч 3: Analysis (21 плагин)

**Security headers (пересечение!):**
- [ ] `http_headers` — CORS/CSP/HSTS/X-Frame → overlap с cors_scan, csp_analyzer
- [ ] `csp_analyzer` — глубокий CSP, сравнить с Google CSP Evaluator
- [ ] `waf_detect` — fingerprinting WAF продуктов
- [ ] `waf_bypass` — техники обхода, сравнить с wafw00f

**JS-анализ:**
- [ ] `js_api_extract` — endpoint extraction из JS, secrets (уже на utils/secrets.py)
- [ ] `js_secret_scan` — secrets в JS (уже на utils/secrets.py), проверить overlap с js_api_extract
- [ ] `comment_finder` — HTML/JS comments, может найти debug info

**CMS/Tech:**
- [ ] `tech_detect` — fingerprinting, сравнить с Wappalyzer/WhatWeb
- [ ] `cms_detect` — WordPress/Joomla/Drupal, проверить сигнатуры
- [ ] `version_detect` — версии софта из headers/meta/files

**Специализированные:**
- [ ] `takeover_check` — CNAME → dangling records, проверить fingerprints
- [ ] `openapi_parser` — Swagger/OpenAPI discovery + parsing
- [ ] `api_detect` — REST/GraphQL/SOAP endpoint обнаружение
- [ ] `security_txt` — /.well-known/security.txt
- [ ] `favicon_hash` — Shodan favicon hash matching
- [ ] `meta_extract` — HTML meta tags
- [ ] `link_extractor` — links + resources
- [ ] `form_analyzer` — form fields, CSRF tokens, action URLs
- [ ] `cloud_detect` — cloud provider по IP/headers
- [ ] `prometheus_scrape` — /metrics endpoint intelligence
- [ ] `ssl_cert_chain` — certificate chain validation

**Сравнение с инструментами:** Wappalyzer, WhatWeb, wafw00f, CSP Evaluator, nuclei

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
- **Отсутствие тестов**: ~85 плагинов без функциональных тестов

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
