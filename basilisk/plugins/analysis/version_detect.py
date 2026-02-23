"""Software version detection — headers, meta tags, error pages, and CVE mapping."""

from __future__ import annotations

import re
from typing import Any, ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.data.fingerprints import match_technologies
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target
from basilisk.utils.http_check import resolve_base_url

# ── Version header extraction patterns ────────────────────────────────

_HEADER_VERSION_RULES: list[tuple[str, str, str]] = [
    # (header_name, regex_pattern, tech_name)
    ("Server", r"(Apache)[/ ]*([\d.]+)", "Apache"),
    ("Server", r"(nginx)[/ ]*([\d.]+)", "nginx"),
    ("Server", r"(Microsoft-IIS)[/ ]*([\d.]+)", "IIS"),
    ("Server", r"(LiteSpeed)[/ ]*([\d.]+)", "LiteSpeed"),
    ("Server", r"(openresty)[/ ]*([\d.]+)", "OpenResty"),
    ("Server", r"(Caddy)[/ ]*([\d.]+)", "Caddy"),
    ("Server", r"(gunicorn)[/ ]*([\d.]+)", "Gunicorn"),
    ("Server", r"(Werkzeug)[/ ]*([\d.]+)", "Werkzeug"),
    ("Server", r"(Varnish)[/ ]*([\d.]+)", "Varnish"),
    ("Server", r"(Envoy)[/ ]*([\d.]+)", "Envoy"),
    ("Server", r"(uvicorn)[/ ]*([\d.]+)", "Uvicorn"),
    ("X-Powered-By", r"(PHP)[/ ]*([\d.]+)", "PHP"),
    ("X-Powered-By", r"(ASP\.NET)[/ ]*([\d.]+)", "ASP.NET"),
    ("X-Powered-By", r"(Express)", "Express"),
    ("X-Powered-By", r"(Next\.js)[/ ]*([\d.]+)", "Next.js"),
    ("X-Powered-By", r"(Nuxt\.js)[/ ]*([\d.]+)", "Nuxt.js"),
    ("X-Powered-By", r"(Phusion Passenger)[/ ]*([\d.]+)", "Passenger"),
    ("X-Powered-By", r"(Django)[/ ]*([\d.]+)?", "Django"),
    ("X-Powered-By", r"(Flask)[/ ]*([\d.]+)?", "Flask"),
    ("X-Powered-By", r"(FastAPI)[/ ]*([\d.]+)?", "FastAPI"),
    ("X-Powered-By", r"(Laravel)[/ ]*([\d.]+)?", "Laravel"),
    ("X-Powered-By", r"(Ruby on Rails)[/ ]*([\d.]+)?", "Ruby on Rails"),
    ("X-Powered-By", r"(Spring Boot)[/ ]*([\d.]+)?", "Spring Boot"),
    ("X-AspNet-Version", r"([\d.]+)", "ASP.NET"),
    ("X-Generator", r"(Drupal)\s*([\d.]+)?", "Drupal"),
    ("X-Generator", r"(WordPress)\s*([\d.]+)?", "WordPress"),
    ("X-Generator", r"(TYPO3 CMS)\s*([\d.]+)?", "TYPO3"),
    ("Via", r"(Varnish)[/ ]*([\d.]+)?", "Varnish"),
    ("Server", r"(HAProxy)[/ ]*([\d.]+)", "HAProxy"),
    ("X-Jenkins", r"([\d.]+)", "Jenkins"),
    ("X-Grafana-Version", r"([\d.]+)", "Grafana"),
    ("X-GitLab-Meta", r".*", "GitLab"),
    ("X-Powered-By", r"(Servlet)[/ ]*([\d.]+)?", "Tomcat"),
]

# ── Body / script version patterns ────────────────────────────────────

_BODY_VERSION_RULES: list[tuple[str, str]] = [
    (r"jquery[/.-]?(\d[\d.]+)(?:\.min)?\.js", "jQuery"),
    (r"bootstrap[/.-]?([\d.]+)(?:\.min)?\.(?:js|css)", "Bootstrap"),
    (r"vue[/.-]?([\d.]+)(?:\.min)?\.js", "Vue.js"),
    (r'react(?:-dom)?[/.-]([\d.]+)', "React"),
    (r"angular(?:\.min)?[/.-]?([\d.]+)", "Angular"),
    (r"lodash[/.-]?([\d.]+)", "Lodash"),
    (r"moment[/.-]?([\d.]+)", "Moment.js"),
    (r"wordpress[/ ]+([\d.]+)", "WordPress"),
    (r"ckeditor[/.-]?([\d.]+)", "CKEditor"),
    (r"tinymce[/.-]?([\d.]+)", "TinyMCE"),
    (r"nuxt[/.-]?([\d.]+)", "Nuxt.js"),
    (r"next[/.-]data[/.-]?([\d.]+)?", "Next.js"),
    (r"express[/.-]?([\d.]+)", "Express"),
    (r"phpmyadmin[/.-]?([\d.]+)", "phpMyAdmin"),
    (r"grafana[/.-]?([\d.]+)", "Grafana"),
    (r"kibana[/.-]?([\d.]+)", "Kibana"),
    (r"sonarqube[/.-]?([\d.]+)", "SonarQube"),
    (r"jenkins[/.-]?([\d.]+)", "Jenkins"),
]

# ── Meta tag generator patterns ───────────────────────────────────────

_META_GENERATOR_RULES: list[tuple[str, str]] = [
    (r"WordPress\s+([\d.]+)", "WordPress"),
    (r"Joomla!\s*([\d.]+)", "Joomla"),
    (r"Drupal\s+([\d.]+)", "Drupal"),
    (r"MediaWiki\s+([\d.]+)", "MediaWiki"),
    (r"Ghost\s+([\d.]+)", "Ghost"),
    (r"TYPO3 CMS\s*([\d.]+)?", "TYPO3"),
    (r"Magento\s*([\d.]+)?", "Magento"),
    (r"Adobe Commerce\s*([\d.]+)?", "Magento"),
    (r"Wix\.com", "Wix"),
    (r"Blogger", "Blogger"),
    (r"Hugo\s+([\d.]+)", "Hugo"),
    (r"Jekyll\s+v?([\d.]+)", "Jekyll"),
    (r"Gatsby\s+([\d.]+)", "Gatsby"),
]

# ── Known vulnerable version ranges ──────────────────────────────────
# Format: tech -> list of (comparator, version, severity, CVE/description)

_VULNERABLE_VERSIONS: dict[str, list[tuple[str, str, str, str]]] = {
    # ── Web Servers ──────────────────────────────────────────────────
    "Apache": [
        ("lt", "2.4.62", "high", "CVE-2024-38476: server-side request forgery"),
        ("lt", "2.4.60", "high", "CVE-2024-36387: HTTP/2 null pointer DoS"),
        ("lt", "2.4.59", "high", "CVE-2024-27316: HTTP/2 memory exhaustion"),
        ("lt", "2.4.58", "high", "CVE-2023-43622 / CVE-2023-45802: HTTP/2 DoS"),
        ("lt", "2.4.56", "high", "CVE-2023-27522: mod_proxy_uwsgi response splitting"),
        ("lt", "2.4.55", "high", "CVE-2023-25690: HTTP request smuggling"),
        ("lt", "2.4.54", "high", "CVE-2022-31813: X-Forwarded-* header bypass"),
        ("lt", "2.4.52", "medium", "CVE-2022-22721: mod_lua buffer overflow"),
        ("lt", "2.4.51", "critical", "CVE-2021-41773: path traversal / RCE"),
        ("lt", "2.4.49", "high", "CVE-2021-40438: SSRF in mod_proxy"),
        ("lt", "2.4.46", "medium", "CVE-2020-11984: mod_proxy_uwsgi overflow"),
    ],
    "nginx": [
        ("lt", "1.26.1", "high", "CVE-2024-31079: HTTP/3 stack buffer overflow"),
        ("lt", "1.25.5", "high", "CVE-2024-32760: HTTP/3 buffer overwrite"),
        ("lt", "1.25.4", "high", "CVE-2024-24989/24990: HTTP/3 null pointer DoS"),
        ("lt", "1.25.3", "medium", "CVE-2023-44487: HTTP/2 rapid reset"),
        ("lt", "1.23.3", "medium", "CVE-2022-41741: mp4 module memory corruption"),
        ("lt", "1.21.0", "medium", "CVE-2021-3618: ALPACA TLS cross-protocol attack"),
    ],
    "IIS": [
        ("lt", "10.0", "medium", "IIS < 10 is on unsupported Windows versions"),
        ("lt", "8.5", "high", "CVE-2017-7269: WebDAV buffer overflow (RCE)"),
    ],
    "LiteSpeed": [
        ("lt", "6.1.1", "high", "CVE-2023-40518: HTTP request smuggling"),
        ("lt", "6.0.12", "medium", "Multiple security fixes in 6.0.12+"),
    ],
    "OpenResty": [
        ("lt", "1.25.3", "medium", "Bundled nginx CVEs including HTTP/2 rapid reset"),
        ("lt", "1.21.4", "medium", "Multiple nginx CVEs in bundled nginx"),
    ],
    "Tomcat": [
        ("lt", "10.1.19", "medium", "CVE-2024-23672: WebSocket DoS"),
        ("lt", "10.1.16", "high", "CVE-2023-46589: HTTP request smuggling"),
        ("lt", "10.1.14", "high", "CVE-2023-44487: HTTP/2 rapid reset DoS"),
        ("lt", "10.1.13", "medium", "CVE-2023-41080: open redirect"),
        ("lt", "10.1.9", "medium", "CVE-2023-28709: DoS via excessive headers"),
        ("lt", "9.0.84", "medium", "CVE-2024-21733: HTTP connector info leak"),
        ("lt", "9.0.83", "high", "CVE-2023-46589: HTTP request smuggling (9.0.x)"),
        ("lt", "9.0.81", "high", "CVE-2023-44487: HTTP/2 rapid reset DoS (9.0.x)"),
        ("lt", "9.0.80", "medium", "CVE-2023-41080: open redirect (9.0.x)"),
        ("lt", "9.0.74", "medium", "CVE-2023-28709: DoS via excessive headers (9.0.x)"),
        ("lt", "8.5.97", "high", "CVE-2023-46589: request smuggling (8.5.x)"),
    ],
    "Envoy": [
        ("lt", "1.28.1", "high", "CVE-2023-44487: HTTP/2 rapid reset DoS"),
        ("lt", "1.27.2", "high", "CVE-2023-35945: HTTP/2 memory leak on RST"),
        ("lt", "1.26.6", "medium", "CVE-2023-35943: CORS filter origin bypass"),
    ],
    "HAProxy": [
        ("lt", "2.8.4", "high", "CVE-2023-44487: HTTP/2 rapid reset DoS"),
        ("lt", "2.7.3", "high", "CVE-2023-25725: HTTP request smuggling via headers"),
        ("lt", "2.6.7", "high", "CVE-2023-0836: HTTP/2 stream handling info leak"),
        ("lt", "2.2.30", "medium", "CVE-2023-45539: URI normalization bypass"),
    ],
    "Varnish": [
        ("lt", "7.4.2", "high", "CVE-2023-44487: HTTP/2 rapid reset DoS"),
        ("lt", "7.3.1", "high", "CVE-2022-45060: HTTP request smuggling"),
        ("lt", "7.1.2", "medium", "CVE-2022-23959: request smuggling via HTTP/1 pipelining"),
    ],
    "Caddy": [
        ("lt", "2.7.5", "medium", "CVE-2023-44487: HTTP/2 rapid reset DoS"),
        ("lt", "2.6.3", "medium", "CVE-2023-45142: OpenTelemetry middleware DoS"),
    ],
    "Gunicorn": [
        ("lt", "22.0.0", "high", "CVE-2024-1135: HTTP request smuggling"),
        ("lt", "21.2.0", "medium", "CVE-2024-1135: request smuggling (older branches)"),
    ],
    "Werkzeug": [
        ("lt", "3.0.3", "critical", "CVE-2024-34069: debugger RCE via eval"),
        ("lt", "3.0.1", "high", "CVE-2023-46136: multipart form DoS"),
        ("lt", "2.3.8", "high", "CVE-2023-46136: DoS in older 2.3.x"),
        ("lt", "2.2.3", "high", "CVE-2023-25577: multipart parser DoS"),
    ],
    "Uvicorn": [
        ("lt", "0.27.1", "high", "CVE-2024-24762: multipart DoS via python-multipart"),
        ("lt", "0.25.0", "medium", "Multiple security fixes in 0.25.0+"),
    ],
    "Passenger": [
        ("lt", "6.0.19", "high", "CVE-2024-34507: request smuggling"),
        ("lt", "6.0.17", "medium", "CVE-2023-44487: HTTP/2 rapid reset DoS"),
    ],
    # ── TLS / Crypto ─────────────────────────────────────────────────
    "OpenSSL": [
        ("lt", "3.2.1", "medium", "CVE-2024-0727: PKCS12 null pointer DoS"),
        ("lt", "3.1.5", "medium", "CVE-2023-5678: DH key generation DoS"),
        ("lt", "3.1.2", "medium", "CVE-2023-3817: DH_check excessive time"),
        ("lt", "3.0.7", "critical", "CVE-2022-3602 / CVE-2022-3786: X.509 buffer overflows"),
        ("lt", "3.0.2", "high", "CVE-2022-0778: BN_mod_sqrt infinite loop DoS"),
        ("lt", "1.1.1w", "high", "CVE-2023-5678: DH generation DoS (1.1.1 branch)"),
        ("lt", "1.1.1t", "high", "CVE-2023-0286: X.400 address type confusion"),
        ("lt", "1.1.1s", "medium", "CVE-2022-4450: PEM_read_bio double free"),
    ],
    # ── Programming languages / runtimes ─────────────────────────────
    "PHP": [
        ("lt", "8.3.8", "critical", "CVE-2024-4577: CGI argument injection RCE"),
        ("lt", "8.3.4", "high", "CVE-2024-2756: password_verify bypass"),
        ("lt", "8.2.20", "critical", "CVE-2024-4577: CGI argument injection (8.2.x)"),
        ("lt", "8.2.17", "high", "CVE-2024-2756: cookie bypass in older 8.2.x"),
        ("lt", "8.1.29", "critical", "CVE-2024-4577: CGI argument injection (8.1.x)"),
        ("lt", "8.1.0", "medium", "PHP 8.0.x is end-of-life"),
        ("lt", "7.5.0", "high", "PHP 7.x is end-of-life, no security patches"),
    ],
    "ASP.NET": [
        ("lt", "4.8", "medium", "Older ASP.NET versions have known vulnerabilities"),
    ],
    # ── CMS ──────────────────────────────────────────────────────────
    "WordPress": [
        ("lt", "6.5.2", "high", "Multiple security fixes in WordPress 6.5.2"),
        ("lt", "6.4.3", "high", "CVE-2024-0942: admin bypass vulnerability"),
        ("lt", "6.3.2", "high", "Multiple security fixes in 6.3.2+"),
        ("lt", "6.2.3", "high", "CVE-2023-5561: user email disclosure via REST API"),
        ("lt", "6.1.4", "high", "CVE-2023-22622: unauthenticated blind SSRF"),
        ("lt", "5.8.10", "critical", "CVE-2022-21661: SQL injection in WP_Query"),
        ("lt", "5.6.0", "high", "Multiple XSS and CSRF fixes in 5.6+"),
        ("lt", "5.0.0", "high", "Legacy WordPress, multiple critical vulnerabilities"),
    ],
    "Joomla": [
        ("lt", "5.0.3", "high", "CVE-2024-21726: XSS vulnerability"),
        ("lt", "4.4.3", "high", "CVE-2024-21726: XSS in mail template"),
        ("lt", "4.3.4", "high", "CVE-2023-40626: XSS in mail template output"),
        ("lt", "4.2.8", "critical", "CVE-2023-23752: unauthenticated info disclosure"),
        ("lt", "4.2.7", "high", "CVE-2023-23751: improper access check"),
        ("lt", "3.10.12", "high", "Multiple security fixes in 3.10.12+ (LTS)"),
    ],
    "Drupal": [
        ("lt", "10.2.3", "high", "SA-CORE-2024-001: access bypass"),
        ("lt", "10.1.8", "high", "CVE-2023-31250: file download access bypass"),
        ("lt", "9.5.11", "high", "CVE-2023-31250: file download bypass (9.5.x)"),
        ("lt", "9.4.0", "high", "CVE-2022-25277: RCE via uploaded .htaccess"),
        ("lt", "8.9.0", "critical", "CVE-2019-6340: RESTful API deserialization RCE"),
        ("lt", "7.100", "critical", "Drupal 7 is end-of-life, no security patches"),
    ],
    "Ghost": [
        ("lt", "5.59.4", "high", "CVE-2023-40028: arbitrary file read via symlinks"),
        ("lt", "5.42.1", "high", "CVE-2022-47194: stored XSS via SVG upload"),
        ("lt", "5.35.0", "medium", "Multiple security fixes in 5.35.0+"),
    ],
    "MediaWiki": [
        ("lt", "1.41.1", "high", "CVE-2023-45359: RCE via crafted page content"),
        ("lt", "1.39.6", "high", "CVE-2023-22911: XSS in Special:Search"),
        ("lt", "1.39.4", "medium", "CVE-2023-29197: HTTP message parsing bypass"),
        ("lt", "1.35.0", "high", "Multiple security fixes, upgrade strongly recommended"),
    ],
    "TYPO3": [
        ("lt", "12.4.4", "high", "CVE-2023-38500: XSS in form framework"),
        ("lt", "12.4.2", "high", "CVE-2023-24814: authentication bypass"),
        ("lt", "11.5.30", "high", "CVE-2023-38500: XSS in form framework (11.5.x)"),
    ],
    "Magento": [
        ("lt", "2.4.7", "critical", "CVE-2024-20720: RCE via crafted layout template"),
        ("lt", "2.4.6.4", "high", "CVE-2023-38218: stored XSS in admin panel"),
        ("lt", "2.4.4", "critical", "CVE-2022-24086: improper input validation RCE"),
        ("lt", "2.4.3.2", "critical", "CVE-2022-24086: RCE (older 2.4.3.x)"),
    ],
    # ── JavaScript frameworks / libraries ────────────────────────────
    "jQuery": [
        ("lt", "3.5.0", "medium", "CVE-2020-11022/11023: XSS in htmlPrefilter"),
        ("lt", "3.0.0", "high", "CVE-2019-11358: prototype pollution"),
        ("lt", "1.12.0", "high", "CVE-2015-9251: XSS vulnerability"),
        ("lt", "1.9.0", "high", "CVE-2020-7656: XSS via load() method"),
        ("lt", "1.6.3", "high", "CVE-2012-6708: selector-based XSS"),
    ],
    "Vue.js": [
        ("lt", "3.4.15", "medium", "Multiple security fixes in 3.4.15+"),
        ("lt", "3.2.47", "medium", "CVE-2023-22462: XSS via component render"),
        ("lt", "2.7.16", "medium", "CVE-2024-6783: XSS via transition component"),
        ("lt", "2.6.0", "high", "Vue 2.x < 2.6 has known XSS issues"),
    ],
    "Angular": [
        ("lt", "17.3.0", "medium", "Multiple security fixes in Angular 17.3+"),
        ("lt", "16.2.10", "medium", "CVE-2023-26117: ReDoS in semver range parsing"),
        ("lt", "16.1.7", "medium", "CVE-2023-26117: ReDoS in angular-expressions"),
        ("lt", "14.2.12", "high", "CVE-2022-25869: XSS via sanitizer bypass"),
        ("lt", "12.0.0", "medium", "Angular < 12 is end-of-life"),
    ],
    "React": [
        ("lt", "18.0.0", "low", "React < 18 is in maintenance mode"),
        ("lt", "16.13.0", "medium", "Multiple XSS fixes in React 16.13+"),
    ],
    "Lodash": [
        ("lt", "4.17.21", "critical", "CVE-2021-23337: template command injection"),
        ("lt", "4.17.20", "high", "CVE-2020-28500: ReDoS in toNumber/trim"),
        ("lt", "4.17.12", "high", "CVE-2019-10744: prototype pollution via defaultsDeep"),
        ("lt", "4.17.5", "high", "CVE-2018-16487: prototype pollution"),
    ],
    "Moment.js": [
        ("lt", "2.29.4", "high", "CVE-2022-31129: ReDoS in RFC 2822 parser"),
        ("lt", "2.29.2", "medium", "CVE-2022-24785: path traversal in locale loading"),
        ("lt", "2.19.3", "medium", "CVE-2017-18214: ReDoS in parsing"),
    ],
    "Express": [
        ("lt", "4.20.0", "medium", "CVE-2024-43796: XSS via response.redirect()"),
        ("lt", "4.19.2", "medium", "CVE-2024-29041: open redirect in res.location"),
        ("lt", "4.17.3", "medium", "CVE-2022-24999: qs prototype pollution DoS"),
    ],
    "Next.js": [
        ("lt", "14.1.1", "high", "CVE-2024-34351: SSRF via Server Actions"),
        ("lt", "14.0.4", "high", "CVE-2024-46982: cache poisoning via CacheHandler"),
        ("lt", "13.5.1", "medium", "CVE-2024-56337: TOCTOU race condition"),
        ("lt", "13.4.0", "medium", "Multiple security fixes in 13.4+"),
    ],
    "Nuxt.js": [
        ("lt", "3.5.3", "critical", "CVE-2023-3224: RCE via devtools config"),
        ("lt", "3.4.3", "medium", "Multiple security fixes in 3.4.3+"),
    ],
    "Bootstrap": [
        ("lt", "5.3.3", "medium", "CVE-2024-6484: XSS in carousel component"),
        ("lt", "4.3.1", "medium", "CVE-2019-8331: XSS in tooltip/popover"),
        ("lt", "4.1.2", "medium", "CVE-2018-14042: XSS in data-container attr"),
        ("lt", "3.4.1", "medium", "CVE-2019-8331: XSS in tooltip/popover (3.x)"),
        ("lt", "3.4.0", "high", "CVE-2018-14040: XSS in collapse plugin"),
    ],
    "CKEditor": [
        ("lt", "4.24.0", "medium", "CVE-2024-24816: XSS in samples pages"),
        ("lt", "4.22.0", "high", "CVE-2023-28439: XSS in HTML parser"),
        ("lt", "4.18.0", "high", "CVE-2022-24728: XSS in HTML data processor"),
    ],
    "TinyMCE": [
        ("lt", "6.8.1", "medium", "CVE-2024-29203: XSS in noscript handling"),
        ("lt", "6.7.1", "medium", "CVE-2023-48219: XSS via mXSS nesting"),
        ("lt", "5.10.9", "medium", "CVE-2024-29203: XSS in noscript (5.x branch)"),
    ],
    # ── Databases ────────────────────────────────────────────────────
    "MySQL": [
        ("lt", "8.3.0", "medium", "CVE-2024-20960: optimizer DoS vulnerability"),
        ("lt", "8.0.35", "medium", "CVE-2023-22008: optimizer DoS (8.0.x)"),
        ("lt", "8.0.32", "medium", "CVE-2023-21977: optimizer info disclosure"),
        ("lt", "5.7.42", "high", "Multiple security fixes in 5.7.42+ (last 5.7)"),
    ],
    "PostgreSQL": [
        ("lt", "16.1", "high", "CVE-2023-5869: integer overflow in array processing"),
        ("lt", "16.0", "high", "CVE-2023-39417: SQL injection in extension scripts"),
        ("lt", "15.5", "high", "CVE-2023-5869: integer overflow (15.x branch)"),
        ("lt", "14.10", "high", "CVE-2023-5869: integer overflow (14.x branch)"),
        ("lt", "13.13", "high", "CVE-2023-5869: integer overflow (13.x branch)"),
    ],
    "Redis": [
        ("lt", "7.2.6", "medium", "CVE-2024-31228: DoS via pattern matching"),
        ("lt", "7.2.4", "medium", "CVE-2023-45145: unix socket race condition"),
        ("lt", "7.0.15", "high", "CVE-2023-41056: heap overflow in networking"),
        ("lt", "6.2.14", "medium", "CVE-2023-45145: unix socket race (6.2.x)"),
    ],
    "MongoDB": [
        ("lt", "7.0.6", "high", "CVE-2024-1351: authentication bypass in mongos"),
        ("lt", "7.0.3", "medium", "CVE-2023-1409: TLS certificate validation bypass"),
        ("lt", "6.0.12", "high", "CVE-2024-1351: auth bypass (6.0.x branch)"),
        ("lt", "5.0.22", "medium", "CVE-2023-1409: TLS bypass (5.0.x branch)"),
    ],
    "Elasticsearch": [
        ("lt", "8.11.2", "medium", "CVE-2023-46674: sensitive info in error messages"),
        ("lt", "8.9.1", "high", "CVE-2023-31419: DoS via _search API"),
        ("lt", "7.17.16", "medium", "CVE-2023-46674: info leak (7.17.x branch)"),
        ("lt", "7.17.13", "high", "CVE-2023-31419: DoS (7.17.x branch)"),
    ],
    # ── Monitoring / Admin tools ─────────────────────────────────────
    "Grafana": [
        ("lt", "10.3.3", "high", "CVE-2024-1313: unauthorized dashboard deletion"),
        ("lt", "10.2.3", "high", "CVE-2023-6152: email validation bypass"),
        ("lt", "10.1.0", "critical", "CVE-2023-3128: Azure AD auth bypass"),
        ("lt", "9.5.13", "high", "CVE-2023-6152: email bypass (9.5.x)"),
        ("lt", "9.4.7", "critical", "CVE-2023-3128: Azure AD auth bypass (9.x)"),
    ],
    "Prometheus": [
        ("lt", "2.48.1", "medium", "CVE-2024-6104: credentials in debug logs"),
        ("lt", "2.47.2", "medium", "CVE-2023-45142: OpenTelemetry DoS"),
    ],
    "Jenkins": [
        ("lt", "2.442", "critical", "CVE-2024-23897: arbitrary file read via CLI"),
        ("lt", "2.441", "high", "CVE-2024-23898: CSRF via WebSocket hijacking"),
        ("lt", "2.400", "high", "CVE-2023-27898: stored XSS via plugin manager"),
        ("lt", "2.375", "high", "CVE-2023-24422: sandbox bypass in Script Security"),
        ("lt", "2.346", "medium", "Multiple security fixes in 2.346+"),
    ],
    "GitLab": [
        ("lt", "16.8.1", "critical", "CVE-2024-0402: arbitrary file write via workspace"),
        ("lt", "16.7.2", "critical", "CVE-2023-7028: account takeover via password reset"),
        ("lt", "16.1.5", "high", "CVE-2023-5009: group approval policy bypass"),
        ("lt", "16.0.8", "critical", "CVE-2023-2825: path traversal to file read"),
        ("lt", "15.11.13", "high", "CVE-2023-2825: path traversal (15.x branch)"),
    ],
    "SonarQube": [
        ("lt", "10.3.0", "high", "CVE-2024-47911: SSRF via project badges"),
        ("lt", "9.9.5", "high", "CVE-2024-47911: SSRF (9.9 LTS branch)"),
        ("lt", "9.9.0", "medium", "Multiple security fixes in 9.9 LTS+"),
    ],
    "Kibana": [
        ("lt", "8.14.2", "critical", "CVE-2024-37287: prototype pollution to RCE"),
        ("lt", "8.11.1", "critical", "CVE-2023-31415: RCE via XSRF in Timelion"),
        ("lt", "7.17.16", "medium", "Multiple security fixes in 7.17.16+"),
    ],
    "phpMyAdmin": [
        ("lt", "5.2.1", "medium", "CVE-2023-25727: XSS via MIME column"),
        ("lt", "5.1.2", "medium", "CVE-2022-23808: XSS in setup and navigation"),
        ("lt", "5.1.1", "high", "CVE-2022-23807: auth bypass in two-factor"),
        ("lt", "4.9.11", "high", "CVE-2022-23808: XSS (4.x branch)"),
    ],
    # ── Python frameworks ────────────────────────────────────────────
    "Django": [
        ("lt", "5.0.7", "medium", "CVE-2024-39614: ReDoS in get_supported_language"),
        ("lt", "5.0.6", "medium", "CVE-2024-38875: DoS via URL path parameter"),
        ("lt", "5.0.2", "medium", "CVE-2024-24680: DoS in intcomma template filter"),
        ("lt", "4.2.16", "medium", "CVE-2024-39614: ReDoS (4.2.x branch)"),
        ("lt", "4.2.15", "medium", "CVE-2023-43665: DoS in Truncator/truncatechars"),
        ("lt", "4.2.10", "high", "CVE-2023-31047: file upload bypass multiple handlers"),
        ("lt", "3.2.0", "high", "Django 3.1 and below are end-of-life"),
    ],
    "Flask": [
        ("lt", "3.0.0", "medium", "Multiple security improvements in Flask 3.0+"),
        ("lt", "2.3.2", "high", "CVE-2023-30861: session cookie leak on redirect"),
        ("lt", "2.2.5", "medium", "CVE-2023-30861: cookie leak (2.2.x branch)"),
    ],
    "FastAPI": [
        ("lt", "0.109.1", "high", "CVE-2024-24762: multipart DoS via python-multipart"),
        ("lt", "0.100.0", "medium", "Multiple security fixes in 0.100+"),
    ],
    # ── Ruby frameworks ──────────────────────────────────────────────
    "Ruby on Rails": [
        ("lt", "7.1.3.2", "medium", "CVE-2024-26142: ReDoS in Accept header parsing"),
        ("lt", "7.0.8.1", "medium", "CVE-2024-26142: ReDoS (7.0.x branch)"),
        ("lt", "7.0.7.2", "medium", "CVE-2023-28362: redirect_to open redirect"),
        ("lt", "7.0.4.3", "medium", "CVE-2023-22796: ReDoS in ActiveSupport"),
        ("lt", "7.0.4.2", "high", "CVE-2023-22794: SQL injection in Active Record"),
        ("lt", "6.1.7.6", "medium", "CVE-2023-28362: redirect_to bypass (6.1.x)"),
        ("lt", "6.0.0", "high", "Rails 5.x is end-of-life, no security patches"),
    ],
    # ── Java frameworks ──────────────────────────────────────────────
    "Spring Boot": [
        ("lt", "3.2.3", "high", "CVE-2024-22259: URL redirect validation bypass"),
        ("lt", "3.1.8", "high", "CVE-2024-22243: URL parsing redirect bypass"),
        ("lt", "3.0.13", "medium", "CVE-2023-34053: DoS via HTTP request handling"),
        ("lt", "2.7.18", "medium", "Multiple security fixes in last 2.7.x LTS"),
    ],
    "Spring": [
        ("lt", "6.1.5", "high", "CVE-2024-22259: URL redirect validation bypass"),
        ("lt", "6.1.4", "high", "CVE-2024-22243: URL parsing redirect bypass"),
        ("lt", "6.0.17", "medium", "CVE-2023-34053: DoS via HTTP request"),
        ("lt", "5.3.31", "high", "CVE-2023-34053: DoS (5.3.x last branch)"),
        ("lt", "5.3.18", "critical", "CVE-2022-22965: Spring4Shell RCE"),
        ("lt", "5.2.0", "high", "Spring Framework 5.1 and below are EOL"),
    ],
    "Struts": [
        ("lt", "6.3.0.2", "critical", "CVE-2023-50164: file upload path traversal RCE"),
        ("lt", "6.1.2.2", "critical", "CVE-2023-50164: file upload RCE (6.1.x)"),
        ("lt", "2.5.33", "critical", "CVE-2023-50164: file upload RCE (2.5.x)"),
        ("lt", "2.5.30", "critical", "CVE-2021-31805: OGNL injection RCE"),
    ],
    # ── PHP frameworks ───────────────────────────────────────────────
    "Laravel": [
        ("lt", "10.48.4", "medium", "CVE-2024-29291: timing-based user enumeration"),
        ("lt", "9.52.16", "medium", "CVE-2024-29291: timing side-channel (9.x branch)"),
        ("lt", "9.32.0", "high", "CVE-2022-40799: file access via storage link"),
        ("lt", "8.0.0", "medium", "Laravel 7.x and below are end-of-life"),
    ],
    # ── Other tools/technologies ─────────────────────────────────────
    "Wix": [],
    "Blogger": [],
}

# Total entry count validation — keep above 200
_TOTAL_CVE_ENTRIES = sum(len(v) for v in _VULNERABLE_VERSIONS.values())
assert _TOTAL_CVE_ENTRIES >= 200, (
    f"Expected 200+ CVE entries, got {_TOTAL_CVE_ENTRIES}"
)

# Server-side technologies — version disclosure is higher risk
_SERVER_SIDE = frozenset({
    # Web servers
    "Apache", "nginx", "IIS", "LiteSpeed", "OpenResty", "Caddy",
    "Gunicorn", "Werkzeug", "Uvicorn", "Tomcat", "Passenger",
    # Proxies / load balancers
    "Envoy", "HAProxy", "Varnish",
    # TLS / crypto
    "OpenSSL",
    # Languages / runtimes
    "PHP", "ASP.NET",
    # JS server frameworks
    "Express", "Next.js", "Nuxt.js",
    # CMS
    "WordPress", "Joomla", "Drupal", "Ghost", "MediaWiki",
    "TYPO3", "Magento",
    # Python frameworks
    "Django", "Flask", "FastAPI",
    # Ruby
    "Ruby on Rails",
    # Java
    "Spring", "Spring Boot", "Struts",
    # PHP frameworks
    "Laravel",
    # Databases (when exposed)
    "MySQL", "PostgreSQL", "Redis", "MongoDB", "Elasticsearch",
    # Monitoring / admin
    "Grafana", "Prometheus", "Jenkins", "GitLab", "SonarQube",
    "Kibana", "phpMyAdmin",
})


def _parse_version(ver: str) -> tuple[int, ...]:
    """Parse a dotted version string into a tuple of integers."""
    parts: list[int] = []
    for segment in ver.split("."):
        # Strip non-numeric suffixes (e.g. "2.4.54ubuntu4")
        num = ""
        for ch in segment:
            if ch.isdigit():
                num += ch
            else:
                break
        if num:
            parts.append(int(num))
    return tuple(parts)


def _version_lt(version: str, threshold: str) -> bool:
    """Return True if version < threshold using simple tuple comparison."""
    v = _parse_version(version)
    t = _parse_version(threshold)
    if not v or not t:
        return False
    return v < t


def _check_cves(
    tech: str, version: str,
) -> list[dict[str, str]]:
    """Check a detected version against known vulnerable ranges."""
    rules = _VULNERABLE_VERSIONS.get(tech, [])
    hits: list[dict[str, str]] = []
    for comparator, threshold, severity, description in rules:
        if comparator == "lt" and _version_lt(version, threshold):
            hits.append({
                "threshold": threshold,
                "severity": severity,
                "description": description,
            })
    return hits


class VersionDetectPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="version_detect",
        display_name="Version Detector",
        category=PluginCategory.ANALYSIS,
        description=(
            "Detects software versions from headers, meta tags, "
            "error pages, and maps to known CVEs"
        ),
        produces=["versions"],
        timeout=20.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        findings: list[Finding] = []
        versions: dict[str, str] = {}
        cve_hits: list[dict[str, Any]] = []

        base_url = await resolve_base_url(target.host, ctx)
        if not base_url:
            findings.append(Finding.info(
                "Target not reachable via HTTP/HTTPS",
                tags=["analysis", "version"],
            ))
            return PluginResult.success(
                self.meta.name, target.host,
                findings=findings,
                data={"versions": versions},
            )

        headers: dict[str, str] = {}
        body = ""

        # ── Fetch main page ──────────────────────────────────────
        try:
            async with ctx.rate:
                resp = await ctx.http.get(f"{base_url}/", timeout=8.0)
                headers = dict(resp.headers)
                body = await resp.text(encoding="utf-8", errors="replace")
        except Exception as exc:
            ctx.log.debug("version_detect: main page fetch failed: %s", exc)

        # ── 1. Header-based version detection ────────────────────
        for hdr_name, pattern, tech in _HEADER_VERSION_RULES:
            hdr_value = headers.get(hdr_name, "")
            if not hdr_value:
                # Case-insensitive header lookup
                for k, v in headers.items():
                    if k.lower() == hdr_name.lower():
                        hdr_value = v
                        break
            if hdr_value:
                match = re.search(pattern, hdr_value, re.IGNORECASE)
                if match:
                    ver = match.group(2) if match.lastindex and match.lastindex >= 2 else ""
                    if tech not in versions or (
                        ver and versions.get(tech) == "detected"
                    ):
                        versions[tech] = ver or "detected"

        # ── 2. Meta tag generator detection ──────────────────────
        generator_match = re.search(
            r'<meta[^>]+name=["\']?generator["\']?[^>]+content=["\']([^"\']+)',
            body,
            re.IGNORECASE,
        )
        if generator_match:
            gen_content = generator_match.group(1).strip()
            for pattern, tech in _META_GENERATOR_RULES:
                m = re.search(pattern, gen_content, re.IGNORECASE)
                if m:
                    ver = m.group(1) if m.lastindex and m.lastindex >= 1 else ""
                    if tech not in versions or (
                        ver and versions.get(tech) == "detected"
                    ):
                        versions[tech] = ver or "detected"
                    break

        # ── 3. Body / script version patterns ────────────────────
        for pattern, tech in _BODY_VERSION_RULES:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                ver = match.group(1) if match.lastindex and match.lastindex >= 1 else ""
                if tech not in versions or (
                    ver and versions.get(tech) == "detected"
                ):
                    versions[tech] = ver or "detected"

        # ── 4. Fingerprint DB integration ────────────────────────
        fp_techs = match_technologies(headers, body)
        for tech_info in fp_techs:
            name = tech_info["name"]
            ver = tech_info.get("version", "")
            if ver and (
                name not in versions
                or versions.get(name) in ("", "detected")
            ):
                versions[name] = ver

        # ── 5. Error page version disclosure ─────────────────────
        if not ctx.should_stop:
            await self._check_error_page(
                base_url, ctx, versions, findings,
            )

        # ── 6. Generate findings ─────────────────────────────────
        for tech, ver in sorted(versions.items()):
            is_server = tech in _SERVER_SIDE

            # Check for known CVEs
            if ver and ver != "detected":
                hits = _check_cves(tech, ver)
                for hit in hits:
                    sev = hit["severity"]
                    desc = hit["description"]
                    cve_hits.append({
                        "technology": tech,
                        "version": ver,
                        **hit,
                    })
                    # Map severity string to Finding factory
                    factory = {
                        "critical": Finding.critical,
                        "high": Finding.high,
                        "medium": Finding.medium,
                        "low": Finding.low,
                    }.get(sev, Finding.medium)
                    findings.append(factory(
                        f"Vulnerable {tech} {ver}: {desc}",
                        evidence=f"Detected {tech} {ver} (threshold: {hit['threshold']})",
                        description=(
                            f"{tech} {ver} is below the safe threshold "
                            f"{hit['threshold']}. "
                            "Upgrade to fix known vulnerabilities."
                        ),
                        remediation=f"Upgrade {tech} to >= {hit['threshold']}",
                        tags=["analysis", "version", "cve"],
                    ))

            # Version disclosure finding
            if is_server:
                # Only report if not already covered by a CVE finding
                if not any(
                    h["technology"] == tech for h in cve_hits
                ):
                    findings.append(Finding.low(
                        f"{tech} version disclosed: {ver}",
                        description=(
                            "Server-side version disclosure helps attackers "
                            "identify known vulnerabilities for targeted attacks."
                        ),
                        remediation=f"Hide {tech} version information",
                        tags=["analysis", "version", "info-disclosure"],
                    ))
            else:
                findings.append(Finding.info(
                    f"{tech}: {ver}",
                    tags=["analysis", "version"],
                ))

        if not versions:
            findings.append(Finding.info(
                "No software versions detected",
                tags=["analysis", "version"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "versions": versions,
                "cve_hits": cve_hits,
                "fingerprint_techs": [
                    {"name": t["name"], "confidence": t["confidence"]}
                    for t in fp_techs[:20]
                ],
            },
        )

    async def _check_error_page(
        self,
        base_url: str,
        ctx,
        versions: dict[str, str],
        findings: list[Finding],
    ) -> None:
        """Probe a non-existent path for version info in error pages."""
        try:
            async with ctx.rate:
                resp = await ctx.http.get(
                    f"{base_url}/nonexistent-page-bslk-12345",
                    timeout=8.0,
                )
                if resp.status in (404, 403, 500):
                    error_body = await resp.text(
                        encoding="utf-8", errors="replace",
                    )
                    error_headers = dict(resp.headers)

                    # Check error page headers
                    for hdr_name, pattern, tech in _HEADER_VERSION_RULES:
                        hdr_val = ""
                        for k, v in error_headers.items():
                            if k.lower() == hdr_name.lower():
                                hdr_val = v
                                break
                        if hdr_val:
                            match = re.search(pattern, hdr_val, re.IGNORECASE)
                            if match:
                                ver = (
                                    match.group(2)
                                    if match.lastindex and match.lastindex >= 2
                                    else ""
                                )
                                if tech not in versions or (
                                    ver and versions.get(tech) in ("", "detected")
                                ):
                                    versions[tech] = ver or "detected"

                    # Check error body for version patterns
                    error_patterns = [
                        (r"Apache/([\d.]+)", "Apache"),
                        (r"nginx/([\d.]+)", "nginx"),
                        (r"Microsoft-IIS/([\d.]+)", "IIS"),
                        (r"PHP/([\d.]+)", "PHP"),
                        (r"Tomcat/([\d.]+)", "Tomcat"),
                        (r"OpenSSL/([\d.a-z]+)", "OpenSSL"),
                        (r"Powered by ([A-Za-z]+)\s*([\d.]+)?", None),
                    ]
                    for pattern, tech in error_patterns:
                        match = re.search(pattern, error_body, re.IGNORECASE)
                        if match and tech:
                            ver = (
                                match.group(1)
                                if tech in ("Apache", "nginx", "IIS", "PHP",
                                            "Tomcat", "OpenSSL")
                                else ""
                            )
                            if tech not in versions or (
                                ver and versions.get(tech) in ("", "detected")
                            ):
                                versions[tech] = ver or "detected"

                    # Flag verbose error pages
                    verbose_markers = [
                        "stack trace", "traceback", "at line",
                        "syntax error", "debug", "exception",
                    ]
                    body_lower = error_body.lower()
                    for marker in verbose_markers:
                        if marker in body_lower:
                            findings.append(Finding.low(
                                "Verbose error page detected",
                                description=(
                                    "Error page contains debug information "
                                    "that may reveal internal details."
                                ),
                                evidence=f"Found '{marker}' in {resp.status} page",
                                remediation=(
                                    "Configure custom error pages that do "
                                    "not expose debug information"
                                ),
                                tags=["analysis", "version", "error-page"],
                            ))
                            break
        except Exception:
            pass
