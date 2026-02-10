"""
magnit-audit: массовая проверка безопасности поддоменов magnit.ru и tander.ru
Пассивная разведка: DNS resolve, SSL-сертификаты, HTTP-заголовки, технологии.
"""

import socket
import ssl
import json
import csv
import sys
import os
import io
import time
import datetime
import concurrent.futures
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from pathlib import Path

# Fix Windows console encoding
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

TIMEOUT = 8
MAX_WORKERS = 20
OUTPUT_DIR = Path(__file__).parent / "data" / "audit_results"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Все поддомены с известными IP (наиболее интересные для аудита)
MAGNIT_SUBDOMAINS = [
    "magnit.ru",
    "www.magnit.ru",
    "2life.magnit.ru",
    "500.magnit.ru",
    "adfs.magnit.ru",
    "agro.magnit.ru",
    "api-merch.magnit.ru",
    "api.blago.magnit.ru",
    "api.zabota.magnit.ru",
    "apteka.magnit.ru",
    "apteka-highload.magnit.ru",
    "apteka-prod.magnit.ru",
    "apteka-stage.magnit.ru",
    "apteka-stage2.magnit.ru",
    "argument.magnit.ru",
    "armhde.magnit.ru",
    "arsint02.magnit.ru",
    "autodiscover.magnit.ru",
    "b2b.magnit.ru",
    "b2b-api.magnit.ru",
    "b2b-portal.magnit.ru",
    "banan.magnit.ru",
    "bezgranic.magnit.ru",
    "biometriatst.magnit.ru",
    "blago.magnit.ru",
    "blogger.magnit.ru",
    "bonus.magnit.ru",
    "booking.magnit.ru",
    "buzova.magnit.ru",
    "byodagent.magnit.ru",
    "bzdsit.magnit.ru",
    "c2c.magnit.ru",
    "ca.magnit.ru",
    "ccmdp.magnit.ru",
    "ccmmp.magnit.ru",
    "clm.magnit.ru",
    "collab-edge.uc.magnit.ru",
    "cosmetic.magnit.ru",
    "courier.magnit.ru",
    "courier-stage.magnit.ru",
    "courier-stage2.magnit.ru",
    "couriers.magnit.ru",
    "cptspocsp1.magnit.ru",
    "cptspocsp2.magnit.ru",
    "crossword.magnit.ru",
    "digital.magnit.ru",
    "dmp.magnit.ru",
    "docs.magnit.ru",
    "dostavka.magnit.ru",
    "dostavka-highload.magnit.ru",
    "dostavka-stage.magnit.ru",
    "eportal.magnit.ru",
    "eway.magnit.ru",
    "eway1.magnit.ru",
    "ews.magnit.ru",
    "express-highload.magnit.ru",
    "express-stage2.magnit.ru",
    "fotoobmen.magnit.ru",
    "images-foodtech.dev.magnit.ru",
    "karta.magnit.ru",
    "mail.apteka-stage.magnit.ru",
    "mailback.magnit.ru",
    "master.dte.azure.magnit.ru",
    "master.prod.azure.magnit.ru",
    "meet.magnit.ru",
    "middle-api.magnit.ru",
    "mrkt.magnit.ru",
    "mtbmc.magnit.ru",
    "pampers.magnit.ru",
    "pulsem.magnit.ru",
    "rabota.magnit.ru",
    "remote-crafttalk.magnit.ru",
    "sdclassic.magnit.ru",
    "sfbwapp.magnit.ru",
    "smartrepbmc.magnit.ru",
    "smtp.magnit.ru",
    "tori.magnit.ru",
    "track.magnit.ru",
    "vacancy.magnit.ru",
    "video.magnit.ru",
    "videoproxy.magnit.ru",
    "videostream.magnit.ru",
    "www.apteka.magnit.ru",
    "www.couriers.magnit.ru",
    "www.dostavka.magnit.ru",
    "zabota.magnit.ru",
]

TANDER_SUBDOMAINS = [
    "api-magnit-drc-ca.tander.ru",
    "api-magnit-uat-ca.tander.ru",
    "armsd.tander.ru",
    "awac.corp.tander.ru",
    "awactst.corp.tander.ru",
    "awassist.tander.ru",
    "awcm.tander.ru",
    "awds.tander.ru",
    "awens.tander.ru",
    "awmagrel.tander.ru",
    "awmagrext.tander.ru",
    "awmagrwincorp.tander.ru",
    "awseg.tander.ru",
    "awuagrt.tander.ru",
    "cert-testg.tander.ru",
    "connect.tander.ru",
    "exch01.star.tander.ru",
    "fgate.tander.ru",
    "fgate.745100.tander.ru",
    "filetrance.tander.ru",
    "fk.tander.ru",
    "fmdc.tander.ru",
    "ftoken.tander.ru",
    "ftp-tech.tander.ru",
    "ftp2.tander.ru",
    "ftpext.tander.ru",
    "geoapp.tander.ru",
    "gw.tander.ru",
    "hi.tander.ru",
    "magnit-drc-ca.tander.ru",
    "mail.tander.ru",
    "mailback.tander.ru",
    "mailbulk.tander.ru",
    "meetgk.tander.ru",
    "mobilebmc.tander.ru",
    "mx1.tander.ru",
    "mx3.tander.ru",
    "mx4.tander.ru",
    "mx5.tander.ru",
    "ns.tander.ru",
    "ns01.tander.ru",
    "ns02.tander.ru",
    "ns03.tander.ru",
    "phone.tander.ru",
    "pki.tander.ru",
    "projftp.tander.ru",
    "qr-help.tander.ru",
    "rshk.tander.ru",
    "rvpn1.tander.ru",
    "srm.tander.ru",
    "strvideo.tander.ru",
    "testgate.tander.ru",
    "tstoreapp.tander.ru",
    "vectra.tander.ru",
    "vpnmm1.tander.ru",
    "vpnmm2.tander.ru",
]

ALL_SUBDOMAINS = MAGNIT_SUBDOMAINS + TANDER_SUBDOMAINS

# Важные заголовки безопасности
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Access-Control-Allow-Origin",
]

# Заголовки, раскрывающие информацию о сервере
INFO_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "Via",
]


def resolve_dns(domain):
    """Резолвит домен в IP-адреса."""
    try:
        results = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips = list(set(r[4][0] for r in results))
        return ips
    except socket.gaierror:
        return []


def check_ssl(domain, port=443):
    """Проверяет SSL-сертификат."""
    info = {
        "has_ssl": False,
        "cert_subject": None,
        "cert_issuer": None,
        "cert_expires": None,
        "cert_san": [],
        "ssl_version": None,
        "ssl_error": None,
    }
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                info["has_ssl"] = True
                info["ssl_version"] = ssock.version()
                cert = ssock.getpeercert()
                if cert:
                    subj = dict(x[0] for x in cert.get("subject", []))
                    info["cert_subject"] = subj.get("commonName", "")
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    info["cert_issuer"] = issuer.get("organizationName", "")
                    info["cert_expires"] = cert.get("notAfter", "")
                    san = cert.get("subjectAltName", [])
                    info["cert_san"] = [v for _, v in san]
    except ssl.SSLCertVerificationError as e:
        info["ssl_error"] = f"CERT_VERIFY_FAILED: {e}"
        info["has_ssl"] = True  # SSL есть, но сертификат невалидный
    except ssl.SSLError as e:
        info["ssl_error"] = str(e)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        info["ssl_error"] = str(e)
    return info


def check_http(domain, use_https=True):
    """Проверяет HTTP(S) ответ: статус, заголовки, редиректы."""
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{domain}/"
    info = {
        "url": url,
        "status_code": None,
        "redirect_url": None,
        "headers": {},
        "security_headers": {},
        "missing_security_headers": [],
        "info_disclosure_headers": {},
        "title": None,
        "error": None,
    }
    try:
        req = Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) magnit-audit/1.0",
            "Accept": "text/html,application/xhtml+xml,*/*",
        })
        resp = urlopen(req, timeout=TIMEOUT)
        info["status_code"] = resp.status
        info["redirect_url"] = resp.url if resp.url != url else None
        hdrs = dict(resp.headers)
        info["headers"] = hdrs

        # Заголовки безопасности
        for h in SECURITY_HEADERS:
            val = resp.headers.get(h)
            if val:
                info["security_headers"][h] = val
            else:
                info["missing_security_headers"].append(h)

        # Заголовки, раскрывающие информацию
        for h in INFO_HEADERS:
            val = resp.headers.get(h)
            if val:
                info["info_disclosure_headers"][h] = val

        # Попробуем извлечь <title>
        try:
            body = resp.read(32768).decode("utf-8", errors="replace")
            import re
            m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
            if m:
                info["title"] = m.group(1).strip()[:200]
        except Exception:
            pass

    except HTTPError as e:
        info["status_code"] = e.code
        info["error"] = str(e)
        hdrs = dict(e.headers) if e.headers else {}
        info["headers"] = hdrs
        for h in SECURITY_HEADERS:
            val = e.headers.get(h) if e.headers else None
            if val:
                info["security_headers"][h] = val
            else:
                info["missing_security_headers"].append(h)
        for h in INFO_HEADERS:
            val = e.headers.get(h) if e.headers else None
            if val:
                info["info_disclosure_headers"][h] = val
    except (URLError, socket.timeout, ConnectionRefusedError, OSError) as e:
        info["error"] = str(e)
    return info


def check_http_port(domain, port):
    """Быстрая проверка — слушает ли порт."""
    try:
        with socket.create_connection((domain, port), timeout=4):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def classify_findings(result):
    """Классифицирует находки по критичности."""
    findings = []

    # DNS
    if not result["dns_ips"]:
        findings.append(("INFO", "DNS не резолвится"))
        return findings

    # SSL
    ssl_info = result["ssl"]
    if ssl_info["ssl_error"] and "CERT_VERIFY_FAILED" in str(ssl_info.get("ssl_error", "")):
        findings.append(("HIGH", f"Невалидный SSL-сертификат: {ssl_info['ssl_error']}"))
    elif not ssl_info["has_ssl"]:
        findings.append(("MEDIUM", "SSL/TLS недоступен на порту 443"))

    # HTTP/HTTPS
    for proto in ["https", "http"]:
        http_info = result.get(f"{proto}_check")
        if not http_info:
            continue
        if http_info.get("error") and "refused" in str(http_info["error"]).lower():
            continue

        # Раскрытие информации о сервере
        for hdr, val in http_info.get("info_disclosure_headers", {}).items():
            findings.append(("LOW", f"[{proto.upper()}] Раскрытие информации: {hdr}: {val}"))

        # Отсутствующие заголовки безопасности
        missing = http_info.get("missing_security_headers", [])
        critical_missing = [h for h in missing if h in (
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
        )]
        if critical_missing and http_info.get("status_code"):
            findings.append(("MEDIUM", f"[{proto.upper()}] Отсутствуют заголовки: {', '.join(critical_missing)}"))

        # Staging/dev/test в домене
        domain = result["domain"]
        if any(kw in domain for kw in ("stage", "dev", "test", "demo", "uat")):
            if http_info.get("status_code") and http_info["status_code"] < 400:
                findings.append(("HIGH", f"[{proto.upper()}] Staging/dev/test доступен публично (HTTP {http_info['status_code']})"))

        # Redirect на другой домен
        redir = http_info.get("redirect_url")
        if redir:
            findings.append(("INFO", f"[{proto.upper()}] Редирект → {redir}"))

        # Интересные названия
        interesting_keywords = {
            "gitlab": "CRITICAL", "sentry": "HIGH", "secret": "HIGH",
            "adfs": "MEDIUM", "autodiscover": "MEDIUM", "ews": "MEDIUM",
            "helpdesk": "MEDIUM", "ftp": "MEDIUM", "vpn": "INFO",
            "admin": "HIGH", "jenkins": "CRITICAL", "grafana": "HIGH",
            "kibana": "HIGH", "phpmyadmin": "CRITICAL",
        }
        for kw, sev in interesting_keywords.items():
            if kw in domain:
                if http_info.get("status_code") and http_info["status_code"] < 500:
                    findings.append((sev, f"[{proto.upper()}] Потенциально чувствительный сервис ({kw}) доступен публично"))
                break

    # Subdomain takeover hints
    domain = result["domain"]
    ips = result["dns_ips"]
    if ips:
        # IP не из корпоративных диапазонов Tander (193.19.168-171.x) и не из Magnit CDN
        corp_prefixes = ("193.19.168.", "193.19.169.", "193.19.170.", "193.19.171.", "178.248.")
        non_corp = [ip for ip in ips if not any(ip.startswith(p) for p in corp_prefixes)]
        if non_corp:
            # Внешний хостинг — проверяем cloud providers
            cloud_indicators = {
                "51.250.": "Yandex Cloud", "84.252.": "Yandex Cloud",
                "89.208.": "Selectel", "213.219.": "Selectel",
                "37.139.": "Selectel", "176.99.": "CDNvideo",
                "185.65.": "Hosting", "185.215.": "Hosting",
                "185.157.": "Hosting", "176.57.": "Hosting",
                "13.": "Azure", "20.": "Azure", "40.": "Azure",
                "51.": "Azure/Cloud", "52.": "Azure/AWS",
                "137.117.": "Azure", "172.104.": "Linode",
                "109.120.": "Hosting", "212.233.": "Hosting",
                "92.63.": "Hosting", "188.72.": "Hosting",
                "78.41.": "Hosting", "87.249.": "Hosting",
                "81.30.": "Hosting", "62.231.": "Hosting",
                "95.167.": "Hosting", "158.160.": "Yandex Cloud",
                "84.201.": "Yandex Cloud",
            }
            for ip in non_corp:
                provider = "Unknown"
                for prefix, name in cloud_indicators.items():
                    if ip.startswith(prefix):
                        provider = name
                        break
                findings.append(("INFO", f"Внешний IP: {ip} ({provider})"))

    if not findings:
        findings.append(("INFO", "Нет значимых находок"))

    return findings


def audit_subdomain(domain):
    """Полная проверка одного поддомена."""
    result = {
        "domain": domain,
        "timestamp": datetime.datetime.now().isoformat(),
        "dns_ips": [],
        "ssl": {},
        "https_check": None,
        "http_check": None,
        "open_ports": {},
        "findings": [],
    }

    print(f"  [{ALL_SUBDOMAINS.index(domain)+1}/{len(ALL_SUBDOMAINS)}] {domain} ...", flush=True)

    # 1. DNS
    result["dns_ips"] = resolve_dns(domain)
    if not result["dns_ips"]:
        result["findings"] = [("INFO", "DNS не резолвится")]
        print(f"    ✗ DNS не резолвится", flush=True)
        return result

    # 2. Быстрая проверка портов
    for port, name in [(443, "HTTPS"), (80, "HTTP"), (21, "FTP"), (8080, "HTTP-ALT"), (8443, "HTTPS-ALT")]:
        result["open_ports"][name] = check_http_port(domain, port)

    # 3. SSL
    if result["open_ports"].get("HTTPS"):
        result["ssl"] = check_ssl(domain)

    # 4. HTTP/HTTPS
    if result["open_ports"].get("HTTPS"):
        result["https_check"] = check_http(domain, use_https=True)
    if result["open_ports"].get("HTTP"):
        result["http_check"] = check_http(domain, use_https=False)

    # 5. Классификация
    result["findings"] = classify_findings(result)

    # Вывод в консоль
    ips_str = ", ".join(result["dns_ips"][:3])
    ports_open = [n for n, v in result["open_ports"].items() if v]
    ssl_status = "✓" if result["ssl"].get("has_ssl") else "✗"
    title = ""
    for check_key in ("https_check", "http_check"):
        ch = result.get(check_key)
        if ch and ch.get("title"):
            title = ch["title"][:60]
            break
    status = ""
    for check_key in ("https_check", "http_check"):
        ch = result.get(check_key)
        if ch and ch.get("status_code"):
            status = str(ch["status_code"])
            break

    critical_count = sum(1 for s, _ in result["findings"] if s in ("CRITICAL", "HIGH"))
    print(f"    IP: {ips_str} | Ports: {','.join(ports_open) or 'none'} | SSL: {ssl_status} | HTTP: {status} | {title}", flush=True)
    if critical_count:
        for sev, msg in result["findings"]:
            if sev in ("CRITICAL", "HIGH"):
                print(f"    ⚠ [{sev}] {msg}", flush=True)

    return result


def generate_report(results):
    """Генерирует сводный отчёт."""
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    # JSON — полные результаты
    json_path = OUTPUT_DIR / f"audit_full_{ts}.json"
    serializable = []
    for r in results:
        s = dict(r)
        s["ssl"] = dict(r.get("ssl", {}))
        serializable.append(s)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(serializable, f, ensure_ascii=False, indent=2, default=str)
    print(f"\n✓ Полные результаты: {json_path}")

    # CSV — сводная таблица
    csv_path = OUTPUT_DIR / f"audit_summary_{ts}.csv"
    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Domain", "IPs", "Open Ports", "SSL", "SSL Version", "Cert Issuer",
            "Cert Expires", "HTTPS Status", "HTTP Status", "Title",
            "Server", "Missing Security Headers",
            "Severity", "Findings"
        ])
        for r in results:
            ips = "; ".join(r["dns_ips"][:3])
            ports = "; ".join(n for n, v in r["open_ports"].items() if v)
            ssl_ok = "Yes" if r["ssl"].get("has_ssl") else "No"
            ssl_ver = r["ssl"].get("ssl_version", "")
            issuer = r["ssl"].get("cert_issuer", "")
            expires = r["ssl"].get("cert_expires", "")
            https_st = ""
            http_st = ""
            title = ""
            server = ""
            missing = ""
            if r.get("https_check"):
                https_st = str(r["https_check"].get("status_code", ""))
                title = r["https_check"].get("title", "") or ""
                server = r["https_check"].get("info_disclosure_headers", {}).get("Server", "")
                missing = "; ".join(r["https_check"].get("missing_security_headers", []))
            if r.get("http_check"):
                http_st = str(r["http_check"].get("status_code", ""))
                if not title:
                    title = r["http_check"].get("title", "") or ""
                if not server:
                    server = r["http_check"].get("info_disclosure_headers", {}).get("Server", "")

            max_sev = "INFO"
            sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
            for s, _ in r["findings"]:
                if sev_order.get(s, 0) > sev_order.get(max_sev, 0):
                    max_sev = s
            findings_str = " | ".join(f"[{s}] {m}" for s, m in r["findings"])

            writer.writerow([
                r["domain"], ips, ports, ssl_ok, ssl_ver, issuer, expires,
                https_st, http_st, title, server, missing,
                max_sev, findings_str
            ])
    print(f"✓ CSV-сводка: {csv_path}")

    # Текстовый отчёт по критичности
    report_path = OUTPUT_DIR / f"audit_report_{ts}.txt"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(f"=" * 80 + "\n")
        f.write(f"ОТЧЁТ АУДИТА БЕЗОПАСНОСТИ ПОДДОМЕНОВ magnit.ru / tander.ru\n")
        f.write(f"Дата: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Проверено поддоменов: {len(results)}\n")
        f.write(f"=" * 80 + "\n\n")

        # Статистика
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for r in results:
            for s, _ in r["findings"]:
                sev_counts[s] = sev_counts.get(s, 0) + 1

        f.write("СТАТИСТИКА НАХОДОК:\n")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            f.write(f"  {sev:10s}: {sev_counts[sev]}\n")
        f.write("\n")

        # Критические и высокие
        for sev_filter in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            items = []
            for r in results:
                for s, m in r["findings"]:
                    if s == sev_filter:
                        items.append((r["domain"], m))
            if items:
                f.write(f"\n{'='*60}\n")
                f.write(f" {sev_filter} ({len(items)} находок)\n")
                f.write(f"{'='*60}\n")
                for domain, msg in items:
                    f.write(f"  {domain:45s} → {msg}\n")

        # Детали по каждому домену
        f.write(f"\n\n{'='*80}\n")
        f.write(f"ДЕТАЛЬНЫЕ РЕЗУЛЬТАТЫ ПО КАЖДОМУ ПОДДОМЕНУ\n")
        f.write(f"{'='*80}\n")
        for r in results:
            f.write(f"\n--- {r['domain']} ---\n")
            f.write(f"  IP: {', '.join(r['dns_ips']) or 'не резолвится'}\n")
            f.write(f"  Open Ports: {', '.join(n for n, v in r['open_ports'].items() if v) or 'none'}\n")
            if r["ssl"]:
                f.write(f"  SSL: {'OK' if r['ssl'].get('has_ssl') else 'NO'}")
                if r["ssl"].get("ssl_version"):
                    f.write(f" ({r['ssl']['ssl_version']})")
                if r["ssl"].get("cert_issuer"):
                    f.write(f" | Issuer: {r['ssl']['cert_issuer']}")
                if r["ssl"].get("cert_expires"):
                    f.write(f" | Expires: {r['ssl']['cert_expires']}")
                if r["ssl"].get("ssl_error"):
                    f.write(f" | Error: {r['ssl']['ssl_error']}")
                f.write("\n")
            for check_key, label in [("https_check", "HTTPS"), ("http_check", "HTTP")]:
                ch = r.get(check_key)
                if ch and (ch.get("status_code") or ch.get("error")):
                    f.write(f"  {label}: {ch.get('status_code', 'N/A')}")
                    if ch.get("title"):
                        f.write(f" | Title: {ch['title'][:80]}")
                    if ch.get("redirect_url"):
                        f.write(f" | Redirect: {ch['redirect_url']}")
                    if ch.get("info_disclosure_headers"):
                        f.write(f" | Server info: {ch['info_disclosure_headers']}")
                    if ch.get("error"):
                        f.write(f" | Error: {ch['error'][:100]}")
                    f.write("\n")
            f.write(f"  Findings:\n")
            for s, m in r["findings"]:
                f.write(f"    [{s}] {m}\n")

    print(f"✓ Текстовый отчёт: {report_path}")
    return json_path, csv_path, report_path


def main():
    print(f"{'='*60}")
    print(f"magnit-audit: аудит безопасности поддоменов")
    print(f"Дата: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Всего поддоменов: {len(ALL_SUBDOMAINS)}")
    print(f"  magnit.ru: {len(MAGNIT_SUBDOMAINS)}")
    print(f"  tander.ru: {len(TANDER_SUBDOMAINS)}")
    print(f"Потоков: {MAX_WORKERS}")
    print(f"{'='*60}\n")

    results = []
    start = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(audit_subdomain, d): d for d in ALL_SUBDOMAINS}
        for future in concurrent.futures.as_completed(futures):
            domain = futures[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                print(f"  ✗ {domain}: ошибка — {e}", flush=True)
                results.append({
                    "domain": domain,
                    "timestamp": datetime.datetime.now().isoformat(),
                    "dns_ips": [],
                    "ssl": {},
                    "https_check": None,
                    "http_check": None,
                    "open_ports": {},
                    "findings": [("ERROR", str(e))],
                })

    elapsed = time.time() - start
    print(f"\n{'='*60}")
    print(f"Аудит завершён за {elapsed:.1f} секунд")
    print(f"{'='*60}\n")

    # Сортируем по домену для удобства
    results.sort(key=lambda r: r["domain"])

    # Генерация отчётов
    json_path, csv_path, report_path = generate_report(results)

    # Итоговая сводка
    print(f"\n{'='*60}")
    print("ИТОГОВАЯ СВОДКА:")
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for r in results:
        for s, _ in r["findings"]:
            sev_counts[s] = sev_counts.get(s, 0) + 1
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        marker = "⚠" if sev in ("CRITICAL", "HIGH") else " "
        print(f"  {marker} {sev:10s}: {sev_counts[sev]}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
