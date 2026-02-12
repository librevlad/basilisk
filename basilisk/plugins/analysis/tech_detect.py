"""Technology detection plugin — Wappalyzer-style fingerprinting.

Uses the centralized fingerprints database for multi-signal detection with
confidence scoring and version extraction.  Falls back to legacy
TECH_SIGNATURES for patterns not yet in the fingerprints DB.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.data.fingerprints import TECH_FINGERPRINTS, match_technologies
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target
from basilisk.utils.http_check import resolve_base_url

# ── Version-extraction helpers ───────────────────────────────────────

_VERSION_HEADER_PATTERNS: list[tuple[str, str]] = [
    ("server", r"nginx/([\d.]+)"),
    ("server", r"Apache/([\d.]+)"),
    ("server", r"Microsoft-IIS/([\d.]+)"),
    ("server", r"LiteSpeed/([\d.]+)"),
    ("server", r"openresty/([\d.]+)"),
    ("server", r"gunicorn/([\d.]+)"),
    ("server", r"uvicorn/([\d.]+)"),
    ("server", r"Caddy/([\d.]+)"),
    ("x-powered-by", r"PHP/([\d.]+)"),
    ("x-powered-by", r"ASP\.NET\s+version[:\s]*([\d.]+)"),
    ("x-powered-by", r"Express/([\d.]+)"),
    ("x-powered-by", r"Next\.js\s*([\d.]+)"),
    ("x-aspnet-version", r"([\d.]+)"),
    ("x-aspnetmvc-version", r"([\d.]+)"),
]

_META_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
    re.IGNORECASE,
)

# ── Cookie-based technology hints ────────────────────────────────────

_COOKIE_TECH: list[tuple[str, str, str, int]] = [
    # (cookie_pattern, tech_name, category, confidence)
    ("PHPSESSID", "PHP", "language", 60),
    ("JSESSIONID", "Java", "language", 60),
    ("ASP.NET_SessionId", "ASP.NET", "framework", 60),
    (".ASPXAUTH", "ASP.NET", "framework", 60),
    ("laravel_session", "Laravel", "framework", 60),
    ("XSRF-TOKEN", "Laravel", "framework", 40),
    ("csrftoken", "Django", "framework", 60),
    ("django_language", "Django", "framework", 70),
    ("ci_session", "CodeIgniter", "framework", 60),
    ("cakephp", "CakePHP", "framework", 60),
    ("wordpress_", "WordPress", "cms", 60),
    ("wp-settings", "WordPress", "cms", 60),
    ("BITRIX_SM_", "Bitrix", "cms", 60),
    ("PrestaShop-", "PrestaShop", "cms", 60),
    ("joomla_", "Joomla", "cms", 60),
    ("fe_typo_user", "Typo3", "cms", 60),
    ("_shopify_s", "Shopify", "cms", 60),
    ("__cfduid", "Cloudflare", "cdn", 50),
    ("__cf_bm", "Cloudflare", "cdn", 50),
    ("_rails_session", "Ruby on Rails", "framework", 60),
    ("rack.session", "Ruby", "language", 50),
    ("connect.sid", "Node.js", "language", 50),
    ("YII_CSRF_TOKEN", "Yii", "framework", 60),
    ("Drupal.visitor", "Drupal", "cms", 60),
    ("dle_user_id", "DLE (DataLife Engine)", "cms", 60),
]

# ── Legacy fallback signatures (patterns not in fingerprints DB) ─────
# Each tuple: (tech_name, location, regex_pattern, category)

TECH_SIGNATURES: list[tuple[str, str, str, str]] = [
    # Analytics (granular body checks)
    ("Google Analytics", "body",
     r"google-analytics\.com|gtag/js", "analytics"),
    ("Google Tag Manager", "body",
     r"googletagmanager\.com", "analytics"),
    ("Yandex.Metrika", "body",
     r"mc\.yandex\.ru/metrika|ym\(", "analytics"),
    ("Facebook Pixel", "body",
     r"connect\.facebook\.net|fbq\(", "analytics"),
    ("Hotjar", "body", r"hotjar\.com|_hjSettings", "analytics"),
    ("Segment", "body", r"segment\.com|analytics\.js", "analytics"),
    ("Mixpanel", "body",
     r"mixpanel\.com|mixpanel\.init", "analytics"),
    ("Amplitude", "body",
     r"amplitude\.com|amplitude\.getInstance", "analytics"),
    # E-commerce
    ("WooCommerce", "body",
     r"woocommerce|wc-blocks", "ecommerce"),
    ("Stripe", "body", r"js\.stripe\.com|Stripe\(", "ecommerce"),
    ("PayPal", "body",
     r"paypal\.com/sdk|paypalobjects", "ecommerce"),
    ("Sentry", "body", r"sentry\.io|Sentry\.init", "monitoring"),
    # Security widgets
    ("reCAPTCHA", "body",
     r"recaptcha|google\.com/recaptcha", "security"),
    ("hCaptcha", "body", r"hcaptcha\.com|h-captcha", "security"),
    ("Cloudflare Turnstile", "body",
     r"challenges\.cloudflare\.com/turnstile", "security"),
    # JS frameworks / libraries extras
    ("Ember.js", "body", r"ember\.js|ember-cli", "js-lib"),
    ("Backbone.js", "body",
     r"backbone\.js|Backbone\.Model", "js-lib"),
    ("Alpine.js", "body", r"alpine\.js|x-data=", "js-lib"),
    ("HTMX", "body", r"htmx\.org|hx-get|hx-post", "js-lib"),
    ("Stimulus", "body",
     r"stimulus|data-controller=", "js-lib"),
    ("Material UI", "body",
     r"MuiButton|material-ui", "css-lib"),
    ("Font Awesome", "body",
     r"font-awesome|fontawesome", "css-lib"),
    ("Moment.js", "body",
     r"moment\.min\.js|moment\.js", "js-lib"),
    ("Chart.js", "body", r"chart\.min\.js|Chart\.js", "js-lib"),
    ("D3.js", "body", r"d3\.min\.js|d3\.js", "js-lib"),
    ("Three.js", "body",
     r"three\.min\.js|three\.js", "js-lib"),
    ("Axios", "body", r"axios\.min\.js", "js-lib"),
    # CMS extras
    ("MODX", "body", r"modx|MODX", "cms"),
    ("OpenCart", "body",
     r"opencart|route=common/home", "cms"),
    ("Tilda", "body",
     r"tildacdn\.com|tilda-publishing", "cms"),
    ("Hugo", "body", r"hugo-[\d]|generator.*Hugo", "cms"),
    ("Webflow", "body", r"webflow\.com|wf-page", "cms"),
    # Build tools
    ("Webpack", "body", r"webpackJsonp|webpack", "build"),
    ("AMP", "body", r"amp-html|cdn\.ampproject\.org", "other"),
    ("PWA", "body",
     r"service-worker|serviceWorker\.register", "other"),
    ("GraphQL", "body", r"graphql|__schema", "api"),
    ("Turbo", "body", r"turbo\.js|turbo-frame", "js-lib"),
    ("Livewire", "body", r"livewire\.js|wire:", "js-lib"),
    ("Inertia.js", "body", r"inertia|@inertiajs", "js-lib"),
    # CDN extras
    ("Varnish", "header:via", r"varnish", "cache"),
    ("Fastly", "header:x-served-by", r".+", "cdn"),
    ("Amazon CloudFront", "header:x-amz-cf-id",
     r".+", "cdn"),
    ("Akamai", "header:x-akamai-transformed", r".+", "cdn"),
    ("Azure CDN", "header:x-msedge-ref", r".+", "cdn"),
    ("Nginx Ultimate Bad Bot Blocker", "body",
     r"nginx-ultimate-bad-bot-blocker", "security"),
]

# Pages to probe for broader fingerprinting
_PROBE_PATHS = ("/", "/robots.txt")

# WAF / CDN categories tracked separately for other plugins
_WAF_CDN_CATEGORIES = {"cdn", "waf", "cache"}


class TechDetectPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="tech_detect",
        display_name="Technology Detection",
        category=PluginCategory.ANALYSIS,
        description=(
            "Detects web technologies, frameworks, and CMS "
            "(Wappalyzer-style) with confidence scoring and "
            "version extraction"
        ),
        produces=["technologies"],
        timeout=20.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host,
                error="HTTP client not available",
            )

        base_url = await resolve_base_url(target.host, ctx)
        if not base_url:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info(
                    "Could not reach target for tech detection",
                )],
                data={"technologies": [], "waf_cdn": []},
            )

        # Collect responses from multiple pages
        all_headers: dict[str, str] = {}
        all_body = ""
        all_cookies: dict[str, str] = {}

        for path in _PROBE_PATHS:
            url = f"{base_url}{path}"
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(
                        url, timeout=10.0,
                    )
                    hdrs = {
                        k.lower(): v
                        for k, v in resp.headers.items()
                    }
                    body = await resp.text(
                        encoding="utf-8", errors="replace",
                    )
                    # Merge — first page headers take priority
                    for k, v in hdrs.items():
                        all_headers.setdefault(k, v)
                    all_body += body
                    # Parse Set-Cookie headers
                    for cookie_raw in resp.headers.getall(
                        "Set-Cookie", [],
                    ):
                        name = cookie_raw.split("=", 1)[0].strip()
                        all_cookies[name] = cookie_raw
            except Exception:
                continue

        if not all_headers and not all_body:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info(
                    "Could not fetch pages for tech detection",
                )],
                data={"technologies": [], "waf_cdn": []},
            )

        # ── 1. Fingerprints DB matching ──────────────────────────
        detected: dict[str, dict[str, Any]] = {}

        fp_results = match_technologies(
            all_headers, all_body, all_cookies, base_url,
        )
        for tech in fp_results:
            name = tech["name"]
            if name not in detected or (
                tech["confidence"] > detected[name]["confidence"]
            ):
                detected[name] = {
                    "name": name,
                    "version": tech.get("version", ""),
                    "confidence": tech["confidence"],
                    "category": tech.get("category", ""),
                }

        # ── 2. Header-based version extraction ───────────────────
        for hdr_name, pattern in _VERSION_HEADER_PATTERNS:
            value = all_headers.get(hdr_name, "")
            if not value:
                continue
            m = re.search(pattern, value, re.IGNORECASE)
            if m:
                version = m.group(1)
                # Determine tech name from pattern
                tech_name = self._tech_from_header(
                    hdr_name, value,
                )
                if tech_name and tech_name in detected:
                    if not detected[tech_name]["version"]:
                        detected[tech_name]["version"] = version
                elif tech_name and tech_name not in detected:
                    detected[tech_name] = {
                        "name": tech_name,
                        "version": version,
                        "confidence": 90,
                        "category": "server",
                    }

        # ── 3. Meta generator detection ──────────────────────────
        for m in _META_GENERATOR_RE.finditer(all_body):
            content = m.group(1).strip()
            meta_tech = self._parse_generator(content)
            if meta_tech:
                name = meta_tech["name"]
                if name not in detected:
                    detected[name] = meta_tech
                elif not detected[name]["version"] and (
                    meta_tech.get("version")
                ):
                    detected[name]["version"] = (
                        meta_tech["version"]
                    )

        # ── 4. Cookie-based detection ────────────────────────────
        cookie_names_lower = " ".join(
            all_cookies.keys(),
        ).lower()
        for pattern, tech_name, cat, conf in _COOKIE_TECH:
            if pattern.lower() in cookie_names_lower and tech_name not in detected:
                detected[tech_name] = {
                        "name": tech_name,
                        "version": "",
                        "confidence": conf,
                        "category": cat,
                    }

        # ── 5. Legacy fallback signatures ────────────────────────
        for tech_name, location, pattern, cat in TECH_SIGNATURES:
            if tech_name in detected:
                continue
            try:
                if location.startswith("header:"):
                    hdr = location.split(":", 1)[1]
                    val = all_headers.get(hdr, "")
                    if val and re.search(
                        pattern, val, re.IGNORECASE,
                    ):
                        detected[tech_name] = {
                            "name": tech_name,
                            "version": "",
                            "confidence": 70,
                            "category": cat,
                        }
                elif location == "body" and all_body:
                    if re.search(
                        pattern, all_body, re.IGNORECASE,
                    ):
                        detected[tech_name] = {
                            "name": tech_name,
                            "version": "",
                            "confidence": 70,
                            "category": cat,
                        }
            except re.error:
                continue

        # ── 6. Resolve implied technologies ──────────────────────
        self._resolve_implies(detected)

        # ── Build output ─────────────────────────────────────────
        tech_list = sorted(
            detected.values(), key=lambda t: -t["confidence"],
        )

        # Separate WAF/CDN for other plugins
        waf_cdn = [
            t for t in tech_list
            if t.get("category", "") in _WAF_CDN_CATEGORIES
        ]

        findings = self._build_findings(tech_list)

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "technologies": tech_list,
                "waf_cdn": waf_cdn,
            },
        )

    # ── Helpers ───────────────────────────────────────────────────

    @staticmethod
    def _tech_from_header(
        hdr_name: str, value: str,
    ) -> str | None:
        """Derive technology name from a header value."""
        val_lower = value.lower()
        if hdr_name == "server":
            for prefix, name in (
                ("nginx", "Nginx"),
                ("apache", "Apache"),
                ("microsoft-iis", "IIS"),
                ("litespeed", "LiteSpeed"),
                ("openresty", "OpenResty"),
                ("gunicorn", "Gunicorn"),
                ("uvicorn", "Uvicorn"),
                ("caddy", "Caddy"),
            ):
                if prefix in val_lower:
                    return name
        elif hdr_name == "x-powered-by":
            for prefix, name in (
                ("php", "PHP"),
                ("asp.net", "ASP.NET"),
                ("express", "Express"),
                ("next.js", "Next.js"),
            ):
                if prefix in val_lower:
                    return name
        elif hdr_name in (
            "x-aspnet-version", "x-aspnetmvc-version",
        ):
            return "ASP.NET"
        return None

    @staticmethod
    def _parse_generator(content: str) -> dict[str, Any] | None:
        """Parse meta generator content into a tech dict."""
        # Try "Name Version" pattern
        m = re.match(
            r"^([A-Za-z][A-Za-z0-9 .!-]+?)"
            r"\s+([\d]+(?:\.[\d]+)*)",
            content,
        )
        if m:
            return {
                "name": m.group(1).strip(),
                "version": m.group(2),
                "confidence": 85,
                "category": "cms",
            }
        # Name only
        name = content.strip()
        if name and len(name) < 50:
            return {
                "name": name,
                "version": "",
                "confidence": 85,
                "category": "cms",
            }
        return None

    @staticmethod
    def _resolve_implies(
        detected: dict[str, dict[str, Any]],
    ) -> None:
        """Add implied technologies from the fingerprints DB."""
        fp_map = {fp.name: fp for fp in TECH_FINGERPRINTS}
        queue = list(detected.keys())
        visited: set[str] = set()

        while queue:
            name = queue.pop()
            if name in visited:
                continue
            visited.add(name)
            fp = fp_map.get(name)
            if not fp or not fp.implies:
                continue
            for implied in fp.implies:
                if implied not in detected:
                    detected[implied] = {
                        "name": implied,
                        "version": "",
                        "confidence": 50,
                        "category": (
                            fp_map[implied].category
                            if implied in fp_map else "language"
                        ),
                    }
                    queue.append(implied)

    @staticmethod
    def _build_findings(
        tech_list: list[dict[str, Any]],
    ) -> list[Finding]:
        """Create findings from the detected technology list."""
        if not tech_list:
            return [Finding.info(
                "No technologies detected",
                tags=["analysis", "tech-detect"],
            )]

        # Group by category for readable output
        by_cat: dict[str, list[str]] = {}
        for t in tech_list:
            cat = t.get("category", "other")
            label = t["name"]
            if t.get("version"):
                label += f" {t['version']}"
            label += f" ({t['confidence']}%)"
            by_cat.setdefault(cat, []).append(label)

        summary_parts: list[str] = []
        for cat in sorted(by_cat):
            items = ", ".join(by_cat[cat])
            summary_parts.append(f"{cat}: {items}")
        summary = "; ".join(summary_parts)

        names = [t["name"] for t in tech_list]
        findings = [Finding.info(
            f"Detected {len(tech_list)} technologies: "
            f"{', '.join(names[:15])}"
            + ("..." if len(names) > 15 else ""),
            evidence=summary[:500],
            tags=["analysis", "tech-detect"],
        )]

        # Flag version disclosure in headers as low-severity
        versioned = [
            t for t in tech_list
            if t.get("version")
            and t.get("category") in ("server", "language")
        ]
        if versioned:
            ev = ", ".join(
                f"{t['name']} {t['version']}" for t in versioned
            )
            findings.append(Finding.low(
                "Server/runtime version disclosed",
                description=(
                    "Version numbers visible in HTTP headers help "
                    "attackers identify known vulnerabilities"
                ),
                evidence=ev,
                remediation=(
                    "Remove or obfuscate version information "
                    "from Server and X-Powered-By headers"
                ),
                tags=["analysis", "tech-detect", "info-disclosure"],
            ))

        return findings
