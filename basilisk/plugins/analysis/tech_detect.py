"""Technology detection plugin — Wappalyzer-style fingerprinting."""

from __future__ import annotations

import re
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

# Simplified tech signatures (header + body patterns)
TECH_SIGNATURES: list[tuple[str, str, str]] = [
    # --- Web Servers ---
    ("Nginx", "header:server", r"nginx"),
    ("Apache", "header:server", r"apache"),
    ("IIS", "header:server", r"microsoft-iis"),
    ("LiteSpeed", "header:server", r"litespeed"),
    ("Caddy", "header:server", r"caddy"),
    ("Tomcat", "header:server", r"apache-coyote|tomcat"),
    ("Jetty", "header:server", r"jetty"),
    # --- Languages / Runtimes ---
    ("PHP", "header:x-powered-by", r"php"),
    ("ASP.NET", "header:x-powered-by", r"asp\.net"),
    ("Express", "header:x-powered-by", r"express"),
    ("Django", "header:x-framework", r"django"),
    ("Java", "header:x-powered-by", r"servlet|jsp|java"),
    ("Ruby", "header:x-powered-by", r"phusion|passenger|rack"),
    ("Python", "header:x-powered-by", r"python|gunicorn|uvicorn|werkzeug"),
    ("Node.js", "header:x-powered-by", r"next\.js|nuxt|koa|hapi"),
    # --- CDN/Proxy headers ---
    ("Cloudflare", "header:server", r"cloudflare"),
    ("Cloudflare", "header:cf-ray", r".+"),
    ("Fastly", "header:x-served-by", r".+"),
    ("Varnish", "header:via", r"varnish"),
    ("Amazon CloudFront", "header:x-amz-cf-id", r".+"),
    ("Akamai", "header:x-akamai-transformed", r".+"),
    ("Google Cloud", "header:x-goog-generation", r".+"),
    ("Azure CDN", "header:x-msedge-ref", r".+"),
    # --- CMS ---
    ("WordPress", "body", r"wp-content|wp-includes|wp-json"),
    ("Joomla", "body", r"Joomla!|/media/jui/|com_content"),
    ("Drupal", "body", r"Drupal|drupal\.js|drupal\.settings"),
    ("1C-Bitrix", "body", r"bitrix|BX\.message"),
    ("Bitrix", "header:x-powered-cms", r"bitrix"),
    ("MODX", "body", r"modx|MODX"),
    ("Magento", "body", r"Mage\.Cookies|magento|/skin/frontend/"),
    ("PrestaShop", "body", r"prestashop|/themes/default-bootstrap/"),
    ("OpenCart", "body", r"opencart|route=common/home"),
    ("Shopify", "body", r"cdn\.shopify\.com|Shopify\.theme"),
    ("Tilda", "body", r"tildacdn\.com|tilda-publishing"),
    ("Wix", "body", r"wix\.com|X-Wix-"),
    ("Squarespace", "body", r"squarespace\.com|sqsp"),
    ("Ghost", "body", r"ghost\.org|ghost-url"),
    ("Hugo", "body", r"hugo-[\d]|generator.*Hugo"),
    ("Gatsby", "body", r"gatsby|__gatsby"),
    ("Webflow", "body", r"webflow\.com|wf-page"),
    # --- JS Frameworks ---
    ("React", "body", r"react\.production\.min\.js|_react|__NEXT_DATA__"),
    ("Vue.js", "body", r"vue\.min\.js|vue\.runtime|__vue__"),
    ("Angular", "body", r"ng-version|angular\.min\.js|ng-app"),
    ("Svelte", "body", r"svelte|__svelte"),
    ("Ember.js", "body", r"ember\.js|ember-cli"),
    ("Backbone.js", "body", r"backbone\.js|Backbone\.Model"),
    ("Alpine.js", "body", r"alpine\.js|x-data="),
    ("HTMX", "body", r"htmx\.org|hx-get|hx-post"),
    ("Stimulus", "body", r"stimulus|data-controller="),
    # --- JS Libraries ---
    ("jQuery", "body", r"jquery[\.-][\d]"),
    ("Bootstrap", "body", r"bootstrap\.min\.(css|js)"),
    ("Tailwind CSS", "body", r"tailwindcss|tailwind\.min"),
    ("Material UI", "body", r"MuiButton|material-ui"),
    ("Font Awesome", "body", r"font-awesome|fontawesome"),
    ("Lodash", "body", r"lodash\.min\.js|lodash\.js"),
    ("Moment.js", "body", r"moment\.min\.js|moment\.js"),
    ("Chart.js", "body", r"chart\.min\.js|Chart\.js"),
    ("D3.js", "body", r"d3\.min\.js|d3\.js"),
    ("Socket.IO", "body", r"socket\.io\.js|socket\.io\.min"),
    ("Three.js", "body", r"three\.min\.js|three\.js"),
    ("Axios", "body", r"axios\.min\.js"),
    # --- Analytics ---
    ("Google Analytics", "body", r"google-analytics\.com|gtag/js"),
    ("Google Tag Manager", "body", r"googletagmanager\.com"),
    ("Yandex.Metrika", "body", r"mc\.yandex\.ru/metrika|ym\("),
    ("Facebook Pixel", "body", r"connect\.facebook\.net|fbq\("),
    ("Hotjar", "body", r"hotjar\.com|_hjSettings"),
    ("Segment", "body", r"segment\.com|analytics\.js"),
    ("Mixpanel", "body", r"mixpanel\.com|mixpanel\.init"),
    ("Amplitude", "body", r"amplitude\.com|amplitude\.getInstance"),
    # --- E-commerce ---
    ("WooCommerce", "body", r"woocommerce|wc-blocks"),
    ("Stripe", "body", r"js\.stripe\.com|Stripe\("),
    ("PayPal", "body", r"paypal\.com/sdk|paypalobjects"),
    ("Sentry", "body", r"sentry\.io|Sentry\.init"),
    # --- Security ---
    ("reCAPTCHA", "body", r"recaptcha|google\.com/recaptcha"),
    ("hCaptcha", "body", r"hcaptcha\.com|h-captcha"),
    ("Cloudflare Turnstile", "body", r"challenges\.cloudflare\.com/turnstile"),
    # --- Caching ---
    ("Redis", "header:x-cache-engine", r"redis"),
    ("Memcached", "header:x-cache-engine", r"memcached"),
    # --- Other ---
    ("Nginx Ultimate Bad Bot Blocker", "body", r"nginx-ultimate-bad-bot-blocker"),
    ("AMP", "body", r"amp-html|cdn\.ampproject\.org"),
    ("PWA", "body", r"service-worker|serviceWorker\.register"),
    ("GraphQL", "body", r"graphql|__schema"),
    ("Webpack", "body", r"webpackJsonp|webpack"),
    ("Turbo", "body", r"turbo\.js|turbo-frame"),
    ("Livewire", "body", r"livewire\.js|wire:"),
    ("Inertia.js", "body", r"inertia|@inertiajs"),
]


class TechDetectPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="tech_detect",
        display_name="Technology Detection",
        category=PluginCategory.ANALYSIS,
        description="Detects web technologies, frameworks, and CMS (Wappalyzer-style)",
        produces=["technologies"],
        timeout=15.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        headers: dict[str, str] = {}
        body = ""

        for scheme in ("https", "http"):
            url = f"{scheme}://{target.host}"
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(url, timeout=10.0)
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                    body = await resp.text(encoding="utf-8", errors="replace")
                    break
            except Exception:
                continue

        if not headers and not body:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info("Could not fetch page for tech detection")],
                data={"technologies": []},
            )

        detected: set[str] = set()

        for tech_name, location, pattern in TECH_SIGNATURES:
            try:
                if location.startswith("header:"):
                    header_name = location.split(":", 1)[1]
                    value = headers.get(header_name, "")
                    if value and re.search(pattern, value, re.IGNORECASE):
                        detected.add(tech_name)
                elif location == "body" and body:
                    if re.search(pattern, body, re.IGNORECASE):
                        detected.add(tech_name)
            except re.error:
                continue

        tech_list = sorted(detected)

        findings = [
            Finding.info(
                f"Technologies: {', '.join(tech_list) if tech_list else 'none detected'}",
                evidence=f"Detected {len(tech_list)} technologies",
                tags=["analysis", "tech-detect"],
            )
        ]

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"technologies": tech_list},
        )
