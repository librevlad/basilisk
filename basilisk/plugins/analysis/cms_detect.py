"""CMS detection — detailed identification of content management systems."""

from __future__ import annotations

import re
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

CMS_SIGNATURES = [
    {
        "name": "WordPress",
        "body": [r"wp-content", r"wp-includes"],
        "headers": {"x-powered-by": "wordpress"},
        "meta_generator": r"WordPress\s*([\d.]+)?",
        "paths": ["/wp-login.php"],
    },
    {
        "name": "Joomla",
        "body": [r"/media/jui/", r"Joomla!"],
        "headers": {},
        "meta_generator": r"Joomla!\s*([\d.]+)?",
        "paths": ["/administrator/"],
    },
    {
        "name": "Drupal",
        "body": [r"drupal\.js", r"Drupal\.settings"],
        "headers": {"x-generator": "drupal"},
        "meta_generator": r"Drupal\s*([\d.]+)?",
        "paths": [],
    },
    {
        "name": "1C-Bitrix",
        "body": [r"bitrix/js", r"BX\.message"],
        "headers": {"x-powered-cms": "bitrix"},
        "meta_generator": r"Bitrix",
        "paths": ["/bitrix/admin/"],
    },
    {
        "name": "Magento",
        "body": [r"Mage\.Cookies", r"/skin/frontend/"],
        "headers": {},
        "meta_generator": r"Magento",
        "paths": ["/admin/"],
    },
    {
        "name": "Shopify",
        "body": [r"cdn\.shopify\.com", r"Shopify\.theme"],
        "headers": {},
        "meta_generator": r"Shopify",
        "paths": [],
    },
    {
        "name": "Tilda",
        "body": [r"tildacdn\.com", r"tilda-"],
        "headers": {},
        "meta_generator": r"Tilda",
        "paths": [],
    },
    {
        "name": "Wix",
        "body": [r"wix\.com", r"wixsite\.com"],
        "headers": {},
        "meta_generator": r"Wix",
        "paths": [],
    },
    {
        "name": "Squarespace",
        "body": [r"squarespace\.com", r"static\.squarespace"],
        "headers": {},
        "meta_generator": r"Squarespace",
        "paths": [],
    },
    {
        "name": "Ghost",
        "body": [r"ghost-url"],
        "headers": {"x-ghost-cache-status": ""},
        "meta_generator": r"Ghost\s*([\d.]+)?",
        "paths": ["/ghost/"],
    },
    {
        "name": "MODX",
        "body": [r"assets/components", r"modx"],
        "headers": {"x-powered-by": "modx"},
        "meta_generator": r"MODX",
        "paths": ["/manager/"],
    },
    {
        "name": "PrestaShop",
        "body": [r"prestashop", r"/themes/default-bootstrap/"],
        "headers": {},
        "meta_generator": r"PrestaShop",
        "paths": ["/admin/"],
    },
    {
        "name": "OpenCart",
        "body": [r"opencart", r"route=common/home"],
        "headers": {},
        "meta_generator": r"OpenCart",
        "paths": ["/admin/"],
    },
    {
        "name": "Typo3",
        "body": [r"typo3conf", r"typo3temp"],
        "headers": {},
        "meta_generator": r"TYPO3\s*([\d.]+)?",
        "paths": ["/typo3/"],
    },
    {
        "name": "Concrete5",
        "body": [r"concrete5", r"/concrete/"],
        "headers": {},
        "meta_generator": r"concrete5\s*([\d.]+)?",
        "paths": [],
    },
    {
        "name": "Hugo",
        "body": [r"hugo-[\d]"],
        "headers": {},
        "meta_generator": r"Hugo\s*([\d.]+)?",
        "paths": [],
    },
    {
        "name": "Gatsby",
        "body": [r"__gatsby", r"gatsby-"],
        "headers": {"x-powered-by": "gatsby"},
        "meta_generator": r"Gatsby",
        "paths": [],
    },
    {
        "name": "Webflow",
        "body": [r"webflow\.com", r"wf-page"],
        "headers": {},
        "meta_generator": r"Webflow",
        "paths": [],
    },
    {
        "name": "Next.js",
        "body": [r"__NEXT_DATA__", r"_next/static"],
        "headers": {"x-powered-by": "next.js"},
        "meta_generator": "",
        "paths": [],
    },
    {
        "name": "Nuxt.js",
        "body": [r"__NUXT__", r"_nuxt/"],
        "headers": {},
        "meta_generator": "",
        "paths": [],
    },
]


class CmsDetectPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="cms_detect",
        display_name="CMS Detector",
        category=PluginCategory.ANALYSIS,
        description="Identifies CMS (WordPress, Joomla, Drupal, Bitrix, etc.)",
        produces=["cms_info"],
        timeout=15.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        findings: list[Finding] = []
        detected: list[dict] = []

        headers: dict = {}
        body = ""

        for scheme in ("https", "http"):
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(
                        f"{scheme}://{target.host}/", timeout=8.0,
                    )
                    headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
                    body = await resp.text(encoding="utf-8", errors="replace")
                    break
            except Exception:
                continue

        for cms in CMS_SIGNATURES:
            matched = False
            version = ""

            # Check body patterns
            for pattern in cms["body"]:
                if re.search(pattern, body, re.IGNORECASE):
                    matched = True
                    break

            # Check headers
            if not matched:
                for hdr, val in cms.get("headers", {}).items():
                    if hdr in headers and (not val or val in headers[hdr]):
                        matched = True
                        break

            # Check meta generator
            if cms.get("meta_generator"):
                gen_match = re.search(
                    rf'content="({cms["meta_generator"]})"', body, re.IGNORECASE,
                )
                if gen_match:
                    matched = True
                    if gen_match.lastindex and gen_match.lastindex >= 1:
                        ver = re.search(r"[\d.]+", gen_match.group(1))
                        if ver:
                            version = ver.group()

            if matched:
                info = {"name": cms["name"], "version": version}
                detected.append(info)
                findings.append(Finding.info(
                    f"CMS detected: {cms['name']}{' ' + version if version else ''}",
                    tags=["analysis", "cms"],
                ))

        if not detected:
            findings.append(Finding.info(
                "No CMS detected (custom or unknown)",
                tags=["analysis", "cms"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"cms": detected},
        )
