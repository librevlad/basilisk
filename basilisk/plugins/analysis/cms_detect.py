"""CMS detection — detailed identification of content management systems."""

from __future__ import annotations

import re
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

CMS_SIGNATURES = [
    # ===================================================================
    # Traditional CMS (popular)
    # ===================================================================
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
        "headers": {"x-generator": "drupal", "x-drupal-cache": "", "x-drupal-dynamic-cache": ""},
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
    # ===================================================================
    # Traditional CMS (additional)
    # ===================================================================
    {
        "name": "Craft CMS",
        "body": [r"craftcms", r"/cpresources/"],
        "headers": {"x-powered-by": "craft cms"},
        "meta_generator": r"Craft CMS\s*([\d.]+)?",
        "paths": ["/admin/"],
    },
    {
        "name": "October CMS",
        "body": [r"ocframework", r"/modules/cms/"],
        "headers": {"x-october-request-handler": ""},
        "meta_generator": r"OctoberCMS\s*([\d.]+)?",
        "paths": ["/backend/"],
    },
    {
        "name": "Textpattern",
        "body": [r"txp_token", r"textpattern"],
        "headers": {"x-powered-by": "textpattern"},
        "meta_generator": r"Textpattern\s*([\d.]+)?",
        "paths": ["/textpattern/"],
    },
    {
        "name": "SilverStripe",
        "body": [r"SilverStripe", r"/framework/css/"],
        "headers": {"x-silverstripe-info": ""},
        "meta_generator": r"SilverStripe\s*([\d.]+)?",
        "paths": ["/admin/"],
    },
    {
        "name": "ProcessWire",
        "body": [r"processwire", r"/site/templates/"],
        "headers": {"x-powered-by": "processwire"},
        "meta_generator": r"ProcessWire\s*([\d.]+)?",
        "paths": ["/processwire/"],
    },
    {
        "name": "Contao",
        "body": [r"contao", r"assets/contao/"],
        "headers": {"x-contao-cache": ""},
        "meta_generator": r"Contao Open Source CMS\s*([\d.]+)?",
        "paths": ["/contao/"],
    },
    {
        "name": "Backdrop CMS",
        "body": [r"backdrop\.js", r"Backdrop\.settings"],
        "headers": {},
        "meta_generator": r"Backdrop CMS\s*([\d.]+)?",
        "paths": [],
    },
    {
        "name": "Plone",
        "body": [r"portal_css", r"plone\.app", r"plone-toolbar"],
        "headers": {"x-powered-by": "plone"},
        "meta_generator": r"Plone\s*([\d.]+)?",
        "paths": ["/manage_main"],
    },
    {
        "name": "Umbraco",
        "body": [r"umbraco", r"/umbraco_client/"],
        "headers": {"x-umbraco-version": ""},
        "meta_generator": r"Umbraco\s*([\d.]+)?",
        "paths": ["/umbraco/"],
    },
    {
        "name": "Kentico",
        "body": [r"CMSPages", r"Kentico"],
        "headers": {},
        "meta_generator": r"Kentico\s*([\d.]+)?",
        "paths": ["/CMSPages/logon.aspx"],
    },
    {
        "name": "Sitecore",
        "body": [r"sitecore", r"/sitecore/shell/"],
        "headers": {"x-powered-by": "sitecore"},
        "meta_generator": r"Sitecore\s*([\d.]+)?",
        "paths": ["/sitecore/login/"],
    },
    {
        "name": "DotNetNuke",
        "body": [r"DNN_", r"dnnVariable", r"/DesktopModules/"],
        "headers": {},
        "meta_generator": r"DotNetNuke\s*([\d.]+)?",
        "paths": ["/Login.aspx"],
    },
    {
        "name": "ExpressionEngine",
        "body": [r"exp:channel", r"EE_APPPATH"],
        "headers": {"x-powered-by": "expressionengine"},
        "meta_generator": r"ExpressionEngine\s*([\d.]+)?",
        "paths": ["/admin.php"],
    },
    {
        "name": "Grav",
        "body": [r"/user/themes/", r"grav-"],
        "headers": {},
        "meta_generator": r"GravCMS\s*([\d.]+)?",
        "paths": ["/admin/"],
    },
    {
        "name": "Kirby",
        "body": [r"kirby", r"/assets/css/templates/"],
        "headers": {},
        "meta_generator": r"Kirby\s*([\d.]+)?",
        "paths": ["/panel/"],
    },
    {
        "name": "Statamic",
        "body": [r"statamic", r"/vendor/statamic/"],
        "headers": {"x-powered-by": "statamic"},
        "meta_generator": r"Statamic\s*([\d.]+)?",
        "paths": ["/cp/"],
    },
    {
        "name": "Bolt CMS",
        "body": [r"bolt\.js", r"/bolt/"],
        "headers": {},
        "meta_generator": r"Bolt\s*([\d.]+)?",
        "paths": ["/bolt/"],
    },
    {
        "name": "Pico",
        "body": [r"pico-content", r"PicoDeprecated"],
        "headers": {},
        "meta_generator": r"Pico\s*([\d.]+)?",
        "paths": [],
    },
    {
        "name": "Automad",
        "body": [r"automad", r"/packages/"],
        "headers": {},
        "meta_generator": r"Automad\s*([\d.]+)?",
        "paths": ["/dashboard/"],
    },
    # ===================================================================
    # E-commerce
    # ===================================================================
    {
        "name": "WooCommerce",
        "body": [r"woocommerce", r"wc-ajax", r"wc-cart-fragments"],
        "headers": {},
        "meta_generator": r"WooCommerce\s*([\d.]+)?",
        "paths": ["/shop/"],
    },
    {
        "name": "BigCommerce",
        "body": [r"bigcommerce", r"cdn11\.bigcommerce\.com"],
        "headers": {"x-bc-store-version": ""},
        "meta_generator": r"BigCommerce\s*([\d.]+)?",
        "paths": ["/manage/"],
    },
    {
        "name": "Volusion",
        "body": [r"volusion", r"a\.vimage"],
        "headers": {},
        "meta_generator": r"Volusion",
        "paths": ["/admin/"],
    },
    {
        "name": "osCommerce",
        "body": [r"osCommerce", r"osCsid"],
        "headers": {},
        "meta_generator": r"osCommerce\s*([\d.]+)?",
        "paths": ["/admin/"],
    },
    {
        "name": "Zen Cart",
        "body": [r"zen-cart", r"zencart", r"zen_cart"],
        "headers": {},
        "meta_generator": r"Zen Cart\s*([\d.]+)?",
        "paths": ["/admin/"],
    },
    {
        "name": "CS-Cart",
        "body": [r"cs-cart", r"cscart", r"dispatch="],
        "headers": {},
        "meta_generator": r"CS-Cart\s*([\d.]+)?",
        "paths": ["/admin.php"],
    },
    {
        "name": "nopCommerce",
        "body": [r"nopcommerce", r"nopCommerce"],
        "headers": {},
        "meta_generator": r"nopCommerce\s*([\d.]+)?",
        "paths": ["/Admin/"],
    },
    {
        "name": "Saleor",
        "body": [r"saleor", r"__saleor__"],
        "headers": {},
        "meta_generator": "",
        "paths": ["/dashboard/"],
    },
    {
        "name": "Medusa",
        "body": [r"medusa-", r"@medusajs"],
        "headers": {"x-powered-by": "medusa"},
        "meta_generator": "",
        "paths": ["/admin/"],
    },
    # ===================================================================
    # Forums / Community
    # ===================================================================
    {
        "name": "phpBB",
        "body": [r"phpBB", r"phpbb_", r"viewtopic\.php"],
        "headers": {},
        "meta_generator": r"phpBB\s*([\d.]+)?",
        "paths": ["/adm/"],
    },
    {
        "name": "vBulletin",
        "body": [r"vBulletin", r"vbulletin_", r"vb_login"],
        "headers": {},
        "meta_generator": r"vBulletin\s*([\d.]+)?",
        "paths": ["/admincp/"],
    },
    {
        "name": "Discourse",
        "body": [r"discourse-", r"ember-application", r"data-discourse-helper"],
        "headers": {},
        "meta_generator": r"Discourse\s*([\d.]+)?",
        "paths": ["/admin/"],
    },
    {
        "name": "XenForo",
        "body": [r"xenforo", r"XenForo", r"xf-body"],
        "headers": {},
        "meta_generator": r"XenForo\s*([\d.]+)?",
        "paths": ["/admin.php"],
    },
    {
        "name": "MyBB",
        "body": [r"mybb", r"MyBB", r"my_post_key"],
        "headers": {},
        "meta_generator": r"MyBB\s*([\d.]+)?",
        "paths": ["/admin/"],
    },
    {
        "name": "Flarum",
        "body": [r"flarum", r"Flarum", r"flarum-content"],
        "headers": {},
        "meta_generator": r"Flarum\s*([\d.]+)?",
        "paths": ["/admin/"],
    },
    {
        "name": "NodeBB",
        "body": [r"nodebb", r"NodeBB", r"nbb-"],
        "headers": {"x-powered-by": "nodebb"},
        "meta_generator": r"NodeBB\s*([\d.]+)?",
        "paths": ["/admin/"],
    },
    {
        "name": "IPBoard",
        "body": [r"ipb_", r"ips\.ui", r"ipsWidget"],
        "headers": {},
        "meta_generator": r"Invision Community\s*([\d.]+)?",
        "paths": ["/admin/"],
    },
    # ===================================================================
    # Wiki / Knowledge
    # ===================================================================
    {
        "name": "MediaWiki",
        "body": [r"wgPageName", r"mw-head", r"mediawiki"],
        "headers": {"x-powered-by": "mediawiki"},
        "meta_generator": r"MediaWiki\s*([\d.]+)?",
        "paths": ["/Special:Version"],
    },
    {
        "name": "DokuWiki",
        "body": [r"dokuwiki", r"doku\.php", r"DokuWiki"],
        "headers": {},
        "meta_generator": r"DokuWiki\s*([\d.]+)?",
        "paths": ["/doku.php"],
    },
    {
        "name": "Confluence",
        "body": [r"ajs-context-path", r"confluence-", r"Atlassian Confluence"],
        "headers": {"x-confluence-request-time": ""},
        "meta_generator": r"Atlassian Confluence\s*([\d.]+)?",
        "paths": ["/login.action"],
    },
    {
        "name": "BookStack",
        "body": [r"bookstack", r"BookStack"],
        "headers": {},
        "meta_generator": r"BookStack\s*([\d.]+)?",
        "paths": ["/login"],
    },
    {
        "name": "Wiki.js",
        "body": [r"wiki-js", r"wikijs"],
        "headers": {},
        "meta_generator": r"Wiki\.js\s*([\d.]+)?",
        "paths": [],
    },
    # ===================================================================
    # LMS
    # ===================================================================
    {
        "name": "Moodle",
        "body": [r"moodle", r"M\.cfg", r"/theme/yui_combo\.php"],
        "headers": {},
        "meta_generator": r"Moodle\s*([\d.]+)?",
        "paths": ["/login/index.php"],
    },
    {
        "name": "Canvas LMS",
        "body": [r"canvas-lms", r"instructure\.com", r"ic-app"],
        "headers": {},
        "meta_generator": "",
        "paths": ["/login/canvas"],
    },
    {
        "name": "Open edX",
        "body": [r"openedx", r"edx-bootstrap", r"edx-platform"],
        "headers": {},
        "meta_generator": "",
        "paths": ["/dashboard"],
    },
    # ===================================================================
    # Site builders
    # ===================================================================
    {
        "name": "Weebly",
        "body": [r"weebly\.com", r"wsite-"],
        "headers": {},
        "meta_generator": r"Weebly",
        "paths": [],
    },
    {
        "name": "Strikingly",
        "body": [r"strikingly\.com", r"s-page-container"],
        "headers": {},
        "meta_generator": r"Strikingly",
        "paths": [],
    },
    {
        "name": "Carrd",
        "body": [r"carrd\.co", r"is-carrd"],
        "headers": {},
        "meta_generator": r"Carrd",
        "paths": [],
    },
    {
        "name": "Bubble",
        "body": [r"bubble\.io", r"bubble-element"],
        "headers": {},
        "meta_generator": "",
        "paths": [],
    },
    {
        "name": "Framer",
        "body": [r"framer\.com", r"framer-"],
        "headers": {},
        "meta_generator": r"Framer",
        "paths": [],
    },
    # ===================================================================
    # Russian / CIS CMS
    # ===================================================================
    {
        "name": "UMI.CMS",
        "body": [r"umi-cms", r"umi\.ru", r"/umicms/"],
        "headers": {"x-generated-by": "umi.cms"},
        "meta_generator": r"UMI\.CMS\s*([\d.]+)?",
        "paths": ["/admin/"],
    },
    {
        "name": "NetCat",
        "body": [r"netcat", r"nc_path_prefix"],
        "headers": {},
        "meta_generator": r"NetCat\s*([\d.]+)?",
        "paths": ["/netcat/"],
    },
    {
        "name": "DataLife Engine",
        "body": [r"dle_", r"engine/classes", r"DataLife Engine"],
        "headers": {},
        "meta_generator": r"DataLife Engine\s*([\d.]+)?",
        "paths": ["/admin.php"],
    },
    {
        "name": "Ametys",
        "body": [r"ametys", r"Ametys"],
        "headers": {},
        "meta_generator": r"Ametys\s*([\d.]+)?",
        "paths": [],
    },
    {
        "name": "InSales",
        "body": [r"insales", r"static-cdn\.insales\.ru"],
        "headers": {},
        "meta_generator": r"InSales\s*([\d.]+)?",
        "paths": ["/admin/"],
    },
    # ===================================================================
    # Headless CMS (detectable via frontend scripts/markers)
    # ===================================================================
    {
        "name": "Strapi",
        "body": [r"strapi", r"/uploads/"],
        "headers": {"x-powered-by": "strapi"},
        "meta_generator": "",
        "paths": ["/admin/"],
    },
    {
        "name": "Sanity",
        "body": [r"sanity\.io", r"cdn\.sanity\.io"],
        "headers": {},
        "meta_generator": "",
        "paths": [],
    },
    {
        "name": "Contentful",
        "body": [r"contentful\.com", r"ctfl-", r"images\.ctfassets\.net"],
        "headers": {},
        "meta_generator": "",
        "paths": [],
    },
    {
        "name": "Storyblok",
        "body": [r"storyblok", r"a\.storyblok\.com"],
        "headers": {},
        "meta_generator": "",
        "paths": [],
    },
    {
        "name": "Prismic",
        "body": [r"prismic\.io", r"prismic-"],
        "headers": {},
        "meta_generator": r"Prismic",
        "paths": [],
    },
    {
        "name": "Directus",
        "body": [r"directus", r"Directus"],
        "headers": {"x-powered-by": "directus"},
        "meta_generator": "",
        "paths": ["/admin/"],
    },
    # ===================================================================
    # E-commerce platforms (additional)
    # ===================================================================
    {
        "name": "Ecwid",
        "body": [r"ecwid", r"Ecwid", r"app\.ecwid\.com"],
        "headers": {},
        "meta_generator": "",
        "paths": [],
    },
    {
        "name": "Swell",
        "body": [r"swell\.is", r"swell-js"],
        "headers": {},
        "meta_generator": "",
        "paths": [],
    },
    {
        "name": "Vendure",
        "body": [r"vendure", r"Vendure"],
        "headers": {},
        "meta_generator": "",
        "paths": ["/admin/"],
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

        # Use pre-probed scheme from autonomous mode when available
        _pre = ctx.state.get("http_scheme", {}).get(target.host)
        _schemes = (_pre,) if _pre else ("https", "http")

        for scheme in _schemes:
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(
                        f"{scheme}://{target.host}/", timeout=8.0,
                    )
                    headers = {k.lower(): v for k, v in resp.headers.items()}
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
                    hdr_value = headers.get(hdr, "")
                    if hdr_value and (not val or val in hdr_value.lower()):
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
