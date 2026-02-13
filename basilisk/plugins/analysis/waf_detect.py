"""WAF (Web Application Firewall) detection plugin.

Multi-probe fingerprinting inspired by wafw00f methodology:
- Signature-based detection via headers, cookies, body patterns, server strings
- Behavioral detection via response-code diff between normal and suspicious probes
- CDN vs WAF differentiation
- Confidence scoring (0-100)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target
from basilisk.utils.http_check import resolve_base_url

# ---------------------------------------------------------------------------
# Structured WAF signature
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class WafSignature:
    """Signature for a single WAF/CDN product."""

    name: str
    headers: tuple[str, ...] = ()
    server: str = ""
    cookie: str = ""
    body: str = ""
    status_codes: tuple[int, ...] = ()
    is_cdn: bool = False  # True = CDN that MAY also have WAF rules


# ---------------------------------------------------------------------------
# 125+ WAF / CDN signatures
# ---------------------------------------------------------------------------

WAF_SIGNATURES: tuple[WafSignature, ...] = (
    # --- Major cloud WAFs ---
    WafSignature(
        "Cloudflare",
        headers=("cf-ray", "cf-cache-status", "cf-mitigated"),
        server="cloudflare",
        is_cdn=True,
    ),
    WafSignature(
        "AWS WAF",
        headers=("x-amzn-requestid", "x-amzn-waf-action"),
        body=r"aws[.\s-]*waf",
    ),
    WafSignature(
        "AWS Shield",
        headers=("x-amzn-trace-id",),
        body=r"aws[.\s-]*shield",
    ),
    WafSignature(
        "Akamai",
        headers=("x-akamai-transformed", "akamai-grn"),
        server="akamaighost",
        is_cdn=True,
    ),
    WafSignature(
        "Akamai Kona",
        headers=("x-akamai-session-info",),
        server="akamaighost",
        body=r"reference\s*#[\da-f.]+",
    ),
    WafSignature(
        "Azure Front Door",
        headers=("x-azure-ref", "x-fd-healthprobe"),
        body=r"azure.*front.*door",
        is_cdn=True,
    ),
    WafSignature(
        "Azure WAF",
        headers=("x-azure-ref",),
        body=r"azure.*application.*gateway",
    ),
    WafSignature(
        "Google Cloud Armor",
        headers=(),
        body=r"google.*cloud.*armor|your client has issued",
        status_codes=(403,),
    ),
    WafSignature(
        "Fastly WAF",
        headers=("x-fastly-request-id", "fastly-restarts"),
        server="fastly",
        is_cdn=True,
    ),
    WafSignature(
        "Vercel",
        headers=("x-vercel-id", "x-vercel-cache"),
        server="vercel",
        is_cdn=True,
    ),

    # --- Enterprise WAFs ---
    WafSignature(
        "Imperva Incapsula",
        headers=("x-iinfo", "x-cdn"),
        cookie="incap_ses_",
        body=r"incapsula|imperva",
    ),
    WafSignature(
        "Imperva SecureSphere",
        headers=("x-iinfo",),
        cookie="MgmtConsole",
        body=r"secureSphere|imperva.*securesphere",
    ),
    WafSignature(
        "F5 BIG-IP",
        server="big-ip",
        cookie="BIGipServer",
    ),
    WafSignature(
        "F5 BIG-IP ASM",
        headers=("x-waf-status",),
        cookie="TS",
        body=r"the requested url was rejected",
        server="big-ip",
    ),
    WafSignature(
        "Barracuda",
        server="barracuda",
        cookie="barra_counter",
        body=r"barracuda",
    ),
    WafSignature(
        "Fortinet FortiGate",
        cookie="FORTIWAFSID",
        body=r"fortigate|fortiguard|.fgd_icon",
    ),
    WafSignature(
        "Fortinet FortiWeb",
        headers=("x-forweb-version",),
        cookie="FORTIWAFSID",
        body=r"fortiweb|by fortinet",
    ),
    WafSignature(
        "Palo Alto",
        body=r"has been blocked in accordance with company policy",
        status_codes=(403,),
    ),
    WafSignature(
        "Citrix NetScaler",
        headers=("cneonction", "x-citrix-request-id"),
        cookie="ns_af",
        body=r"ns_af.*netscaler|citrix.*netscaler",
    ),
    WafSignature(
        "Radware AppWall",
        headers=("x-sl-compstate",),
        body=r"radware|appwall",
    ),
    WafSignature(
        "Check Point",
        headers=("x-checkpoint",),
        cookie="cpSID",
        body=r"check\s*point|cpdefense",
    ),
    WafSignature(
        "SonicWall",
        server="sonicwall",
        body=r"sonicwall|web site is being filtered",
        cookie="SonicWALL",
    ),
    WafSignature(
        "Sophos UTM",
        headers=(),
        server="sophos",
        body=r"sophos|utm.*web.*protection",
    ),
    WafSignature(
        "Juniper",
        body=r"juniper.*srx|juniper.*web.*filter",
    ),

    # --- Cloud CDN / Edge ---
    WafSignature(
        "Sucuri",
        headers=("x-sucuri-id", "x-sucuri-cache"),
        server="sucuri",
        is_cdn=True,
    ),
    WafSignature(
        "Edgecast/Verizon",
        headers=("x-ec-custom-error",),
        server="ecacc",
        is_cdn=True,
    ),
    WafSignature(
        "StackPath",
        headers=("x-sp-url", "x-sp-waf-id"),
        server="stackpath",
        is_cdn=True,
    ),
    WafSignature(
        "KeyCDN",
        headers=("x-edge-location",),
        server="keycdn",
        is_cdn=True,
    ),
    WafSignature(
        "Bunny.net",
        headers=("cdn-pullzone", "cdn-uid", "cdn-requestid"),
        server="bunnycdn",
        is_cdn=True,
    ),
    WafSignature(
        "CDN77",
        headers=("x-cdn77-cache",),
        server="cdn77",
        is_cdn=True,
    ),
    WafSignature(
        "Limelight",
        headers=("x-llnw-authorization",),
        server="limelight",
        is_cdn=True,
    ),
    WafSignature(
        "ArvanCloud",
        headers=("ar-asg",),
        server="arvancloud",
        is_cdn=True,
    ),

    # --- Chinese WAFs / CDNs ---
    WafSignature(
        "Alibaba Cloud WAF",
        headers=("ali-cdn-real-ip", "eagleid"),
        body=r"aliyun|alibaba.*cloud",
    ),
    WafSignature(
        "Tencent Cloud WAF",
        headers=(),
        body=r"waf\.tencent|tencent.*cloud.*waf",
        cookie="tgw_l7_route",
    ),
    WafSignature(
        "Baidu Yunjiasu",
        headers=("x-daa-tunnel",),
        server="yunjiasu",
        body=r"yunjiasu",
        is_cdn=True,
    ),
    WafSignature(
        "360WangZhanBao",
        headers=("x-powered-by-360wzb",),
        body=r"360wzb|wangzhan.*bao",
    ),
    WafSignature(
        "Jiasule",
        headers=("x-via-jsl",),
        cookie="__jsluid",
        is_cdn=True,
    ),
    WafSignature(
        "HuaweiCloud WAF",
        headers=("x-huawei-waf",),
        body=r"huawei.*cloud.*waf|hwclouds",
        cookie="HWWAFSESID",
    ),
    WafSignature(
        "Yundun",
        headers=("x-yundun-cache",),
        server="yundun",
        body=r"yundun",
    ),
    WafSignature(
        "PowerCDN",
        headers=("powercdn",),
        server="powercdn",
        is_cdn=True,
    ),
    WafSignature(
        "Anquanbao",
        headers=("x-powered-by-anquanbao",),
        body=r"anquanbao",
    ),
    WafSignature(
        "SafeDog",
        server="safedog",
        cookie="safedog",
        body=r"safedog",
    ),
    WafSignature(
        "NSFocus",
        body=r"nsfocus",
    ),

    # --- Specialty / Open-source WAFs ---
    WafSignature(
        "ModSecurity",
        server="mod_security",
        body=r"mod_security|modsecurity",
    ),
    WafSignature(
        "NAXSI",
        headers=(),
        body=r"naxsi|request denied.*naxsi",
        server="naxsi",
    ),
    WafSignature(
        "OpenResty lua-resty-waf",
        server="openresty",
        body=r"lua-resty-waf|openresty.*denied",
    ),
    WafSignature(
        "Shadow Daemon",
        headers=(),
        body=r"shadow.*daemon",
    ),
    WafSignature(
        "LuaSec",
        headers=(),
        body=r"luasec|lua.*security",
        server="luasec",
    ),
    WafSignature(
        "Wallarm",
        headers=("x-wallarm-waf-check",),
    ),
    WafSignature(
        "Reblaze",
        headers=("rbzid",),
        cookie="rbzid",
    ),
    WafSignature(
        "Signal Sciences",
        headers=("x-sigsci-tags", "x-sigsci-decision-ms"),
    ),
    WafSignature(
        "Stormwall",
        headers=(),
        server="stormwall",
        cookie="swp_token",
        body=r"stormwall",
    ),

    # --- WordPress / CMS WAFs ---
    WafSignature(
        "Wordfence",
        body=r"wordfence|wfwaf-authcookie",
        cookie="wfvt_",
    ),
    WafSignature(
        "NinjaFirewall",
        headers=("x-ninjafirewall",),
        body=r"ninjafirewall",
    ),
    WafSignature(
        "SiteLock",
        headers=("x-sucuri-id",),
        body=r"sitelock",
    ),

    # --- Anti-DDoS ---
    WafSignature(
        "Qrator",
        server="qrator",
        headers=("x-qrator-requestid",),
    ),
    WafSignature(
        "DDoS-Guard",
        server="ddos-guard",
        cookie="__ddg",
    ),
    WafSignature(
        "BitNinja",
        server="bitninja",
    ),
    WafSignature(
        "Imunify360",
        body=r"imunify360",
    ),
    WafSignature(
        "Comodo WAF",
        server="comodo",
        body=r"comodo.*waf",
    ),
    WafSignature(
        "WebKnight",
        body=r"webknight",
        server="webknight",
    ),
    WafSignature(
        "Nemesida WAF",
        headers=("nemesida",),
        body=r"nemesida",
    ),
    WafSignature(
        "DenyAll",
        cookie="sessioncookie",
        body=r"conditionblocked|denyall",
    ),

    # --- Misc / Regional ---
    WafSignature(
        "CrawlProtect",
        body=r"crawlprotect",
        cookie="crawlprotect",
    ),
    WafSignature(
        "BulletProof Security",
        body=r"bulletproof.*security",
    ),
    WafSignature(
        "RSFirewall",
        body=r"rsfirewall|com_rsfirewall",
    ),
    WafSignature(
        "Approach",
        headers=("x-approach-cache",),
        server="approach",
    ),
    WafSignature(
        "PerimeterX",
        headers=("x-px-cookie",),
        cookie="_pxhd",
        body=r"perimeterx|px-block",
    ),
    WafSignature(
        "DataPower",
        headers=("x-backside-transport",),
        server="datapower",
    ),
    WafSignature(
        "Squarespace",
        headers=("x-servedby",),
        server="squarespace",
        is_cdn=True,
    ),
    WafSignature(
        "Netlify",
        headers=("x-nf-request-id",),
        server="netlify",
        is_cdn=True,
    ),
    WafSignature(
        "Bekchy",
        body=r"bekchy.*access.*denied",
    ),
    WafSignature(
        "TrafficShield",
        headers=(),
        server="f5.*trafficshield",
        cookie="ASINFO",
    ),

    # --- Cloud WAFs (additional) ---
    WafSignature(
        "Oracle Cloud WAF",
        headers=("x-oracle-dms-ecid", "x-oracle-dms-rid"),
        body=r"oracle.*cloud|oracle.*waf",
    ),
    WafSignature(
        "Alibaba Cloud CDN",
        headers=("ali-swift-global-savetime", "x-swift-savetime"),
        server="tengine",
        is_cdn=True,
    ),
    WafSignature(
        "Tencent Cloud CDN",
        headers=("x-nws-log-uuid",),
        server="tencent",
        is_cdn=True,
    ),
    WafSignature(
        "OVHcloud",
        headers=("x-ovh-id",),
        server="ovh",
        is_cdn=True,
    ),
    WafSignature(
        "Imperva Cloud WAF",
        headers=("x-iinfo",),
        cookie="visid_incap",
        body=r"imperva.*cloud|powered by imperva",
    ),
    WafSignature(
        "Azure CDN",
        headers=("x-ms-ref", "x-ms-request-id"),
        server="ecacc",
        is_cdn=True,
    ),
    WafSignature(
        "Amazon CloudFront",
        headers=("x-amz-cf-id", "x-amz-cf-pop"),
        server="cloudfront",
        is_cdn=True,
    ),
    WafSignature(
        "Google Cloud CDN",
        headers=("x-goog-cache-status",),
        server="google frontend",
        is_cdn=True,
    ),

    # --- Enterprise / commercial WAFs (additional) ---
    WafSignature(
        "Radware DefensePro",
        body=r"radware.*defensepro|request blocked.*radware",
    ),
    WafSignature(
        "Blue Coat ProxySG",
        headers=("x-bluecoat-via",),
        body=r"blue\s*coat|proxySG",
        server="blue coat",
    ),
    WafSignature(
        "Cisco ACE XML Gateway",
        server="cisco-ace",
    ),
    WafSignature(
        "A10 Thunder",
        headers=("x-a10-forwarded-for",),
        server="a10",
    ),
    WafSignature(
        "Barracuda CloudGen",
        headers=("x-barra-cloudgen",),
        body=r"barracuda.*cloudgen",
        server="barracuda",
    ),
    WafSignature(
        "Ergon Airlock",
        headers=("al-req-id",),
        body=r"airlock|ergon.*airlock",
    ),
    WafSignature(
        "ThreatX",
        headers=("x-threatx",),
        body=r"threatx",
    ),
    WafSignature(
        "Alert Logic",
        body=r"alert\s*logic|alertlogic",
    ),
    WafSignature(
        "Edgeware",
        server="edgeware",
    ),
    WafSignature(
        "Zenedge",
        headers=("x-zen-fury",),
        body=r"zenedge",
    ),
    WafSignature(
        "AppTrana",
        headers=("x-wf-sid",),
        body=r"apptrana",
        server="apptrana",
    ),
    WafSignature(
        "USP Secure Entry",
        server="usp-ses",
        body=r"usp.*secure.*entry",
    ),
    WafSignature(
        "Snapt Aria",
        server="snapt",
        body=r"snapt|aria.*waf",
    ),
    WafSignature(
        "Imperva WAF Gateway",
        headers=("x-iinfo",),
        cookie="incap_ses_",
        body=r"imperva.*waf.*gateway",
    ),

    # --- Open-source / specialty WAFs ---
    WafSignature(
        "Coraza WAF",
        body=r"coraza",
        server="coraza",
    ),
    WafSignature(
        "SafeLine",
        server="safeline",
        body=r"safeline|chaitin",
    ),
    WafSignature(
        "OpenWAF",
        server="openwaf",
        body=r"openwaf",
    ),
    WafSignature(
        "lua-resty-waf",
        body=r"lua-resty-waf|resty\.waf",
        server="openresty",
    ),
    WafSignature(
        "IronBee",
        body=r"ironbee",
        server="ironbee",
    ),
    WafSignature(
        "WebCastellum",
        body=r"webcastellum",
    ),
    WafSignature(
        "Profense",
        headers=("x-profense",),
        server="profense",
    ),
    WafSignature(
        "Positive Technologies PT AF",
        headers=("x-pt-request-id",),
        body=r"ptaf|positive.*technologies.*application.*firewall",
    ),
    WafSignature(
        "GoDaddy WAF",
        server="gd-waf",
    ),

    # --- CDNs (additional) ---
    WafSignature(
        "Incapsula CDN",
        headers=("x-cdn",),
        cookie="incap_ses_",
        is_cdn=True,
    ),
    WafSignature(
        "G-Core CDN",
        headers=("x-id",),
        server="gcore",
        is_cdn=True,
    ),
    WafSignature(
        "Fly.io",
        headers=("fly-request-id",),
        server="fly",
        is_cdn=True,
    ),
    WafSignature(
        "Railway",
        headers=("x-railway-request-id",),
        is_cdn=True,
    ),
    WafSignature(
        "Render",
        headers=("x-render-origin-server",),
        is_cdn=True,
    ),
    WafSignature(
        "Section.io",
        headers=("section-io-id",),
        is_cdn=True,
    ),
    WafSignature(
        "Selectel CDN",
        headers=("x-selectel-id",),
        server="selectel",
        is_cdn=True,
    ),

    # --- Anti-bot / Anti-fraud ---
    WafSignature(
        "Datadome",
        headers=("x-datadome",),
        cookie="datadome",
    ),
    WafSignature(
        "Kasada",
        body=r"kasada",
        cookie="_kpsdk",
    ),
    WafSignature(
        "HUMAN Bot Defender",
        headers=("x-px-fp",),
        cookie="_pxhd",
        body=r"human\s*security|humansecurity",
    ),
    WafSignature(
        "Arkose Labs",
        body=r"arkoselabs|funcaptcha",
    ),
    WafSignature(
        "Distil Networks",
        cookie="D_SID",
        body=r"distil",
    ),
    WafSignature(
        "Shape Security",
        body=r"shape\s*security|shapesecurity",
    ),

    # --- Russian / CIS WAFs ---
    WafSignature(
        "Solar webProxy",
        body=r"solar\s*web\s*proxy|ростелеком.*солар",
    ),
    WafSignature(
        "InfoWatch Attack Killer",
        body=r"infowatch|attack\s*killer",
    ),
    WafSignature(
        "Garda WAF",
        body=r"garda\s*waf",
    ),
    WafSignature(
        "Continent WAF",
        body=r"continent\s*waf|континент.*waf",
    ),

    # --- Hosting / platform edge ---
    WafSignature(
        "Automattic/WordPress.com",
        headers=("x-ac",),
        server="wordpress.com",
        is_cdn=True,
    ),
    WafSignature(
        "Pantheon",
        headers=("x-pantheon-styx-hostname",),
        server="pantheon",
        is_cdn=True,
    ),
    WafSignature(
        "WP Engine",
        headers=("x-wpe-backend",),
        is_cdn=True,
    ),
    WafSignature(
        "Kinsta",
        headers=("x-kinsta-cache",),
        is_cdn=True,
    ),
)


# ---------------------------------------------------------------------------
# Probe payloads for behavioral detection
# ---------------------------------------------------------------------------

_PROBES: tuple[tuple[str, str], ...] = (
    ("sqli", "/?id=1'%20OR%201=1--"),
    ("xss", "/?q=<script>alert(1)</script>"),
    ("traversal", "/../../../etc/passwd"),
    ("rce", "/?cmd=;cat%20/etc/passwd"),
)

# Status codes that typically indicate WAF blocking
_BLOCK_CODES = frozenset({403, 405, 406, 429, 451, 501, 503})


# ---------------------------------------------------------------------------
# Detection result
# ---------------------------------------------------------------------------

@dataclass
class WafMatch:
    """A single WAF/CDN detection result."""

    name: str
    confidence: int  # 0-100
    detection_method: str
    is_cdn: bool = False


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------

class WafDetectPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="waf_detect",
        display_name="WAF Detection",
        category=PluginCategory.ANALYSIS,
        description=(
            "Detects Web Application Firewalls via signature matching "
            "and behavioral probing (125+ signatures)"
        ),
        produces=["waf_info"],
        timeout=30.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host,
                error="HTTP client not available",
            )

        base_url = await resolve_base_url(target.host, ctx)
        if not base_url:
            return PluginResult.fail(
                self.meta.name, target.host,
                error="Target unreachable via HTTP/HTTPS",
            )

        findings: list[Finding] = []
        matches: list[WafMatch] = []

        # ---- Phase 1: multi-probe signature matching ----
        # Probe multiple endpoints for better detection rate
        probe_urls = [
            f"{base_url}/",
            f"{base_url}/_nonexistent_8x7z_waf_test",
            f"{base_url}/?q=<script>alert(1)</script>",
        ]
        baseline = None
        for probe_url in probe_urls:
            resp = await self._fetch(ctx, probe_url)
            if resp is None:
                continue
            if baseline is None:
                baseline = resp
            sig_matches = self._match_signatures(resp)
            for sm in sig_matches:
                if not any(m.name == sm.name for m in matches):
                    matches.extend([sm])

        # Additional fingerprinting: challenge page detection
        if baseline is not None and any(
            p in baseline.body.lower()
            for p in (
                "checking your browser",
                "just a moment",
                "please wait",
                "ddos protection",
                "challenge-platform",
                "cf-browser-verification",
            )
        ) and not any(m.name == "Cloudflare" for m in matches):
            matches.append(WafMatch(
                name="Challenge Page (unknown WAF)",
                confidence=75,
                detection_method="challenge_page",
            ))

        # ---- Phase 2: behavioural probes ----
        baseline_status = baseline.status if baseline else 0
        behavioral_hits = 0

        for _probe_name, probe_path in _PROBES:
            probe_resp = await self._fetch(
                ctx, f"{base_url}{probe_path}",
            )
            if probe_resp is None:
                continue

            # Check if probe was blocked while baseline was not
            if (
                baseline_status not in _BLOCK_CODES
                and probe_resp.status in _BLOCK_CODES
            ):
                behavioral_hits += 1

            # Also run signature matching on probe responses
            # (WAFs often reveal themselves on block pages)
            probe_sigs = self._match_signatures(probe_resp)
            for pm in probe_sigs:
                if not any(m.name == pm.name for m in matches):
                    matches.append(pm)

        # Behavioral detection (no signature matched but probes blocked)
        if behavioral_hits > 0 and not matches:
            confidence = min(60 + behavioral_hits * 10, 90)
            matches.append(WafMatch(
                name="Unknown WAF",
                confidence=confidence,
                detection_method="behavioral",
            ))
            findings.append(Finding.info(
                "WAF detected via behavioral analysis",
                evidence=(
                    f"{behavioral_hits}/{len(_PROBES)} probes blocked "
                    f"(baseline status={baseline_status})"
                ),
                tags=["analysis", "waf"],
            ))

        # ---- Phase 3: CDN vs WAF differentiation ----
        cdn_list: list[str] = []
        waf_list: list[dict] = []
        waf_active = False

        for m in matches:
            entry = {
                "name": m.name,
                "confidence": m.confidence,
                "detection_method": m.detection_method,
            }
            if m.is_cdn:
                cdn_list.append(m.name)
                # Check if CDN has WAF rules active (probes get blocked)
                if behavioral_hits > 0:
                    waf_active = True
                    waf_list.append(entry)
                    findings.append(Finding.info(
                        f"CDN with active WAF rules: {m.name}",
                        description=(
                            f"{m.name} detected as CDN with WAF rules "
                            "actively blocking suspicious requests"
                        ),
                        evidence=f"detection={m.detection_method}, "
                                 f"confidence={m.confidence}%",
                        tags=["analysis", "waf", "cdn"],
                    ))
                else:
                    findings.append(Finding.info(
                        f"CDN detected: {m.name} (WAF rules not confirmed)",
                        description=(
                            f"{m.name} headers present but no suspicious "
                            "requests were blocked"
                        ),
                        evidence=f"detection={m.detection_method}, "
                                 f"confidence={m.confidence}%",
                        tags=["analysis", "cdn"],
                    ))
            else:
                waf_active = True
                waf_list.append(entry)
                findings.append(Finding.info(
                    f"WAF detected: {m.name} (confidence {m.confidence}%)",
                    description=(
                        f"Detection method: {m.detection_method}"
                    ),
                    evidence=f"detection={m.detection_method}, "
                             f"confidence={m.confidence}%",
                    tags=["analysis", "waf"],
                ))

        if not matches:
            findings.append(Finding.info(
                "No WAF/CDN detected",
                description=(
                    "No WAF signatures matched and suspicious probes "
                    "were not blocked"
                ),
                tags=["analysis", "waf"],
            ))

        # Store detected WAFs in pipeline state for downstream plugins
        detected_names = [w["name"] for w in waf_list]
        ctx.state["detected_wafs"] = detected_names

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "waf": waf_list,
                "cdn": cdn_list,
                "waf_active": waf_active,
            },
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    async def _fetch(ctx, url: str) -> _ProbeResponse | None:
        """Fetch a URL and return a lightweight response wrapper."""
        try:
            async with ctx.rate:
                resp = await ctx.http.get(url, timeout=8.0)
                headers = {
                    k.lower(): v for k, v in resp.headers.items()
                }
                body = await resp.text(
                    encoding="utf-8", errors="replace",
                )
                cookies_raw = " ".join(
                    resp.headers.getall("Set-Cookie", [])
                )
                return _ProbeResponse(
                    status=resp.status,
                    headers=headers,
                    server=headers.get("server", "").lower(),
                    body=body[:8000],
                    cookies=cookies_raw.lower(),
                )
        except Exception:
            return None

    @staticmethod
    def _match_signatures(resp: _ProbeResponse) -> list[WafMatch]:
        """Match all WAF signatures against a single response."""
        results: list[WafMatch] = []

        for sig in WAF_SIGNATURES:
            best_confidence = 0
            best_method = ""

            # Header match (highest confidence)
            for h in sig.headers:
                if h in resp.headers:
                    best_confidence = max(best_confidence, 95)
                    best_method = f"header:{h}"
                    break

            # Cookie match
            if sig.cookie and sig.cookie.lower() in resp.cookies:
                c = 85
                if c > best_confidence:
                    best_confidence = c
                    best_method = f"cookie:{sig.cookie}"

            # Server string match
            if sig.server and sig.server in resp.server:
                c = 90
                if c > best_confidence:
                    best_confidence = c
                    best_method = f"server:{sig.server}"

            # Body pattern match
            if (
                sig.body
                and resp.body
                and re.search(sig.body, resp.body, re.IGNORECASE)
            ):
                c = 70
                if c > best_confidence:
                    best_confidence = c
                    best_method = f"body:{sig.body[:40]}"

            # Status code match (only if codes are specified)
            if sig.status_codes and resp.status in sig.status_codes:
                c = 50
                if c > best_confidence:
                    best_confidence = c
                    best_method = f"status:{resp.status}"

            if best_confidence > 0:
                results.append(WafMatch(
                    name=sig.name,
                    confidence=best_confidence,
                    detection_method=best_method,
                    is_cdn=sig.is_cdn,
                ))

        return results


# ---------------------------------------------------------------------------
# Lightweight response container (avoids keeping aiohttp objects alive)
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class _ProbeResponse:
    status: int
    headers: dict[str, str]
    server: str
    body: str
    cookies: str
