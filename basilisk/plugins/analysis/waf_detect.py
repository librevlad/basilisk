"""WAF (Web Application Firewall) detection."""

from __future__ import annotations

import re
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

WAF_SIGNATURES = {
    "Cloudflare": {"headers": ["cf-ray", "cf-cache-status"], "server": "cloudflare"},
    "AWS WAF": {"headers": ["x-amzn-requestid"], "body": r"aws.*waf"},
    "AWS Shield": {"headers": ["x-amzn-trace-id"], "body": r"aws.*shield"},
    "Akamai": {"headers": ["x-akamai-transformed"], "server": "akamaighost"},
    "Akamai Kona": {"headers": ["x-akamai-session-info"], "server": "akamaighost"},
    "Imperva/Incapsula": {"headers": ["x-iinfo", "x-cdn"], "body": r"incapsula"},
    "Sucuri": {"headers": ["x-sucuri-id"], "server": "sucuri"},
    "F5 BIG-IP": {"headers": [], "server": "big-ip", "cookie": "BIGipServer"},
    "Barracuda": {"headers": [], "server": "barracuda", "cookie": "barra_counter"},
    "ModSecurity": {"headers": [], "server": "mod_security", "body": r"mod_security"},
    "DenyAll": {"headers": [], "cookie": "sessioncookie"},
    "FortiWeb": {"headers": [], "cookie": "FORTIWAFSID"},
    "Wallarm": {"headers": ["x-wallarm-waf-check"]},
    "Qrator": {"headers": [], "server": "qrator"},
    "DDoS-Guard": {"headers": [], "server": "ddos-guard"},
    "Wordfence": {"headers": [], "body": r"wordfence", "cookie": "wfvt_"},
    "Palo Alto": {"headers": [], "body": r"has been blocked in accordance with company policy"},
    "Fortinet FortiGate": {"headers": [], "body": r"fortigate|fortiguard", "cookie": "FORTIWAFSID"},
    "Radware AppWall": {"headers": ["x-sl-compstate"], "body": r"radware"},
    "Citrix NetScaler": {"headers": ["cneonction", "x-citrix-"], "cookie": "ns_af"},
    "Google Cloud Armor": {"headers": [], "body": r"google.*cloud.*armor|your client has issued"},
    "Azure Front Door": {"headers": ["x-azure-ref"], "body": r"azure.*front.*door"},
    "Edgecast/Verizon": {"headers": ["x-ec-custom-error"]},
    "StackPath": {"headers": ["x-sp-url"], "server": "stackpath"},
    "Reblaze": {"headers": ["rbzid"]},
    "Signal Sciences": {"headers": ["x-sigsci-tags"]},
    "BitNinja": {"headers": [], "server": "bitninja"},
    "Imunify360": {"headers": [], "body": r"imunify360"},
    "NinjaFirewall": {"headers": [], "body": r"ninjafirewall"},
    "NSFocus": {"headers": [], "body": r"nsfocus"},
    "Tencent WAF": {"headers": [], "body": r"waf\.tencent"},
    "Alibaba Cloud WAF": {"headers": ["ali-cdn-real-ip"], "body": r"aliyun"},
    "ArvanCloud": {"headers": ["ar-asg"], "server": "arvancloud"},
    "Comodo WAF": {"headers": [], "server": "comodo"},
    "WebKnight": {"headers": [], "body": r"webknight"},
    "SiteLock": {"headers": ["x-sucuri-id"], "body": r"sitelock"},
    "Nemesida WAF": {"headers": ["nemesida"]},
    "Anquanbao": {"headers": ["x-powered-by-anquanbao"]},
    "SafeDog": {"headers": [], "server": "safedog", "cookie": "safedog"},
    "Yunjiasu": {"headers": [], "server": "yunjiasu"},
}


class WafDetectPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="waf_detect",
        display_name="WAF Detection",
        category=PluginCategory.ANALYSIS,
        description="Detects Web Application Firewalls protecting the target",
        produces=["waf_info"],
        timeout=15.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        findings: list[Finding] = []
        detected_wafs: list[str] = []
        headers: dict = {}
        body = ""
        cookies_str = ""

        for scheme in ("https", "http"):
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(
                        f"{scheme}://{target.host}/", timeout=8.0,
                    )
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                    body = await resp.text(encoding="utf-8", errors="replace")
                    cookies_str = " ".join(resp.headers.getall("Set-Cookie", []))
                    break
            except Exception:
                continue

        server = headers.get("server", "").lower()

        for waf_name, sigs in WAF_SIGNATURES.items():
            matched = False
            for h in sigs.get("headers", []):
                if h in headers:
                    matched = True
                    break
            if not matched and sigs.get("server") and sigs["server"] in server:
                matched = True
            if (
                not matched and sigs.get("body") and body
                and re.search(sigs["body"], body, re.IGNORECASE)
            ):
                matched = True
            if (
                not matched and sigs.get("cookie") and cookies_str
                and sigs["cookie"].lower() in cookies_str.lower()
            ):
                matched = True
            if matched:
                detected_wafs.append(waf_name)

        # Try triggering WAF with a suspicious request
        if not detected_wafs:
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(
                        f"https://{target.host}/?id=1'%20OR%201=1--",
                        timeout=8.0,
                    )
                    if resp.status in (403, 406, 429, 503):
                        detected_wafs.append("Unknown WAF")
                        findings.append(Finding.info(
                            "WAF detected (blocked suspicious request)",
                            evidence=f"Status {resp.status} on SQL-like payload",
                            tags=["analysis", "waf"],
                        ))
            except Exception:
                pass

        if detected_wafs:
            findings.insert(0, Finding.info(
                f"WAF detected: {', '.join(detected_wafs)}",
                description="Web Application Firewall is active",
                tags=["analysis", "waf"],
            ))
        elif not findings:
            findings.append(Finding.info(
                "No WAF detected",
                tags=["analysis", "waf"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"waf": detected_wafs},
        )
