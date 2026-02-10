"""CDN detection — identifies content delivery networks."""

from __future__ import annotations

from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

CDN_SIGNATURES = {
    "cloudflare": {
        "headers": ["cf-ray", "cf-cache-status"],
        "cname": ["cloudflare"],
        "server": ["cloudflare"],
    },
    "akamai": {
        "headers": ["x-akamai-transformed"],
        "cname": ["akamai", "edgesuite", "edgekey"],
        "server": ["akamaighost"],
    },
    "fastly": {
        "headers": ["x-served-by", "x-fastly-request-id"],
        "cname": ["fastly"],
        "server": ["fastly"],
    },
    "amazon_cloudfront": {
        "headers": ["x-amz-cf-id", "x-amz-cf-pop"],
        "cname": ["cloudfront.net"],
        "server": ["cloudfront"],
    },
    "google_cloud_cdn": {
        "headers": ["x-goog-generation"],
        "cname": ["googleusercontent"],
        "server": ["gws", "gse"],
    },
    "microsoft_azure": {
        "headers": ["x-msedge-ref", "x-azure-ref"],
        "cname": ["azureedge.net", "azure.com"],
        "server": [],
    },
    "stackpath": {
        "headers": ["x-sp-url"],
        "cname": ["stackpathdns"],
        "server": [],
    },
    "sucuri": {
        "headers": ["x-sucuri-id"],
        "cname": ["sucuri"],
        "server": ["sucuri"],
    },
    "imperva_incapsula": {
        "headers": ["x-iinfo"],
        "cname": ["incapdns", "imperva"],
        "server": [],
    },
    "keycdn": {
        "headers": [],
        "cname": ["kxcdn"],
        "server": ["keycdn"],
    },
    "bunnycdn": {
        "headers": ["cdn-pullzone"],
        "cname": ["b-cdn.net"],
        "server": ["bunnycdn"],
    },
    "ddos_guard": {
        "headers": [],
        "cname": ["ddos-guard"],
        "server": ["ddos-guard"],
    },
    "qrator": {
        "headers": [],
        "cname": ["qrator"],
        "server": ["qrator"],
    },
    "cdn77": {
        "headers": [],
        "cname": ["cdn77"],
        "server": ["cdn77"],
    },
    "arvancloud": {
        "headers": ["ar-asg"],
        "cname": ["arvancloud"],
        "server": ["arvancloud"],
    },
    "jsdelivr": {
        "headers": [],
        "cname": ["jsdelivr.net"],
        "server": [],
    },
    "limelight": {
        "headers": [],
        "cname": ["llnwd.net", "limelight"],
        "server": [],
    },
    "edgecast": {
        "headers": ["x-ec-custom-error"],
        "cname": ["edgecastcdn"],
        "server": [],
    },
    "tencent_cdn": {
        "headers": [],
        "cname": ["cdn.dnsv1.com"],
        "server": [],
    },
}


class CdnDetectPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="cdn_detect",
        display_name="CDN Detection",
        category=PluginCategory.SCANNING,
        description="Identifies content delivery networks protecting the target",
        produces=["cdn_info"],
        timeout=10.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        findings: list[Finding] = []
        detected_cdns: list[str] = []
        headers: dict = {}

        for scheme in ("https", "http"):
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(
                        f"{scheme}://{target.host}/", timeout=8.0,
                    )
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                    break
            except Exception:
                continue

        # Check CNAME records
        cname_value = ""
        if ctx.dns:
            cname_records = await ctx.dns.resolve(target.host, "CNAME")
            if cname_records:
                cname_value = cname_records[0].value.lower()

        server = headers.get("server", "").lower()

        for cdn_name, sigs in CDN_SIGNATURES.items():
            matched = False
            for header_name in sigs["headers"]:
                if header_name in headers:
                    matched = True
                    break
            if not matched and cname_value:
                for cname_sig in sigs["cname"]:
                    if cname_sig in cname_value:
                        matched = True
                        break
            if not matched and server:
                for server_sig in sigs["server"]:
                    if server_sig in server:
                        matched = True
                        break
            if matched:
                detected_cdns.append(cdn_name)

        if detected_cdns:
            findings.append(Finding.info(
                f"CDN detected: {', '.join(detected_cdns)}",
                description="Target is behind a CDN, direct IP may differ",
                evidence=f"Server: {server}" if server else "Detected via headers/CNAME",
                tags=["scanning", "cdn"],
            ))
        else:
            findings.append(Finding.info(
                "No CDN detected",
                tags=["scanning", "cdn"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"cdn": detected_cdns, "server_header": server},
        )
