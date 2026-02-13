"""CDN detection — identifies content delivery networks."""

from __future__ import annotations

from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

CDN_SIGNATURES = {
    # === Major Global CDNs ===
    "cloudflare": {
        "headers": ["cf-ray", "cf-cache-status"],
        "cname": ["cloudflare"],
        "server": ["cloudflare"],
    },
    "akamai": {
        "headers": ["x-akamai-transformed", "x-akamai-request-id"],
        "cname": ["akamai", "edgesuite", "edgekey", "akamaized.net", "akadns.net"],
        "server": ["akamaighost", "akamaighostStaging"],
    },
    "fastly": {
        "headers": ["x-served-by", "x-fastly-request-id"],
        "cname": ["fastly", "fastlylb.net"],
        "server": ["fastly"],
    },
    "amazon_cloudfront": {
        "headers": ["x-amz-cf-id", "x-amz-cf-pop"],
        "cname": ["cloudfront.net"],
        "server": ["cloudfront"],
    },
    "google_cloud_cdn": {
        "headers": ["x-goog-generation", "x-goog-hash"],
        "cname": ["googleusercontent", "googlevideo.com"],
        "server": ["gws", "gse"],
    },
    "microsoft_azure": {
        "headers": ["x-msedge-ref", "x-azure-ref"],
        "cname": ["azureedge.net", "azure.com", "azurefd.net", "afd.net"],
        "server": [],
    },
    "stackpath": {
        "headers": ["x-sp-url", "x-sp-wl"],
        "cname": ["stackpathdns", "stackpathcdn.com"],
        "server": [],
    },
    "sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "cname": ["sucuri", "sucuri.net"],
        "server": ["sucuri"],
    },
    "imperva_incapsula": {
        "headers": ["x-iinfo", "x-cdn"],
        "cname": ["incapdns", "imperva"],
        "server": [],
    },
    "keycdn": {
        "headers": ["x-pull"],
        "cname": ["kxcdn", "keycdn.com"],
        "server": ["keycdn"],
    },
    "bunnycdn": {
        "headers": ["cdn-pullzone", "cdn-uid"],
        "cname": ["b-cdn.net", "bunny.net", "bunnycdn.com"],
        "server": ["bunnycdn"],
    },
    "ddos_guard": {
        "headers": [],
        "cname": ["ddos-guard", "ddos-guard.net"],
        "server": ["ddos-guard"],
    },
    "qrator": {
        "headers": ["x-qrator-requestid"],
        "cname": ["qrator", "qrator.net"],
        "server": ["qrator"],
    },
    "cdn77": {
        "headers": ["x-77-nzt"],
        "cname": ["cdn77", "cdn77.org"],
        "server": ["cdn77"],
    },
    "arvancloud": {
        "headers": ["ar-asg", "ar-request-id"],
        "cname": ["arvancloud", "arvan.cloud"],
        "server": ["arvancloud"],
    },
    "jsdelivr": {
        "headers": [],
        "cname": ["jsdelivr.net"],
        "server": [],
    },
    "limelight": {
        "headers": ["x-limelight-edge"],
        "cname": ["llnwd.net", "limelight", "llnw.net"],
        "server": [],
    },
    "edgecast": {
        "headers": ["x-ec-custom-error"],
        "cname": ["edgecastcdn", "systemcdn.net"],
        "server": ["ecacc"],
    },
    "tencent_cdn": {
        "headers": ["x-nws-log-uuid", "x-daa-tunnel"],
        "cname": ["cdn.dnsv1.com", "tdnsv5.com"],
        "server": [],
    },
    # === Global CDN (new) ===
    "verizon_digital_media": {
        "headers": ["x-ec-custom-error", "x-ec-debug"],
        "cname": ["edgecastcdn.net", "verizondigitalmedia.com"],
        "server": ["ecd"],
    },
    "alibaba_cdn": {
        "headers": ["eagleid", "x-oss-request-id"],
        "cname": ["alicdn.com", "kunlun.com", "alikunlun.com", "cdngslb.com"],
        "server": ["tengine"],
    },
    "gcore_cdn": {
        "headers": ["x-gcore-request-id"],
        "cname": ["gcdn.co", "gcorelabs.com", "gcore.com"],
        "server": ["gcore"],
    },
    "section_io": {
        "headers": ["x-section-io-id", "section-io-origin-status"],
        "cname": ["section.io", "sectionio.com"],
        "server": [],
    },
    "chinacache": {
        "headers": ["x-cc-via"],
        "cname": ["chinacache.net", "ccgslb.com"],
        "server": [],
    },
    "chinanetcenter": {
        "headers": ["x-cnc-request-id"],
        "cname": ["wscdns.com", "ourwebcdn.net", "wsdvs.com"],
        "server": [],
    },
    # === Regional CDNs ===
    "selectel_cdn": {
        "headers": [],
        "cname": ["selectel.ru", "slc.tl", "sel.cdn"],
        "server": [],
    },
    "mailru_cdn": {
        "headers": ["x-mru-request-id"],
        "cname": ["cdn.mail.ru"],
        "server": [],
    },
    "ngenix": {
        "headers": ["x-ngenix-cache"],
        "cname": ["ngenix.net", "delivery.ngenix.net"],
        "server": ["ngenix"],
    },
    "cdnetworks": {
        "headers": ["x-px-request-id"],
        "cname": ["cdnetworks.com", "cdnetdns.net", "gccdn.net"],
        "server": [],
    },
    "leaseweb_cdn": {
        "headers": [],
        "cname": ["lswcdn.net", "leasewebcdn.com"],
        "server": ["leaseweb"],
    },
    # === Specialized / Media CDNs ===
    "imgix": {
        "headers": ["x-imgix-id"],
        "cname": ["imgix.net"],
        "server": ["imgix"],
    },
    "cloudinary": {
        "headers": ["x-cld-error"],
        "cname": ["cloudinary.com", "res.cloudinary.com"],
        "server": ["cloudinary"],
    },
    "uploadcare": {
        "headers": ["x-uploadcare-cdn"],
        "cname": ["ucarecdn.com", "uploadcare.com"],
        "server": [],
    },
    "netlify_cdn": {
        "headers": ["x-nf-request-id"],
        "cname": ["netlify.app", "netlify.com", "netlifyglobalcdn.com"],
        "server": ["netlify"],
    },
    "vercel_edge": {
        "headers": ["x-vercel-id", "x-vercel-cache"],
        "cname": ["vercel.app", "vercel-dns.com"],
        "server": [],
    },
    "aws_global_accelerator": {
        "headers": ["x-amz-request-id"],
        "cname": ["awsglobalaccelerator.com"],
        "server": [],
    },
    # === DDoS / Security CDNs ===
    "stormwall": {
        "headers": ["x-sw-cache-status"],
        "cname": ["stormwall.pro", "stormwall.network"],
        "server": ["stormwall"],
    },
    "ddos_guard_pro": {
        "headers": ["x-ddg-request-id"],
        "cname": ["ddos-guard.net"],
        "server": ["ddos-guard"],
    },
    "qrator_pro": {
        "headers": ["x-qrator-requestid"],
        "cname": ["qrator.net", "qrator.cloud"],
        "server": ["qrator"],
    },
    "wallarm_cdn": {
        "headers": ["x-wallarm-waf-check"],
        "cname": ["wallarm.com", "wallarm.cloud"],
        "server": ["wallarm"],
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
