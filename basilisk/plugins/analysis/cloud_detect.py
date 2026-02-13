"""Cloud provider detection — identifies hosting infrastructure."""

from __future__ import annotations

from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

# Common cloud provider IP range prefixes and header signatures
CLOUD_SIGNATURES = {
    # === Major Cloud Providers ===
    "AWS": {
        "headers": ["x-amz-request-id", "x-amz-id-2", "x-amz-cf-id"],
        "cname": ["amazonaws.com", "cloudfront.net", "elasticbeanstalk.com",
                  "awsglobalaccelerator.com"],
    },
    "Google Cloud": {
        "headers": ["x-goog-generation", "x-cloud-trace-context", "x-goog-hash"],
        "cname": ["googleapis.com", "googleusercontent.com", "appspot.com", "run.app",
                   "web.app", "firebaseapp.com"],
    },
    "Microsoft Azure": {
        "headers": ["x-azure-ref", "x-msedge-ref", "x-ms-request-id"],
        "cname": ["azurewebsites.net", "azure.com", "cloudapp.net", "azurefd.net",
                   "azure-api.net", "trafficmanager.net"],
    },
    "Oracle Cloud": {
        "headers": ["x-oracle-dms-ecid", "x-oracle-dms-rid"],
        "cname": ["oraclecloud.com", "ocp.oraclecloud.com", "oci.oraclecloud.com"],
    },
    "Alibaba Cloud": {
        "headers": ["x-oss-request-id", "eagleid"],
        "cname": ["alicdn.com", "aliyuncs.com", "alibabacloud.com", "cdngslb.com"],
    },
    "Tencent Cloud": {
        "headers": ["x-nws-log-uuid", "x-daa-tunnel"],
        "cname": ["myqcloud.com", "tencent-cloud.net", "cdn.dnsv1.com", "tdnsv5.com"],
    },
    "IBM Cloud": {
        "headers": ["x-bluemix-region", "x-ibm-client-id"],
        "cname": ["mybluemix.net", "appdomain.cloud", "cloud.ibm.com"],
    },
    "DigitalOcean": {
        "headers": ["x-do-app-origin", "x-do-orig-status"],
        "cname": ["digitaloceanspaces.com", "ondigitalocean.app"],
    },
    "Linode (Akamai)": {
        "headers": ["x-linode-id"],
        "cname": ["nodebalancer.linode.com", "linodeobjects.com", "ip.linodeusercontent.com"],
    },
    "Vultr": {
        "headers": [],
        "cname": ["vultr.com", "vultrobjects.com"],
    },
    "Hetzner Cloud": {
        "headers": [],
        "cname": ["hetzner.cloud", "your-server.de", "hcloud.host"],
    },
    "Scaleway": {
        "headers": ["x-scw-request-id"],
        "cname": ["scaleway.com", "scw.cloud", "s3.fr-par.scw.cloud"],
    },
    "OVHcloud": {
        "headers": [],
        "cname": ["ovh.net", "ovh.co.uk", "ovh.cloud", "hosting.ovh.net"],
    },
    # === PaaS Providers ===
    "Heroku": {
        "headers": ["x-heroku-dynos-in-use", "x-heroku-queue-depth"],
        "cname": ["herokuapp.com", "herokussl.com", "herokudns.com"],
    },
    "Netlify": {
        "headers": ["x-nf-request-id"],
        "cname": ["netlify.app", "netlify.com"],
    },
    "Vercel": {
        "headers": ["x-vercel-id", "x-vercel-cache"],
        "cname": ["vercel.app", "now.sh", "vercel.dns"],
    },
    "Cloudflare Pages": {
        "headers": [],
        "cname": ["pages.dev"],
    },
    "Render": {
        "headers": ["x-render-origin-server"],
        "cname": ["onrender.com", "render.com"],
    },
    "Railway": {
        "headers": [],
        "cname": ["railway.app", "up.railway.app"],
    },
    "Fly.io": {
        "headers": ["fly-request-id"],
        "cname": ["fly.dev", "edgeapp.net", "shw.io"],
    },
    "Platform.sh": {
        "headers": ["x-platform-server", "x-platform-cluster"],
        "cname": ["platform.sh", "platformsh.site"],
    },
    "Deta": {
        "headers": [],
        "cname": ["deta.app", "deta.dev"],
    },
    "Firebase Hosting": {
        "headers": ["x-firebase-hosting-cache"],
        "cname": ["web.app", "firebaseapp.com"],
    },
    "Supabase": {
        "headers": ["x-supabase-id"],
        "cname": ["supabase.co", "supabase.in"],
    },
    "Surge.sh": {
        "headers": [],
        "cname": ["surge.sh"],
    },
    # === Russian / CIS Cloud Providers ===
    "Yandex Cloud": {
        "headers": ["x-yandex-req-id", "x-yandex-uid"],
        "cname": ["yandexcloud.net", "storage.yandexcloud.net", "website.yandexcloud.net"],
    },
    "VK Cloud": {
        "headers": ["x-mcs-request-id"],
        "cname": ["mcs.mail.ru", "infra.mail.ru", "cloud.vk.com"],
    },
    "Selectel": {
        "headers": [],
        "cname": ["selectel.ru", "slc.tl", "sel.storage"],
    },
    "SberCloud": {
        "headers": [],
        "cname": ["sbercloud.ru", "hc.sbercloud.ru"],
    },
    # === Managed Hosting / Other ===
    "Fastly": {
        "headers": ["x-served-by", "x-fastly-request-id"],
        "cname": ["fastly.net", "fastlylb.net"],
    },
    "Pantheon": {
        "headers": ["x-pantheon-styx-hostname"],
        "cname": ["pantheonsite.io", "pantheon.io"],
    },
    "WP Engine": {
        "headers": ["x-powered-by-flavor"],
        "cname": ["wpengine.com", "wpenginepowered.com"],
    },
    "Kinsta": {
        "headers": ["x-kinsta-cache"],
        "cname": ["kinsta.cloud", "kinsta.com"],
    },
    "Cloudways": {
        "headers": ["x-cw-request-id"],
        "cname": ["cloudwaysapps.com"],
    },
}


class CloudDetectPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="cloud_detect",
        display_name="Cloud Provider Detection",
        category=PluginCategory.ANALYSIS,
        description="Identifies cloud hosting provider (AWS, GCP, Azure, etc.)",
        depends_on=["dns_enum"],
        produces=["cloud_info"],
        timeout=10.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        findings: list[Finding] = []
        detected: list[str] = []

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

        # Check CNAME
        cname = ""
        if ctx.dns:
            cname_records = await ctx.dns.resolve(target.host, "CNAME")
            if cname_records:
                cname = cname_records[0].value.lower()

        for provider, sigs in CLOUD_SIGNATURES.items():
            matched = False
            for h in sigs["headers"]:
                if h in headers:
                    matched = True
                    break
            if not matched and cname:
                for c in sigs["cname"]:
                    if c in cname:
                        matched = True
                        break
            if matched:
                detected.append(provider)

        if detected:
            findings.append(Finding.info(
                f"Cloud provider: {', '.join(detected)}",
                evidence=f"CNAME: {cname}" if cname else "Detected via headers",
                tags=["analysis", "cloud"],
            ))
        else:
            findings.append(Finding.info(
                "No cloud provider detected (likely self-hosted or traditional hosting)",
                tags=["analysis", "cloud"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"cloud_providers": detected, "cname": cname},
        )
