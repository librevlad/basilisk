"""Cloud provider detection — identifies hosting infrastructure."""

from __future__ import annotations

from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

# Common cloud provider IP range prefixes and header signatures
CLOUD_SIGNATURES = {
    "AWS": {
        "headers": ["x-amz-request-id", "x-amz-id-2", "x-amz-cf-id"],
        "cname": ["amazonaws.com", "cloudfront.net", "elasticbeanstalk.com"],
    },
    "Google Cloud": {
        "headers": ["x-goog-generation", "x-cloud-trace-context"],
        "cname": ["googleapis.com", "googleusercontent.com", "appspot.com"],
    },
    "Microsoft Azure": {
        "headers": ["x-azure-ref", "x-msedge-ref", "x-ms-request-id"],
        "cname": ["azurewebsites.net", "azure.com", "cloudapp.net"],
    },
    "DigitalOcean": {
        "headers": ["x-do-app-origin"],
        "cname": ["digitaloceanspaces.com", "ondigitalocean.app"],
    },
    "Heroku": {
        "headers": ["x-heroku-dynos-in-use"],
        "cname": ["herokuapp.com", "herokussl.com"],
    },
    "Netlify": {
        "headers": ["x-nf-request-id"],
        "cname": ["netlify.app", "netlify.com"],
    },
    "Vercel": {
        "headers": ["x-vercel-id"],
        "cname": ["vercel.app", "now.sh"],
    },
    "Cloudflare Pages": {
        "headers": [],
        "cname": ["pages.dev"],
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
