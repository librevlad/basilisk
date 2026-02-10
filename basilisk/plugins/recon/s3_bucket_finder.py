"""S3 bucket enumeration — discovers misconfigured cloud storage."""

from __future__ import annotations

from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class S3BucketFinderPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="s3_bucket_finder",
        display_name="S3 Bucket Finder",
        category=PluginCategory.RECON,
        description="Discovers misconfigured S3 buckets related to the target",
        produces=["s3_buckets"],
        timeout=30.0,
    )

    def _generate_bucket_names(self, host: str) -> list[str]:
        """Generate potential S3 bucket names from hostname."""
        name = host.split(".")[0]
        domain = host.replace(".", "-")
        domain_nodot = host.replace(".", "")

        prefixes = [name, domain, domain_nodot, host]
        suffixes = [
            "", "-backup", "-backups", "-assets", "-static", "-media",
            "-uploads", "-files", "-data", "-dev", "-staging", "-prod",
            "-logs", "-cdn", "-public", "-private", "-internal",
        ]

        buckets: list[str] = []
        for prefix in prefixes:
            for suffix in suffixes:
                buckets.append(f"{prefix}{suffix}")

        return list(dict.fromkeys(buckets))

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        bucket_names = self._generate_bucket_names(target.host)
        findings: list[Finding] = []
        found_buckets: list[dict] = []

        for bucket in bucket_names:
            url = f"https://{bucket}.s3.amazonaws.com/"
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(url, timeout=5.0)
                    status = resp.status
                    body = await resp.text(encoding="utf-8", errors="replace")

                    if status == 200 and "ListBucketResult" in body:
                        found_buckets.append({
                            "name": bucket, "url": url, "access": "public-list",
                        })
                        findings.append(Finding.critical(
                            f"Public S3 bucket: {bucket}",
                            description="S3 bucket allows public listing of contents",
                            evidence=url,
                            remediation="Restrict S3 bucket access policy",
                            tags=["recon", "s3", "cloud"],
                        ))
                    elif status == 200:
                        found_buckets.append({
                            "name": bucket, "url": url, "access": "public-read",
                        })
                        findings.append(Finding.high(
                            f"Accessible S3 bucket: {bucket}",
                            evidence=url,
                            remediation="Review S3 bucket access policy",
                            tags=["recon", "s3", "cloud"],
                        ))
                    elif status == 403:
                        found_buckets.append({
                            "name": bucket, "url": url, "access": "exists-denied",
                        })
            except Exception:
                continue

        if not findings:
            findings.append(Finding.info(
                f"No public S3 buckets found ({len(bucket_names)} checked)",
                tags=["recon", "s3"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "buckets": found_buckets,
                "checked": len(bucket_names),
            },
        )
