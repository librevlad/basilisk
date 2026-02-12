"""Multi-cloud bucket enumeration — AWS S3, Azure Blob, GCS."""

from __future__ import annotations

from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class CloudBucketEnumPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="cloud_bucket_enum",
        display_name="Multi-Cloud Bucket Scanner",
        category=PluginCategory.RECON,
        description="Enumerates AWS S3, Azure Blob, and GCS buckets for a domain",
        depends_on=["cloud_detect"],
        produces=["cloud_buckets"],
        timeout=45.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        findings: list[Finding] = []
        found_buckets: list[dict] = []

        # Generate bucket name candidates from domain
        names = self._generate_names(target.host)

        # Get cloud provider hints
        cloud_key = f"cloud_detect:{target.host}"
        cloud_result = ctx.pipeline.get(cloud_key)
        providers: list[str] = []
        if cloud_result and cloud_result.ok:
            providers = [
                p.lower() for p in cloud_result.data.get("providers", [])
            ]

        # Check all three providers (or prioritize based on detection)
        check_aws = not providers or any("aws" in p or "amazon" in p for p in providers)
        check_azure = not providers or any("azure" in p or "microsoft" in p for p in providers)
        check_gcs = not providers or any("gcp" in p or "google" in p for p in providers)

        # Extract base domain for severity context
        parts = target.host.split(".")
        domain = parts[-2] if len(parts) >= 2 else parts[0]

        for name in names:
            if ctx.should_stop:
                break

            # AWS S3
            if check_aws:
                result = await self._check_s3(ctx, name, domain)
                if result:
                    found_buckets.append(result)
                    findings.append(self._make_finding(result, domain))

            # Azure Blob
            if check_azure and not ctx.should_stop:
                result = await self._check_azure_blob(ctx, name)
                if result:
                    found_buckets.append(result)
                    findings.append(self._make_finding(result, domain))

            # Google Cloud Storage
            if check_gcs and not ctx.should_stop:
                result = await self._check_gcs(ctx, name)
                if result:
                    found_buckets.append(result)
                    findings.append(self._make_finding(result, domain))

        if not findings:
            findings.append(Finding.info(
                f"No accessible cloud buckets found ({len(names)} names checked)",
                tags=["recon", "cloud", "bucket"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "cloud_buckets": found_buckets,
                "names_checked": len(names),
            },
        )

    @staticmethod
    def _generate_names(host: str) -> list[str]:
        """Generate bucket name candidates from the domain."""
        parts = host.split(".")
        domain = parts[-2] if len(parts) >= 2 else parts[0]
        subdomain = parts[0] if len(parts) >= 3 else ""

        names = [
            domain,
            host.replace(".", "-"),
            f"{domain}-backup",
            f"{domain}-backups",
            f"{domain}-data",
            f"{domain}-assets",
            f"{domain}-uploads",
            f"{domain}-static",
            f"{domain}-media",
            f"{domain}-public",
            f"{domain}-private",
            f"{domain}-dev",
            f"{domain}-staging",
            f"{domain}-prod",
            f"{domain}-logs",
            f"{domain}-cdn",
        ]

        if subdomain and subdomain != domain:
            names.extend([
                subdomain,
                f"{subdomain}-{domain}",
                f"{domain}-{subdomain}",
            ])

        return list(dict.fromkeys(names))

    async def _check_s3(self, ctx, name: str, domain: str = "") -> dict | None:
        """Check if an S3 bucket exists and is accessible."""
        # Skip very short generic names (high false positive rate)
        if len(name) < 5:
            return None
        url = f"https://{name}.s3.amazonaws.com/"
        try:
            async with ctx.rate:
                resp = await ctx.http.get(url, timeout=8.0)
                if resp.status == 200:
                    body = await resp.text(encoding="utf-8", errors="replace")
                    objects = self._parse_s3_listing(body)
                    # Verify ownership: check if ListBucketResult contains domain
                    has_domain_ref = (
                        domain and domain.lower() in body.lower()
                    ) if domain else False
                    return {
                        "provider": "aws_s3",
                        "name": name,
                        "url": url,
                        "status": "public_listing",
                        "objects": objects[:10],
                        "domain_verified": has_domain_ref,
                    }
                if resp.status == 403:
                    return {
                        "provider": "aws_s3",
                        "name": name,
                        "url": url,
                        "status": "exists_no_listing",
                        "objects": [],
                    }
        except Exception:
            pass
        return None

    async def _check_azure_blob(self, ctx, name: str) -> dict | None:
        """Check if an Azure Blob container is accessible."""
        url = (
            f"https://{name}.blob.core.windows.net/"
            f"?comp=list&restype=container"
        )
        try:
            async with ctx.rate:
                resp = await ctx.http.get(url, timeout=8.0)
                if resp.status == 200:
                    body = await resp.text(encoding="utf-8", errors="replace")
                    objects = self._parse_azure_listing(body)
                    return {
                        "provider": "azure_blob",
                        "name": name,
                        "url": url,
                        "status": "public_listing",
                        "objects": objects[:10],
                    }
                if resp.status in (403, 409):
                    return {
                        "provider": "azure_blob",
                        "name": name,
                        "url": f"https://{name}.blob.core.windows.net/",
                        "status": "exists_no_listing",
                        "objects": [],
                    }
        except Exception:
            pass
        return None

    async def _check_gcs(self, ctx, name: str) -> dict | None:
        """Check if a Google Cloud Storage bucket is accessible."""
        url = f"https://storage.googleapis.com/{name}/"
        try:
            async with ctx.rate:
                resp = await ctx.http.get(url, timeout=8.0)
                if resp.status == 200:
                    body = await resp.text(encoding="utf-8", errors="replace")
                    return {
                        "provider": "gcs",
                        "name": name,
                        "url": url,
                        "status": "public_listing",
                        "objects": body[:500].splitlines()[:10],
                    }
                if resp.status == 403:
                    return {
                        "provider": "gcs",
                        "name": name,
                        "url": url,
                        "status": "exists_no_listing",
                        "objects": [],
                    }
        except Exception:
            pass
        return None

    @staticmethod
    def _make_finding(bucket: dict, domain: str = "") -> Finding:
        """Create a finding from a discovered bucket.

        Severity logic:
        - public_listing (200) + domain verified → HIGH
        - public_listing (200) + unverified → MEDIUM (may not be target's)
        - exists_no_listing (403) + name matches domain → LOW
        - exists_no_listing (403) + generic name → INFO (likely false positive)
        """
        provider = bucket["provider"]
        name = bucket["name"]
        status = bucket["status"]
        objects = bucket.get("objects", [])
        domain_verified = bucket.get("domain_verified", False)
        is_domain_match = domain and (
            name == domain or name.startswith(f"{domain}-")
        )

        if status == "public_listing":
            if domain_verified or is_domain_match:
                return Finding.high(
                    f"Public {provider} bucket: {name}",
                    description=(
                        f"Bucket {name} allows public listing "
                        f"({len(objects)} objects sampled)"
                    ),
                    evidence=f"URL: {bucket['url']}",
                    remediation=(
                        "Disable public access. Set bucket policy to deny "
                        "anonymous listing."
                    ),
                    tags=["recon", "cloud", "bucket", provider],
                )
            return Finding.medium(
                f"Public {provider} bucket (unverified ownership): {name}",
                description=(
                    f"Bucket {name} allows public listing but ownership "
                    f"not confirmed for target domain"
                ),
                evidence=f"URL: {bucket['url']}",
                remediation="Verify bucket ownership and disable public access",
                tags=["recon", "cloud", "bucket", provider],
                false_positive_risk="medium",
            )
        # exists_no_listing (403): contextual severity based on domain match
        if is_domain_match:
            return Finding.low(
                f"{provider} bucket exists: {name}",
                description=(
                    f"Bucket {name} exists but listing is denied "
                    "(likely owned by target)"
                ),
                evidence=f"URL: {bucket['url']}",
                remediation="Verify bucket access controls",
                tags=["recon", "cloud", "bucket", provider],
            )
        return Finding.info(
            f"{provider} bucket exists (unverified): {name}",
            description=(
                f"Bucket {name} exists but listing is denied "
                "(may belong to another organization)"
            ),
            evidence=f"URL: {bucket['url']}",
            tags=["recon", "cloud", "bucket", provider],
        )

    @staticmethod
    def _parse_s3_listing(body: str) -> list[str]:
        """Parse S3 XML listing for object keys."""
        import re
        return re.findall(r'<Key>([^<]+)</Key>', body)[:10]

    @staticmethod
    def _parse_azure_listing(body: str) -> list[str]:
        """Parse Azure Blob XML listing for blob names."""
        import re
        return re.findall(r'<Name>([^<]+)</Name>', body)[:10]
