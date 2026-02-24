"""Multi-cloud bucket enumeration — AWS S3, Azure Blob, GCS."""

from __future__ import annotations

from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

# Common subdomain names that should NOT be used as standalone bucket name
# candidates — they are almost certainly generic buckets belonging to other
# organisations (e.g. "api", "assets", "mail").  We still generate
# domain-prefixed variants like "insales-api".
GENERIC_SUBDOMAINS: frozenset[str] = frozenset({
    # Infrastructure / web
    "www", "www2", "www3", "web", "app", "apps", "application",
    "api", "api2", "api3", "rest", "graphql", "gateway", "proxy",
    "cdn", "static", "assets", "media", "images", "img", "files",
    "upload", "uploads", "download", "downloads", "content",
    # Mail / communication
    "mail", "mail2", "smtp", "imap", "pop", "pop3", "email", "mx",
    "webmail", "exchange",
    # Auth / identity
    "auth", "login", "sso", "oauth", "id", "identity", "account", "accounts",
    "my", "profile", "signup", "register",
    # Admin / internal
    "admin", "administrator", "panel", "dashboard", "console", "manage",
    "management", "internal", "intranet", "corp", "corporate",
    # Dev / staging
    "dev", "devel", "develop", "development", "stage", "staging", "stg",
    "test", "testing", "qa", "uat", "sandbox", "demo", "preview", "beta",
    "alpha", "canary", "rc", "pre", "preprod",
    # Ops / monitoring
    "monitor", "monitoring", "status", "health", "metrics", "logs",
    "logging", "grafana", "kibana", "prometheus", "nagios", "zabbix",
    # Database / cache / queue
    "db", "database", "sql", "mysql", "postgres", "redis", "cache",
    "memcached", "elastic", "elasticsearch", "mongo", "mongodb", "rabbit",
    "rabbitmq", "kafka", "mq", "queue",
    # CI/CD / tools
    "ci", "cd", "jenkins", "gitlab", "git", "svn", "build", "deploy",
    "releases", "artifacts", "registry", "docker", "k8s", "kube",
    "kubernetes",
    # DNS / network
    "ns", "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2",
    "vpn", "remote", "bastion", "jump", "tunnel", "wss", "ws",
    "ftp", "sftp", "ssh",
    # Documentation / support
    "docs", "doc", "documentation", "help", "support", "wiki", "kb",
    "knowledgebase", "faq", "forum", "community", "blog",
    # Analytics / marketing
    "analytics", "tracking", "pixel", "ads", "ad", "marketing",
    "newsletter", "crm",
    # Hosting / cloud generic
    "cloud", "host", "server", "node", "worker", "lb", "loadbalancer",
    "edge", "origin", "backend", "frontend", "service", "services", "data",
    "backup", "backups", "storage", "store", "shop", "pay", "payment",
    "billing", "checkout", "cart", "catalog", "search", "home",
    # Misc generic single words
    "new", "old", "legacy", "v1", "v2", "v3", "secure", "public", "private",
    "open", "connect", "link", "go", "redirect", "short", "m", "mobile",
    "live", "prod", "production", "main", "primary", "secondary",
})


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

        # Extract base domain for severity context (handle multi-part TLDs)
        parts = target.host.split(".")
        if (
            len(parts) >= 3
            and parts[-2] in self._SECOND_LEVEL_TLDS
            and len(parts[-1]) <= 3
        ):
            domain = parts[-3] if len(parts) >= 3 else parts[0]
        else:
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
                result = await self._check_azure_blob(ctx, name, domain)
                if result:
                    found_buckets.append(result)
                    findings.append(self._make_finding(result, domain))

            # Google Cloud Storage
            if check_gcs and not ctx.should_stop:
                result = await self._check_gcs(ctx, name, domain)
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

    # Common second-level TLDs — domain is the part BEFORE these
    _SECOND_LEVEL_TLDS: frozenset[str] = frozenset({
        "co", "com", "net", "org", "edu", "gov", "mil", "ac", "or", "ne",
        "go", "gob", "nic", "gen", "biz", "web", "info",
    })

    @staticmethod
    def _generate_names(host: str) -> list[str]:
        """Generate bucket name candidates from the domain.

        Avoids using generic subdomain names (e.g. "api", "assets", "mail") as
        standalone bucket names — these almost certainly belong to other
        organisations and produce false positives.  Domain-prefixed variants
        like ``insales-api`` are kept because they are specific to the target.
        """
        parts = host.split(".")
        # Handle multi-part TLDs like .com.ua, .co.uk, .org.br
        # For brain.com.ua: parts = ["brain", "com", "ua"]
        #   parts[-2] = "com" (WRONG) → detect and use parts[-3] = "brain"
        if (
            len(parts) >= 3
            and parts[-2] in CloudBucketEnumPlugin._SECOND_LEVEL_TLDS
            and len(parts[-1]) <= 3
        ):
            domain = parts[-3] if len(parts) >= 3 else parts[0]
            subdomain = parts[0] if len(parts) >= 4 and parts[0] != domain else ""
        else:
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
            # Always add domain-prefixed variants (specific to target)
            names.extend([
                f"{subdomain}-{domain}",
                f"{domain}-{subdomain}",
            ])
            # Only add bare subdomain if it is NOT a generic word
            if subdomain.lower() not in GENERIC_SUBDOMAINS:
                names.append(subdomain)

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
                    # Only report 403 if the bucket name is domain-related
                    is_domain_related = domain and (
                        name == domain
                        or name.startswith(f"{domain}-")
                        or name.endswith(f"-{domain}")
                        or domain in name
                    )
                    if not is_domain_related:
                        return None
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

    async def _check_azure_blob(self, ctx, name: str, domain: str = "") -> dict | None:
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
                    has_domain_ref = (
                        domain and domain.lower() in body.lower()
                    ) if domain else False
                    return {
                        "provider": "azure_blob",
                        "name": name,
                        "url": url,
                        "status": "public_listing",
                        "objects": objects[:10],
                        "domain_verified": has_domain_ref,
                    }
                if resp.status in (403, 409):
                    is_domain_related = domain and (
                        name == domain
                        or name.startswith(f"{domain}-")
                        or name.endswith(f"-{domain}")
                        or domain in name
                    )
                    if not is_domain_related:
                        return None
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

    async def _check_gcs(self, ctx, name: str, domain: str = "") -> dict | None:
        """Check if a Google Cloud Storage bucket is accessible."""
        url = f"https://storage.googleapis.com/{name}/"
        try:
            async with ctx.rate:
                resp = await ctx.http.get(url, timeout=8.0)
                if resp.status == 200:
                    body = await resp.text(encoding="utf-8", errors="replace")
                    has_domain_ref = (
                        domain and domain.lower() in body.lower()
                    ) if domain else False
                    return {
                        "provider": "gcs",
                        "name": name,
                        "url": url,
                        "status": "public_listing",
                        "objects": body[:500].splitlines()[:10],
                        "domain_verified": has_domain_ref,
                    }
                if resp.status == 403:
                    # 403 means the bucket exists but we cannot list it.
                    # Only report if the name is clearly related to the target
                    # (contains the domain).  Generic names that return 403 are
                    # overwhelmingly false positives — millions of buckets
                    # exist with common words.
                    is_domain_related = domain and (
                        name == domain
                        or name.startswith(f"{domain}-")
                        or name.endswith(f"-{domain}")
                        or domain in name
                    )
                    if not is_domain_related:
                        return None
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
        - public_listing (200) + domain name match → MEDIUM
        - public_listing (200) + unverified → LOW (may not be target's)
        - exists_no_listing (403) + name matches domain → INFO
        """
        provider = bucket["provider"]
        name = bucket["name"]
        status = bucket["status"]
        objects = bucket.get("objects", [])
        domain_verified = bucket.get("domain_verified", False)
        is_domain_match = domain and (
            name == domain
            or name.startswith(f"{domain}-")
            or name.endswith(f"-{domain}")
        )

        if status == "public_listing":
            if domain_verified:
                return Finding.high(
                    f"Public {provider} bucket: {name}",
                    description=(
                        f"Bucket {name} allows public listing "
                        f"({len(objects)} objects sampled). "
                        f"Content references target domain '{domain}'."
                    ),
                    evidence=f"URL: {bucket['url']}",
                    remediation=(
                        "Disable public access. Set bucket policy to deny "
                        "anonymous listing."
                    ),
                    tags=["recon", "cloud", "bucket", provider],
                )
            if is_domain_match:
                return Finding.medium(
                    f"Public {provider} bucket (likely target): {name}",
                    description=(
                        f"Bucket {name} allows public listing "
                        f"({len(objects)} objects sampled). "
                        f"Name matches target domain but content ownership "
                        f"not verified."
                    ),
                    evidence=f"URL: {bucket['url']}",
                    remediation=(
                        "Verify bucket ownership and disable public access"
                    ),
                    tags=["recon", "cloud", "bucket", provider],
                )
            return Finding.low(
                f"Public {provider} bucket (unverified ownership): {name}",
                description=(
                    f"Bucket {name} allows public listing but ownership "
                    f"not confirmed for target domain. "
                    f"May belong to another organization."
                ),
                evidence=f"URL: {bucket['url']}",
                remediation="Verify bucket ownership before taking action",
                tags=["recon", "cloud", "bucket", provider],
                false_positive_risk="high",
            )
        # exists_no_listing (403): already filtered to domain-related names
        # in the _check_* methods, so we know the name is relevant.
        return Finding.info(
            f"{provider} bucket exists (no listing): {name}",
            description=(
                f"Bucket {name} exists but listing is denied. "
                f"May be owned by target based on naming."
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
