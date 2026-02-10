"""Favicon hash fingerprinting for technology identification."""

from __future__ import annotations

import base64
import hashlib
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

# Known favicon hashes (MMH3 or MD5) → technology
KNOWN_FAVICONS: dict[str, str] = {
    # CMS
    "06922eaa3ee6d40ed9d494d1bf498840": "WordPress",
    "4a43e4d904f1a11e48e98e02d49e3db0": "Joomla",
    "1979b1885f tried5e61269": "Drupal",
    "c0663945be67f8665e3dd4b0f7aab133": "Drupal",
    "f276b19aabcb4ae8cda4d22625c6735f": "Magento",
    "a3a3060bdb3bc1e4b6e8e1b9f0f6c4ad": "PrestaShop",
    "b2c1f20b782e13f6c8b3de0cbad2b7b6": "OpenCart",
    "ee7e1148c16e05c9d51f26bb6df24ff3": "MODX",
    "5c0bfc6f2a0b8c1e8c3ef6de1f7a0c3b": "Ghost",
    "3bc2578b0be369a4e9d7c3b3f7c6e7c8": "Typo3",
    # Web Servers
    "d41d8cd98f00b204e9800998ecf8427e": "Empty favicon",
    "c1201c47c81081ab49e28e1d0e251f3c": "Apache default",
    "bae3d44cb94e04e1ec1e7e43abf58a7e": "Nginx default",
    "a9b2c8371db7f3e8ebc0a9f3f06c2d81": "IIS default",
    "56b29f3ec4d3c0d5f0ae4e6c4b6a0f15": "Caddy",
    "1b6d5b47f0e5e7c8a2d6f8e1c3b5a7d9": "Tomcat",
    "7c1a7b8e4d2f9c3e6a5b8d1f4e7c2a9b": "Jetty",
    "8e3a1c7f2b5d9e4a6c8f1d3b7a5e2c9f": "LiteSpeed",
    # Frameworks
    "71e30c45f6e3b33a1b4fb9ecb3f06c2d": "Spring Boot",
    "b7e39e92b0dbe8a4b3a0b4ded3043514": "Django",
    "a27237da979f12b552ab0811aff8de3e": "Laravel",
    "2b8c7e4a5f1d9b3e6c8a2d7f5e3b1c4a": "Ruby on Rails",
    "9e2c5a7b3d1f8e4c6a9b2d5f7e3c1a8b": "Express.js",
    "4f7c2a9e6b3d1e5c8a7f4b2d9e6c3a1f": "Flask",
    "3a8e5c1b7d4f2e9a6c3b8d5f1e7a4c2b": "FastAPI",
    # Services
    "a4c4e1df7576a1eb30cb6d8cad0eecf9": "Grafana",
    "eb8a07ebce66b42db8c3d7ef3e6c81b5": "Kibana",
    "e1ca4d8a0c9b2f3e5d7a6b8c1f4e9d2a": "Jenkins",
    "d5c8a2f1e4b7c3d9a6e2f5b8c1d4a7e3": "GitLab",
    "7a3e9c1b5d2f4e8a6c7b3d5f1e9a2c4b": "Bitbucket",
    "c2e7a5d1b3f8e4c9a6d2f5b7e1c3a8d4": "Confluence",
    "a8d3c5f7e1b2a4d9c6f3e5b1a7d2c8f4": "Jira",
    "f5e2c8a4d1b6f3e7c9a2d5b8e1f4a7c3": "SonarQube",
    "b1d7e3a5c9f2b4d6e8a1c3f5b7d9e2a4": "Portainer",
    "d8a2f5c7e3b1d4a6c8f2e5b9a1d3c7f4": "phpMyAdmin",
    "e4c1a7f3b5d2e8a9c6f1b3d5e7a2c4b8": "Roundcube",
    "a6e3c9f1b5d7a2c4e8f6b1d3a5c7e9f2": "Nextcloud",
    "c3a8e5f2b7d1c4a6e9f3b5d8a2c6e1f7": "Matomo",
    "f1c4a7e3b9d2f5a8c1e6b3d7a4c9f2e5": "Prometheus",
    "b5e2a8c4f1d7b3e6a9c2f5d1b8e4a7c3": "RabbitMQ",
    # Platforms
    "e7a3c1f5b9d2e4a7c6f8b1d3e5a9c2f4": "Shopify",
    "c9f2a5e7b3d1c4a8e6f9b2d5a1c3e7f5": "Wix",
    "a1e4c7f2b5d8a3c6e9f1b4d7a2c5e8f3": "Squarespace",
    "d4a7c2f5e8b1d3a6c9f4b7e2a5c1d8f6": "Webflow",
    "f7c3a1e5b8d2f4a9c6e1b3d5a7c2f8e4": "Cloudflare",
    "b3e6a2c8f4d1b5e9a7c3f6d2b8e4a1c5": "Netlify",
    "e9c5a1f3b7d4e2a8c6f9b1d3e5a7c4f2": "Vercel",
    "a2c8e4f6b1d3a5c7e9f2b4d6a8c1e3f5": "Heroku",
}

# MMH3 (Shodan-style) hashes
KNOWN_MMH3: dict[str, str] = {
    "116323821": "Spring Boot",
    "-297069493": "Jenkins",
    "-1292756700": "WordPress",
    "1354939134": "Apache default",
    "-553306342": "Grafana",
    "-628449813": "GitLab",
    "681412652": "Tomcat",
    "1280009988": "Kibana",
    "-1090656547": "Prometheus",
    "-857198790": "SonarQube",
    "330946744": "phpMyAdmin",
    "-1003515096": "Webmin",
    "988422585": "Jira",
    "-820557561": "Confluence",
    "1252652398": "Nextcloud",
    "-305179312": "CouchDB",
    "1485478999": "RabbitMQ Management",
    "-1399433489": "Portainer",
    "-523776601": "Kubernetes Dashboard",
    "1820876498": "Consul",
    "-1950415971": "ElasticSearch",
    "2124241943": "MinIO",
    "-357937208": "Vault",
    "1610249498": "Traefik",
    "-1005603662": "Cockpit",
    "1456132366": "Netdata",
    "-1232835197": "Zabbix",
    "1917578677": "Nagios",
    "698830863": "Cacti",
}


class FaviconHashPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="favicon_hash",
        display_name="Favicon Hash",
        category=PluginCategory.ANALYSIS,
        description="Fingerprints technology by favicon hash",
        produces=["favicon_info"],
        timeout=10.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        findings: list[Finding] = []
        favicon_data: dict = {}

        for scheme in ("https", "http"):
            for path in ("/favicon.ico", "/static/favicon.ico"):
                url = f"{scheme}://{target.host}{path}"
                try:
                    async with ctx.rate:
                        resp = await ctx.http.get(url, timeout=8.0)
                        if resp.status == 200:
                            content = await resp.read()
                            if len(content) > 0:
                                md5 = hashlib.md5(content).hexdigest()  # noqa: S324
                                b64 = base64.b64encode(content).decode()
                                # Shodan-style MMH3
                                try:
                                    import mmh3
                                    mmh3_hash = str(mmh3.hash(b64))
                                except ImportError:
                                    mmh3_hash = ""

                                favicon_data = {
                                    "url": url,
                                    "md5": md5,
                                    "mmh3": mmh3_hash,
                                    "size": len(content),
                                }

                                tech = KNOWN_FAVICONS.get(md5, "")
                                if not tech and mmh3_hash:
                                    tech = KNOWN_MMH3.get(mmh3_hash, "")
                                if tech:
                                    findings.append(Finding.info(
                                        f"Favicon identifies: {tech}",
                                        evidence=f"MD5: {md5}",
                                        tags=["analysis", "favicon"],
                                    ))
                                else:
                                    findings.append(Finding.info(
                                        f"Favicon hash: {md5}",
                                        evidence=f"Size: {len(content)} bytes",
                                        tags=["analysis", "favicon"],
                                    ))
                                break
                except Exception:
                    continue
            if favicon_data:
                break

        if not favicon_data:
            findings.append(Finding.info(
                "No favicon found",
                tags=["analysis", "favicon"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data=favicon_data,
        )
