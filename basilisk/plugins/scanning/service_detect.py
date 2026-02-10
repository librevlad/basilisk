"""Service detection plugin — identifies services by banner grabbing."""

from __future__ import annotations

from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class ServiceDetectPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="service_detect",
        display_name="Service Detection",
        category=PluginCategory.SCANNING,
        description="Identifies services by grabbing banners on open ports",
        depends_on=["port_scan"],
        produces=["services"],
        timeout=30.0,
    )

    COMMON_PORTS = {
        21: "ftp", 22: "ssh", 25: "smtp", 53: "dns",
        69: "tftp", 80: "http", 110: "pop3", 139: "netbios",
        143: "imap", 161: "snmp", 389: "ldap", 443: "https",
        445: "smb", 465: "smtps", 587: "submission", 636: "ldaps",
        873: "rsync", 993: "imaps", 995: "pop3s", 1080: "socks",
        1433: "mssql", 1521: "oracle", 2375: "docker", 3128: "squid",
        3306: "mysql", 3389: "rdp", 5432: "postgresql",
        5900: "vnc", 5984: "couchdb", 6379: "redis",
        8080: "http-proxy", 8443: "https-alt", 8500: "consul",
        8888: "http-alt", 9090: "prometheus", 9200: "elasticsearch",
        11211: "memcached", 27017: "mongodb",
    }

    # Probes for services that don't send an auto-banner
    SERVICE_PROBES: dict[int, tuple[bytes, str]] = {
        6379: (b"PING\r\n", "redis"),
        11211: (b"version\r\n", "memcached"),
    }

    def accepts(self, target: Target) -> bool:
        return bool(target.ports)

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.net is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="Net utils not available"
            )

        services: list[dict] = []
        findings: list[Finding] = []

        for port in target.ports:
            service_name = self.COMMON_PORTS.get(port, "unknown")
            banner = ""

            try:
                async with ctx.rate:
                    banner = await ctx.net.grab_banner(target.host, port, timeout=5.0)
            except Exception:
                pass

            service_info = {
                "port": port,
                "service": service_name,
                "banner": banner,
            }

            if banner:
                service_info["service"] = self._identify_service(banner, port)

            services.append(service_info)

            # Check for version disclosure
            if banner and any(
                kw in banner.lower()
                for kw in ("version", "server:", "openssh", "apache", "nginx")
            ):
                findings.append(Finding.low(
                    f"Service banner on port {port}",
                    description=f"Service reveals version info: {service_info['service']}",
                    evidence=banner[:200],
                    remediation="Minimize service banner information",
                    tags=["scanning", "info-disclosure"],
                ))

        findings.append(Finding.info(
            f"Services detected on {len(services)} ports",
            evidence=", ".join(
                f"{s['port']}/{s['service']}" for s in services
            ),
            tags=["scanning", "services"],
        ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"services": services},
        )

    @staticmethod
    def _identify_service(banner: str, port: int) -> str:
        """Identify service from banner content."""
        banner_lower = banner.lower()
        signatures = [
            ("ssh", "ssh"), ("ftp", "ftp"), ("smtp", "smtp"),
            ("mysql", "mysql"), ("postgresql", "postgresql"),
            ("redis", "redis"), ("mongodb", "mongodb"),
            ("apache", "apache"), ("nginx", "nginx"), ("iis", "iis"),
            ("http", "http"), ("openssl", "openssl"),
            ("vsftpd", "vsftpd"), ("proftpd", "proftpd"),
            ("pure-ftpd", "pure-ftpd"), ("exim", "exim"),
            ("postfix", "postfix"), ("dovecot", "dovecot"),
            ("memcached", "memcached"), ("elasticsearch", "elasticsearch"),
            ("couchdb", "couchdb"), ("consul", "consul"),
            ("docker", "docker"), ("rabbitmq", "rabbitmq"),
            ("rfb", "vnc"), ("samba", "samba"),
            ("lighttpd", "lighttpd"), ("tomcat", "tomcat"),
            ("jetty", "jetty"), ("caddy", "caddy"),
        ]
        for keyword, service in signatures:
            if keyword in banner_lower:
                return service
        return ServiceDetectPlugin.COMMON_PORTS.get(port, "unknown")
