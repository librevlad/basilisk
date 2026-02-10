"""Port scanner plugin — async TCP port scanning."""

from __future__ import annotations

from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target
from basilisk.models.types import PortState

# Well-known services for common ports
PORT_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    69: "tftp", 80: "http", 110: "pop3", 139: "netbios", 143: "imap",
    161: "snmp", 162: "snmptrap", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 587: "submission", 636: "ldaps", 873: "rsync",
    993: "imaps", 995: "pop3s", 1080: "socks", 1433: "mssql",
    1521: "oracle", 2375: "docker", 2376: "docker-tls", 3128: "squid",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    5901: "vnc", 5984: "couchdb", 6379: "redis", 8000: "http-alt",
    8080: "http-proxy", 8443: "https-alt", 8500: "consul",
    8888: "http-alt", 9090: "prometheus", 9200: "elasticsearch",
    9443: "https-alt", 10050: "zabbix-agent", 10051: "zabbix-server",
    11211: "memcached", 27017: "mongodb",
}


class PortScanPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="port_scan",
        display_name="Port Scanner",
        category=PluginCategory.SCANNING,
        description="Async TCP port scanner",
        depends_on=["dns_enum"],
        produces=["open_ports"],
        timeout=60.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.net is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="Net utils not available"
            )

        ports = ctx.config.scan.default_ports
        results = await ctx.net.scan_ports(target.host, ports)

        open_ports = [p for p in results if p.state == PortState.OPEN]
        target.ports = [p.port for p in open_ports]

        findings: list[Finding] = []

        # Assign service names
        for port_info in open_ports:
            port_info.service = PORT_SERVICES.get(port_info.port, "")

        # Flag risky open ports
        risky_ports = {
            21: ("FTP port open", "FTP may allow anonymous access or be unencrypted"),
            23: ("Telnet port open", "Telnet transmits data in cleartext"),
            161: ("SNMP exposed", "SNMP with default community string is critical"),
            389: ("LDAP exposed", "LDAP may allow anonymous bind"),
            445: ("SMB port open", "SMB may be vulnerable to EternalBlue-like attacks"),
            1521: ("Oracle DB exposed", "Oracle database port exposed to internet"),
            2375: ("Docker API exposed", "Docker API without TLS allows RCE"),
            3306: ("MySQL port open", "Database port exposed to internet"),
            3389: ("RDP port open", "Remote Desktop exposed to internet"),
            5432: ("PostgreSQL port open", "Database port exposed to internet"),
            5900: ("VNC port open", "VNC may have weak/no authentication"),
            5984: ("CouchDB exposed", "CouchDB may allow unauthenticated access"),
            6379: ("Redis port open", "Redis often has no authentication"),
            8500: ("Consul exposed", "HashiCorp Consul may reveal service mesh config"),
            9200: ("Elasticsearch exposed", "Elasticsearch often has no auth"),
            11211: ("Memcached exposed", "Memcached can be used for DDoS amplification"),
            27017: ("MongoDB port open", "MongoDB often has no authentication"),
        }

        for port_info in open_ports:
            if port_info.port in risky_ports:
                title, desc = risky_ports[port_info.port]
                findings.append(Finding.medium(
                    title,
                    description=f"{desc} on {target.host}:{port_info.port}",
                    evidence=f"Port {port_info.port} ({port_info.service}) is OPEN",
                    remediation="Restrict access via firewall or close the port",
                    tags=["port", port_info.service or f"port-{port_info.port}"],
                ))

        if open_ports:
            findings.append(Finding.info(
                f"{len(open_ports)} open ports found",
                evidence=", ".join(
                    f"{p.port}/{p.service or '?'}" for p in open_ports
                ),
                tags=["port"],
            ))

        port_data = [
            {"port": p.port, "state": p.state.value, "service": p.service}
            for p in results
            if p.state == PortState.OPEN
        ]

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"open_ports": port_data},
        )
