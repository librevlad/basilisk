"""Port scanner plugin — nmap-level async TCP/UDP port scanning."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from typing import Any, ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target
from basilisk.models.types import PortInfo, PortState

logger = logging.getLogger(__name__)

# ================================================================
# Service mapping
# ================================================================

PORT_SERVICES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    69: "tftp", 80: "http", 110: "pop3", 111: "rpcbind",
    123: "ntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm",
    139: "netbios", 143: "imap",
    161: "snmp", 162: "snmptrap", 179: "bgp",
    389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 500: "isakmp", 512: "rexec", 513: "rlogin",
    514: "rsh", 515: "printer", 520: "rip",
    587: "submission", 636: "ldaps", 873: "rsync",
    993: "imaps", 995: "pop3s", 1080: "socks",
    1099: "rmiregistry", 1433: "mssql", 1434: "mssql-m",
    1521: "oracle", 1723: "pptp",
    2049: "nfs", 2181: "zookeeper",
    2375: "docker", 2376: "docker-tls",
    3128: "squid", 3268: "globalcatalog", 3269: "globalcatalog-ssl",
    3306: "mysql", 3389: "rdp",
    4443: "https-alt", 4848: "glassfish",
    5000: "upnp", 5432: "postgresql", 5555: "freeciv",
    5672: "amqp", 5900: "vnc", 5901: "vnc",
    5984: "couchdb", 5985: "winrm", 5986: "winrm-ssl",
    6379: "redis", 6443: "kubernetes-api",
    7001: "weblogic", 7002: "weblogic-ssl",
    8000: "http-alt", 8009: "ajp13", 8080: "http-proxy",
    8081: "http-alt", 8443: "https-alt", 8500: "consul",
    8834: "nessus", 8888: "http-alt",
    9000: "cslistener", 9042: "cassandra",
    9090: "prometheus", 9200: "elasticsearch", 9300: "elasticsearch-node",
    9443: "https-alt", 9999: "abyss",
    10050: "zabbix-agent", 10051: "zabbix-server",
    10443: "https-alt",
    11211: "memcached", 11443: "https-alt",
    15672: "rabbitmq-mgmt",
    27017: "mongodb", 27018: "mongodb-shard",
    50000: "sap", 50070: "hadoop-namenode",
}

# Service categories for grouping
_SERVICE_GROUPS: dict[str, list[str]] = {
    "web": [
        "http", "https", "http-proxy", "http-alt", "https-alt",
        "ajp13", "glassfish", "weblogic", "weblogic-ssl",
    ],
    "mail": ["smtp", "smtps", "submission", "pop3", "pop3s", "imap", "imaps"],
    "database": [
        "mysql", "mssql", "mssql-m", "postgresql", "oracle",
        "mongodb", "mongodb-shard", "redis", "couchdb",
        "elasticsearch", "elasticsearch-node", "memcached",
        "cassandra",
    ],
    "remote_access": [
        "ssh", "telnet", "rdp", "vnc", "winrm", "winrm-ssl",
        "rexec", "rlogin", "rsh",
    ],
    "file_transfer": ["ftp", "tftp", "rsync", "nfs"],
    "directory": ["ldap", "ldaps", "globalcatalog", "globalcatalog-ssl"],
    "infrastructure": [
        "dns", "ntp", "snmp", "snmptrap", "docker", "docker-tls",
        "consul", "prometheus", "zabbix-agent", "zabbix-server",
        "kubernetes-api", "zookeeper", "rabbitmq-mgmt",
        "hadoop-namenode", "nessus",
    ],
}

# Top N port lists
_TOP_100: list[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 179,
    389, 443, 445, 465, 500, 587, 636, 873, 993, 995, 1080,
    1099, 1433, 1521, 1723, 2049, 2181, 2375, 2376, 3128, 3306,
    3389, 4443, 4848, 5000, 5432, 5672, 5900, 5901, 5984, 5985,
    5986, 6379, 6443, 7001, 7002, 8000, 8009, 8080, 8081, 8443,
    8500, 8834, 8888, 9000, 9042, 9090, 9200, 9300, 9443, 9999,
    10050, 10051, 11211, 15672, 27017, 27018, 50000, 50070,
]

_TOP_1000: list[int] = sorted(set(
    _TOP_100
    + list(range(1, 1024))
    + [1433, 1434, 1521, 1723, 2049, 2181, 2375, 2376,
       3128, 3268, 3269, 3306, 3389, 4443, 4848, 5000,
       5432, 5555, 5672, 5900, 5901, 5984, 5985, 5986,
       6379, 6443, 7001, 7002, 8000, 8009, 8080, 8081,
       8443, 8500, 8834, 8888, 9000, 9042, 9090, 9200,
       9300, 9443, 9999, 10050, 10051, 10443, 11211,
       11443, 15672, 27017, 27018, 50000, 50070]
))

# UDP probes for common services
_UDP_PROBES: dict[int, tuple[bytes, str]] = {
    53: (  # DNS query for version.bind
        b"\x00\x1e"  # length
        b"\xab\xcd"  # transaction ID
        b"\x01\x00"  # standard query
        b"\x00\x01"  # 1 question
        b"\x00\x00\x00\x00\x00\x00"  # 0 answers/authority/additional
        b"\x07version\x04bind\x00"  # version.bind
        b"\x00\x10"  # TXT
        b"\x00\x03",  # CH class
        "dns",
    ),
    161: (  # SNMP v1 public community string
        b"\x30\x26\x02\x01\x01\x04\x06public"
        b"\xa0\x19\x02\x04\x00\x00\x00\x01"
        b"\x02\x01\x00\x02\x01\x00\x30\x0b"
        b"\x30\x09\x06\x05\x2b\x06\x01\x02"
        b"\x01\x05\x00",
        "snmp",
    ),
    123: (  # NTP version request
        b"\xe3\x00\x04\xfa"
        b"\x00\x01\x00\x00"
        b"\x00\x01\x00\x00"
        + b"\x00" * 36,
        "ntp",
    ),
    69: (  # TFTP read request
        b"\x00\x01"  # opcode: RRQ
        b"basilisk_test\x00"
        b"netascii\x00",
        "tftp",
    ),
}

# Risky ports
_RISKY_PORTS: dict[int, tuple[str, str, str]] = {
    21: ("FTP port open", "FTP may allow anonymous access or be unencrypted", "medium"),
    23: ("Telnet port open", "Telnet transmits data in cleartext", "high"),
    69: ("TFTP port open", "TFTP has no authentication mechanism", "medium"),
    111: ("RPCbind exposed", "RPCbind may reveal running RPC services", "medium"),
    135: ("MSRPC exposed", "Microsoft RPC port exposed", "medium"),
    161: ("SNMP exposed", "SNMP with default community string is critical", "high"),
    389: ("LDAP exposed", "LDAP may allow anonymous bind", "medium"),
    445: ("SMB port open", "SMB may be vulnerable to EternalBlue-like attacks", "high"),
    512: ("rexec exposed", "Remote execution service with weak auth", "high"),
    513: ("rlogin exposed", "Remote login with .rhosts trust", "high"),
    514: ("rsh exposed", "Remote shell with .rhosts trust", "high"),
    1099: ("Java RMI registry exposed", "RMI may allow remote code execution", "high"),
    1521: ("Oracle DB exposed", "Oracle database port exposed to internet", "medium"),
    2049: ("NFS exposed", "NFS may expose file systems with weak exports", "high"),
    2375: ("Docker API exposed (no TLS)", "Docker API without TLS allows RCE", "critical"),
    3306: ("MySQL port open", "Database port exposed to internet", "medium"),
    3389: ("RDP port open", "Remote Desktop exposed to internet", "medium"),
    5432: ("PostgreSQL port open", "Database port exposed to internet", "medium"),
    5900: ("VNC port open", "VNC may have weak/no authentication", "medium"),
    5984: ("CouchDB exposed", "CouchDB may allow unauthenticated access", "medium"),
    5985: ("WinRM exposed", "Windows Remote Management exposed", "medium"),
    6379: ("Redis port open", "Redis often has no authentication", "high"),
    6443: ("Kubernetes API exposed", "K8s API server may allow unauth access", "high"),
    8500: ("Consul exposed", "HashiCorp Consul may reveal service mesh config", "medium"),
    9200: ("Elasticsearch exposed", "Elasticsearch often has no auth", "high"),
    11211: ("Memcached exposed", "Memcached can be used for DDoS amplification", "high"),
    15672: ("RabbitMQ management exposed", "RabbitMQ web UI with default creds", "medium"),
    27017: ("MongoDB port open", "MongoDB often has no authentication", "high"),
    50070: ("Hadoop NameNode UI exposed", "Hadoop web UI has no auth", "high"),
}


class PortScanPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="port_scan",
        display_name="Port Scanner",
        category=PluginCategory.SCANNING,
        description="Async TCP port scanner with service detection and UDP probes",
        depends_on=[],
        produces=["open_ports"],
        timeout=90.0,
        requires_http=False,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.net is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="Net utils not available"
            )

        host = target.host
        findings: list[Finding] = []
        data: dict[str, Any] = {}

        # ---- Determine port list ----
        # Use TOP_1000 if available and config allows extended scanning
        scan_mode = ctx.state.get("scan_mode", "default")
        ports = _TOP_1000 if scan_mode == "full" else ctx.config.scan.default_ports
        data["scan_ports_count"] = len(ports)

        # ---- 1. Adaptive timing: measure RTT with a known open port ----
        base_timeout = ctx.config.scan.port_timeout
        adapted_timeout = await self._adapt_timeout(host, base_timeout, ctx)
        data["timeout_ms"] = int(adapted_timeout * 1000)

        # ---- 2. TCP port scan with concurrency control ----
        open_ports = await self._scan_tcp(
            host, ports, adapted_timeout, ctx
        )

        # ---- 3. Service mapping ----
        for p in open_ports:
            p.service = PORT_SERVICES.get(p.port, "")

        # ---- 4. Banner grabbing on open ports ----
        if not ctx.should_stop:
            await self._grab_banners(host, open_ports, adapted_timeout, ctx)

        # ---- 5. Service version hints from banners ----
        for p in open_ports:
            if p.banner:
                version = self._extract_version(p.banner)
                if version:
                    p.version = version

        # ---- 6. UDP probes for common services ----
        udp_results: list[PortInfo] = []
        if not ctx.should_stop:
            udp_results = await self._probe_udp(host, adapted_timeout)
            data["udp_open"] = [
                {"port": p.port, "service": p.service, "banner": p.banner}
                for p in udp_results
            ]

        # ---- 7. Port grouping by service type ----
        groups: dict[str, list[int]] = {}
        all_services = open_ports + udp_results
        for p in all_services:
            svc = p.service or PORT_SERVICES.get(p.port, "unknown")
            for group_name, group_services in _SERVICE_GROUPS.items():
                if svc in group_services:
                    groups.setdefault(group_name, []).append(p.port)
                    break
            else:
                groups.setdefault("other", []).append(p.port)
        data["service_groups"] = groups

        # ---- 8. Risky port findings ----
        for p in open_ports:
            if p.port in _RISKY_PORTS:
                title, desc, sev = _RISKY_PORTS[p.port]
                findings.append(getattr(Finding, sev)(
                    title,
                    description=f"{desc} on {host}:{p.port}",
                    evidence=f"Port {p.port}/{p.service or '?'} is OPEN"
                    + (f" — banner: {p.banner[:80]}" if p.banner else ""),
                    remediation="Restrict access via firewall or close the port",
                    tags=["port", p.service or f"port-{p.port}"],
                ))

        # UDP risky ports
        for p in udp_results:
            if p.port in _RISKY_PORTS:
                title, desc, sev = _RISKY_PORTS[p.port]
                findings.append(getattr(Finding, sev)(
                    f"{title} (UDP)",
                    description=f"{desc} on {host}:{p.port}/udp",
                    evidence=f"Port {p.port}/udp ({p.service}) responded to probe",
                    remediation="Restrict UDP access via firewall",
                    tags=["port", "udp", p.service or f"port-{p.port}"],
                ))

        # ---- 9. Version disclosure in banners ----
        for p in open_ports:
            if p.version:
                findings.append(Finding.low(
                    f"Service version disclosed on port {p.port}",
                    description=f"{p.service}: {p.version}",
                    evidence=p.banner[:200] if p.banner else "",
                    remediation="Minimize service banner information",
                    tags=["port", "info-disclosure", p.service or f"port-{p.port}"],
                ))

        # ---- 10. Summary ----
        target.ports = [p.port for p in open_ports]

        tcp_count = len(open_ports)
        udp_count = len(udp_results)
        total = tcp_count + udp_count

        if total > 0:
            tcp_str = ", ".join(
                f"{p.port}/{p.service or '?'}" for p in open_ports
            )
            findings.append(Finding.info(
                f"{tcp_count} TCP + {udp_count} UDP open ports found",
                evidence=tcp_str[:500],
                tags=["port", "summary"],
            ))

            if groups:
                group_str = "; ".join(
                    f"{k}: {', '.join(str(p) for p in sorted(v))}"
                    for k, v in sorted(groups.items())
                )
                findings.append(Finding.info(
                    f"Service groups: {group_str}",
                    tags=["port", "groups"],
                ))

        port_data = [
            {
                "port": p.port,
                "state": p.state.value,
                "service": p.service,
                "banner": p.banner,
                "version": p.version,
                "protocol": "tcp",
            }
            for p in open_ports
        ]

        return PluginResult.success(
            self.meta.name, host,
            findings=findings,
            data={"open_ports": port_data, **data},
        )

    # ================================================================
    # Adaptive timing
    # ================================================================

    async def _adapt_timeout(
        self, host: str, base_timeout: float, ctx: Any,
    ) -> float:
        """Measure RTT to the host and adapt timeout accordingly."""
        try:
            start = time.monotonic()
            # Try a quick check on a common port to estimate RTT
            result = await ctx.net.check_port(host, 443, timeout=base_timeout)
            rtt = time.monotonic() - start
            if result.state == PortState.OPEN:
                adapted = max(0.5, min(base_timeout, rtt * 3.0))
                return adapted
            # Fallback: try port 80
            start = time.monotonic()
            result = await ctx.net.check_port(host, 80, timeout=base_timeout)
            rtt = time.monotonic() - start
            if result.state == PortState.OPEN:
                adapted = max(0.5, min(base_timeout, rtt * 3.0))
                return adapted
        except Exception:
            pass

        return base_timeout

    # ================================================================
    # TCP scanning
    # ================================================================

    async def _scan_tcp(
        self,
        host: str,
        ports: list[int],
        timeout: float,
        ctx: Any,
    ) -> list[PortInfo]:
        """Scan TCP ports using ctx.net.scan_ports with batched early stopping."""
        results: list[PortInfo] = []

        # Batch ports in groups to allow early stopping
        batch_size = 100
        for i in range(0, len(ports), batch_size):
            if ctx.should_stop:
                break
            batch = ports[i : i + batch_size]
            batch_results = await ctx.net.scan_ports(host, batch, timeout)
            results.extend(batch_results)

        return [p for p in results if p.state == PortState.OPEN]

    # ================================================================
    # Banner grabbing
    # ================================================================

    async def _grab_banners(
        self,
        host: str,
        open_ports: list[PortInfo],
        timeout: float,
        ctx: Any,
    ) -> None:
        """Grab banners from open ports using service-specific probes."""
        # Service-specific probes
        probes: dict[int, bytes] = {
            80: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",    # HTTP
            389: b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00",  # LDAP bind
            2375: b"GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n",  # Docker API
            3306: b"",                   # MySQL sends banner on connect
            5432: b"\x00\x00\x00\x08\x04\xd2\x16\x2f",  # PostgreSQL SSLRequest
            5672: b"AMQP\x00\x00\x09\x01",  # AMQP
            6379: b"PING\r\n",          # Redis
            6443: b"GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n",  # Kubernetes
            8080: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",  # HTTP proxy
            9200: b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n", # Elasticsearch
            11211: b"version\r\n",       # Memcached
            27017: b"",                  # MongoDB sends banner on connect
        }

        for p in open_ports:
            if ctx.should_stop:
                break

            probe = probes.get(p.port, b"")
            try:
                async with ctx.rate:
                    if probe:
                        banner = await self._probe_with_data(
                            host, p.port, probe, timeout
                        )
                    else:
                        banner = await ctx.net.grab_banner(
                            host, p.port, timeout=timeout
                        )
                    if banner and isinstance(banner, str):
                        p.banner = banner
            except Exception:
                pass

    async def _probe_with_data(
        self, host: str, port: int, probe: bytes, timeout: float,
    ) -> str:
        """Connect, send probe data, and read response."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
            try:
                # Some services send banner immediately
                try:
                    initial = await asyncio.wait_for(
                        reader.read(1024), timeout=1.0
                    )
                    if initial:
                        return initial.decode("utf-8", errors="replace").strip()
                except TimeoutError:
                    pass

                # Send probe
                if probe:
                    writer.write(probe)
                    await writer.drain()
                    try:
                        data = await asyncio.wait_for(
                            reader.read(1024), timeout=timeout
                        )
                        return data.decode("utf-8", errors="replace").strip()
                    except TimeoutError:
                        pass
            finally:
                writer.close()
                await writer.wait_closed()
        except Exception:
            pass
        return ""

    # ================================================================
    # UDP probing
    # ================================================================

    async def _probe_udp(
        self, host: str, timeout: float,
    ) -> list[PortInfo]:
        """Probe common UDP services (DNS, SNMP, NTP, TFTP)."""
        results: list[PortInfo] = []

        for port, (probe, service) in _UDP_PROBES.items():
            try:
                resp = await self._send_udp(host, port, probe, timeout)
                if resp:
                    results.append(PortInfo(
                        port=port,
                        state=PortState.OPEN,
                        protocol="udp",
                        service=service,
                        banner=resp[:200],
                    ))
            except Exception:
                pass

        return results

    async def _send_udp(
        self, host: str, port: int, data: bytes, timeout: float,
    ) -> str:
        """Send UDP datagram and wait for response."""
        loop = asyncio.get_running_loop()
        transport = None
        response: list[bytes] = []
        event = asyncio.Event()

        class UDPProtocol(asyncio.DatagramProtocol):
            def datagram_received(self, data: bytes, addr: tuple) -> None:
                response.append(data)
                event.set()

            def error_received(self, exc: Exception) -> None:
                event.set()

        try:
            transport, protocol = await asyncio.wait_for(
                loop.create_datagram_endpoint(
                    UDPProtocol, remote_addr=(host, port)
                ),
                timeout=timeout,
            )
            transport.sendto(data)
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(event.wait(), timeout=timeout)

            if response:
                return response[0].decode("utf-8", errors="replace").strip()
        except Exception:
            pass
        finally:
            if transport:
                transport.close()

        return ""

    # ================================================================
    # Version extraction
    # ================================================================

    @staticmethod
    def _extract_version(banner: str) -> str:
        """Extract version string from service banner."""
        import re

        patterns = [
            r"(SSH-[\d.]+\S+)",
            r"(Apache/[\d.]+)",
            r"(nginx/[\d.]+)",
            r"(Microsoft-IIS/[\d.]+)",
            r"(ProFTPD\s+[\d.]+)",
            r"(vsFTPd\s+[\d.]+)",
            r"redis[_ ]?(?:server[_ ]?)?v?=?([\d.]+)",
            r"(PostgreSQL\s+[\d.]+)",
            r"(OpenSSL/[\d.]+\w*)",
            # New patterns
            r"(Exim\s+[\d.]+)",
            r"(Postfix)",
            r"(Sendmail[\s/][\d.]+)",
            r"(Dovecot\s*[\d.]*)",
            r"(Courier[\s/][\d.]+)",
            r"(MySQL\s+[\d.]+)",
            r"(MariaDB[- ][\d.]+)",
            r"(Elasticsearch[\s/][\d.]+)",
            r'"version"\s*:\s*"([\d.]+)"',  # JSON version (ES, Docker)
            r"(mongod?b?\s+v?[\d.]+)",
            r"(Jetty[\s/(][\d.]+)",
            r"(Express[\s/][\d.]+)",
            r"(Tomcat/[\d.]+)",
            r"(LiteSpeed[\s/][\d.]+)",
            r"(Caddy[\s/][\d.]+)",
            r"(Kestrel)",
            r"(Cowboy)",
            r"(Tengine/[\d.]+)",
            r"(lighttpd/[\d.]+)",
            r"(Envoy[\s/][\d.]+)",
            r"(\w+/[\d]+\.[\d]+[\w.]*)",  # Generic: Service/Version
        ]

        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return ""
