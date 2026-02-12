"""Service detection plugin — multi-protocol probes with version extraction."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import ssl
from typing import Any, ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)

# ================================================================
# Service probe definitions
# ================================================================

# Probes: (data_to_send, read_first, description)
# read_first=True means read banner before sending probe
_PROBES: dict[str, tuple[bytes, bool, str]] = {
    # FTP
    "ftp": (b"", True, "FTP banner"),
    "ftp_anon": (b"USER anonymous\r\n", False, "FTP anonymous login"),
    # SSH
    "ssh": (b"", True, "SSH banner"),
    # SMTP
    "smtp": (b"", True, "SMTP banner"),
    "smtp_ehlo": (b"EHLO basilisk.local\r\n", False, "SMTP EHLO"),
    # IMAP
    "imap": (b"", True, "IMAP banner"),
    # POP3
    "pop3": (b"", True, "POP3 banner"),
    # HTTP
    "http_get": (b"GET / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n", False, "HTTP"),
    # MySQL
    "mysql": (b"", True, "MySQL handshake"),
    # PostgreSQL — SSLRequest then startup
    "postgresql_ssl": (
        b"\x00\x00\x00\x08\x04\xd2\x16\x2f",  # SSLRequest
        False,
        "PostgreSQL SSL probe",
    ),
    "postgresql": (
        # StartupMessage: version 3.0, user=basilisk
        b"\x00\x00\x00\x27"
        b"\x00\x03\x00\x00"
        b"user\x00basilisk\x00"
        b"database\x00postgres\x00\x00",
        False,
        "PostgreSQL startup",
    ),
    # Redis
    "redis": (b"PING\r\n", False, "Redis PING"),
    "redis_info": (b"INFO server\r\n", False, "Redis INFO"),
    # MongoDB
    "mongodb": (
        # MongoDB isMaster command (OP_QUERY)
        b"\x3f\x00\x00\x00"  # messageLength
        b"\x00\x00\x00\x00"  # requestID
        b"\x00\x00\x00\x00"  # responseTo
        b"\xd4\x07\x00\x00"  # opCode: OP_QUERY
        b"\x00\x00\x00\x00"  # flags
        b"admin.$cmd\x00"     # collection
        b"\x00\x00\x00\x00"  # numberToSkip
        b"\x01\x00\x00\x00"  # numberToReturn
        # BSON document: {isMaster: 1}
        b"\x15\x00\x00\x00"
        b"\x01isMaster\x00"
        b"\x00\x00\x00\x00\x00\x00\xf0\x3f"
        b"\x00",
        False,
        "MongoDB isMaster",
    ),
    # Memcached
    "memcached": (b"version\r\n", False, "Memcached version"),
    # Elasticsearch
    "elasticsearch": (
        b"GET / HTTP/1.1\r\nHost: target\r\nAccept: application/json\r\n\r\n",
        False,
        "Elasticsearch HTTP API",
    ),
    # RabbitMQ AMQP
    "amqp": (b"AMQP\x00\x00\x09\x01", False, "AMQP protocol header"),
}

# Port-to-probe mapping
_PORT_PROBES: dict[int, list[str]] = {
    21: ["ftp", "ftp_anon"],
    22: ["ssh"],
    25: ["smtp", "smtp_ehlo"],
    110: ["pop3"],
    143: ["imap"],
    587: ["smtp", "smtp_ehlo"],
    993: ["imap"],
    995: ["pop3"],
    3306: ["mysql"],
    5432: ["postgresql_ssl", "postgresql"],
    6379: ["redis", "redis_info"],
    27017: ["mongodb"],
    11211: ["memcached"],
    9200: ["elasticsearch"],
    5672: ["amqp"],
    15672: ["elasticsearch"],  # RabbitMQ management uses HTTP
}

# STARTTLS-capable protocols and their commands
_STARTTLS_COMMANDS: dict[str, tuple[int, bytes, bytes]] = {
    "smtp": (25, b"EHLO basilisk.local\r\n", b"STARTTLS\r\n"),
    "smtp_submission": (587, b"EHLO basilisk.local\r\n", b"STARTTLS\r\n"),
    "imap": (143, b"", b"a001 STARTTLS\r\n"),
    "pop3": (110, b"", b"STLS\r\n"),
}

# Known default credentials to flag
_DEFAULT_CREDS: dict[str, list[tuple[str, str]]] = {
    "redis": [("", "")],  # No auth by default
    "mongodb": [("", "")],  # No auth by default
    "elasticsearch": [("", "")],  # No auth by default
    "memcached": [("", "")],  # No auth by default
    "mysql": [("root", ""), ("root", "root")],
    "postgresql": [("postgres", "postgres")],
    "ftp": [("anonymous", ""), ("anonymous", "anonymous@")],
    "rabbitmq-mgmt": [("guest", "guest")],
    "consul": [("", "")],  # No auth by default
}

# Pattern matching for service identification
_SERVICE_PATTERNS: list[tuple[re.Pattern, str, str | None]] = [
    # (pattern, service_name, version_group)
    (re.compile(r"SSH-([\d.]+)-OpenSSH_([\w.]+)", re.I), "openssh", None),
    (re.compile(r"SSH-([\d.]+)-(\S+)", re.I), "ssh", None),
    (re.compile(r"220[- ].*ProFTPD\s+([\d.]+)", re.I), "proftpd", None),
    (re.compile(r"220[- ].*vsFTPd\s+([\d.]+)", re.I), "vsftpd", None),
    (re.compile(r"220[- ].*Pure-FTPd", re.I), "pure-ftpd", None),
    (re.compile(r"220[- ].*FileZilla", re.I), "filezilla-ftpd", None),
    (re.compile(r"220[- ].*Microsoft FTP", re.I), "iis-ftpd", None),
    (re.compile(r"220[- ].*Postfix", re.I), "postfix", None),
    (re.compile(r"220[- ].*Exim\s+([\d.]+)", re.I), "exim", None),
    (re.compile(r"220[- ].*Sendmail", re.I), "sendmail", None),
    (re.compile(r"220[- ].*hMailServer", re.I), "hmailserver", None),
    (re.compile(r"\* OK.*Dovecot", re.I), "dovecot", None),
    (re.compile(r"\* OK.*Courier", re.I), "courier", None),
    (re.compile(r"\* OK.*Cyrus", re.I), "cyrus-imap", None),
    (re.compile(r"\+OK.*Dovecot", re.I), "dovecot-pop3", None),
    (re.compile(r"Server:\s*Apache/([\d.]+)", re.I), "apache", None),
    (re.compile(r"Server:\s*nginx/([\d.]+)", re.I), "nginx", None),
    (re.compile(r"Server:\s*Microsoft-IIS/([\d.]+)", re.I), "iis", None),
    (re.compile(r"Server:\s*LiteSpeed", re.I), "litespeed", None),
    (re.compile(r"Server:\s*Caddy", re.I), "caddy", None),
    (re.compile(r"Server:\s*lighttpd/([\d.]+)", re.I), "lighttpd", None),
    (re.compile(r"Server:\s*Tomcat", re.I), "tomcat", None),
    (re.compile(r"Server:\s*Jetty\(([\d.]+)", re.I), "jetty", None),
    (re.compile(r"Server:\s*gunicorn", re.I), "gunicorn", None),
    (re.compile(r"Server:\s*uvicorn", re.I), "uvicorn", None),
    (re.compile(r"Server:\s*Kestrel", re.I), "kestrel", None),
    (re.compile(r"5\.[\d.]+-.*MySQL", re.I), "mysql", None),
    (re.compile(r"8\.[\d.]+-.*MySQL", re.I), "mysql", None),
    (re.compile(r"MariaDB", re.I), "mariadb", None),
    (re.compile(r"\+PONG", re.I), "redis", None),
    (re.compile(r"redis_version:([\d.]+)", re.I), "redis", None),
    (re.compile(r"VERSION\s+([\d.]+)", re.I), "memcached", None),
    (re.compile(r'"name"\s*:\s*"elasticsearch"', re.I), "elasticsearch", None),
    (re.compile(r"MongoDB", re.I), "mongodb", None),
    (re.compile(r"CouchDB", re.I), "couchdb", None),
    (re.compile(r"Consul", re.I), "consul", None),
    (re.compile(r"Docker", re.I), "docker", None),
    (re.compile(r"RabbitMQ", re.I), "rabbitmq", None),
    (re.compile(r"RFB\s+([\d.]+)", re.I), "vnc", None),
    (re.compile(r"Samba", re.I), "samba", None),
    (re.compile(r"AMQP", re.I), "amqp", None),
]

# Common ports mapping (fallback)
_COMMON_PORTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 25: "smtp", 53: "dns",
    69: "tftp", 80: "http", 110: "pop3", 139: "netbios",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https",
    445: "smb", 465: "smtps", 587: "submission", 636: "ldaps",
    873: "rsync", 993: "imaps", 995: "pop3s", 1080: "socks",
    1433: "mssql", 1521: "oracle", 2375: "docker", 2376: "docker-tls",
    3128: "squid", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5672: "amqp", 5900: "vnc", 5984: "couchdb", 6379: "redis",
    8080: "http-proxy", 8443: "https-alt", 8500: "consul",
    8888: "http-alt", 9090: "prometheus", 9200: "elasticsearch",
    11211: "memcached", 15672: "rabbitmq-mgmt", 27017: "mongodb",
}


class ServiceDetectPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="service_detect",
        display_name="Service Detection",
        category=PluginCategory.SCANNING,
        description="Identifies services by protocol-specific probes and banner analysis",
        depends_on=["port_scan"],
        produces=["services"],
        timeout=45.0,
    )

    def accepts(self, target: Target) -> bool:
        return bool(target.ports)

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.net is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="Net utils not available"
            )

        host = target.host
        services: list[dict] = []
        findings: list[Finding] = []
        data: dict[str, Any] = {}

        for port in target.ports:
            if ctx.should_stop:
                break

            service_name = _COMMON_PORTS.get(port, "unknown")
            banner = ""
            version = ""
            probes_used: list[str] = []
            probe_results: dict[str, str] = {}

            # ---- 1. Service-specific probes ----
            port_probe_names = _PORT_PROBES.get(port, [])
            for probe_name in port_probe_names:
                if ctx.should_stop:
                    break
                probe_data, read_first, desc = _PROBES.get(
                    probe_name, (b"", True, "generic")
                )
                try:
                    async with ctx.rate:
                        result = await self._run_probe(
                            host, port, probe_data, read_first, timeout=5.0
                        )
                        if result:
                            probe_results[probe_name] = result
                            probes_used.append(probe_name)
                            if not banner:
                                banner = result
                except Exception:
                    pass

            # ---- 2. Generic banner grab if no probes matched ----
            if not banner and not port_probe_names:
                try:
                    async with ctx.rate:
                        banner = await ctx.net.grab_banner(
                            host, port, timeout=5.0
                        )
                except Exception:
                    pass

            # ---- 3. HTTP/HTTPS banner (Server header) ----
            if port in (80, 443, 8080, 8443, 9090, 8000, 8888, 3000, 5000):
                http_info = await self._http_probe(host, port, ctx)
                if http_info:
                    probe_results["http"] = http_info.get("server", "")
                    if not banner and http_info.get("server"):
                        banner = f"Server: {http_info['server']}"
                    if http_info.get("server"):
                        service_name = self._identify_http_service(
                            http_info["server"]
                        )

            # ---- 4. Pattern-based identification ----
            all_response = " ".join(probe_results.values()) if probe_results else banner
            if all_response:
                identified, ver = self._pattern_match(all_response, port)
                if identified:
                    service_name = identified
                if ver:
                    version = ver

            # ---- 5. FTP anonymous check ----
            if service_name in ("ftp", "vsftpd", "proftpd", "pure-ftpd", "filezilla-ftpd"):
                anon_result = probe_results.get("ftp_anon", "")
                if anon_result and (
                    "230" in anon_result or "anonymous" in anon_result.lower()
                ):
                        findings.append(Finding.high(
                            f"FTP anonymous login enabled on port {port}",
                            description=(
                                "FTP server allows anonymous access, potentially "
                                "exposing sensitive files"
                            ),
                            evidence=anon_result[:200],
                            remediation="Disable anonymous FTP access",
                            tags=[
                                "scanning", "services", "ftp", "anonymous",
                                "owasp:a01",
                            ],
                        ))

            # ---- 6. SMTP relay / EHLO analysis ----
            if service_name in ("smtp", "postfix", "exim", "sendmail"):
                ehlo_result = probe_results.get("smtp_ehlo", "")
                if ehlo_result:
                    self._analyze_smtp(ehlo_result, port, findings)

            # ---- 7. Redis no-auth check ----
            if service_name == "redis":
                info_result = probe_results.get("redis_info", "")
                ping_result = probe_results.get("redis", "")
                if "+PONG" in ping_result or info_result:
                    findings.append(Finding.critical(
                        f"Redis on port {port} accessible without authentication",
                        description=(
                            "Redis responds to commands without AUTH, "
                            "allowing data theft and potential RCE via "
                            "CONFIG SET / SLAVEOF"
                        ),
                        evidence=(
                            ping_result[:100] if ping_result else info_result[:100]
                        ),
                        remediation=(
                            "Set a strong password with requirepass or use ACLs; "
                            "bind to 127.0.0.1"
                        ),
                        tags=[
                            "scanning", "services", "redis", "no-auth",
                            "owasp:a07",
                        ],
                    ))

            # ---- 8. MySQL/PostgreSQL version + default cred flag ----
            if service_name in ("mysql", "mariadb") and banner:
                ver = self._extract_mysql_version(banner)
                if ver:
                    version = ver

            if service_name == "postgresql":
                ssl_result = probe_results.get("postgresql_ssl", "")
                if ssl_result and ssl_result.startswith("N"):
                    findings.append(Finding.low(
                        f"PostgreSQL on port {port} does not support SSL",
                        evidence="SSL request returned 'N'",
                        remediation="Enable SSL on PostgreSQL",
                        tags=["scanning", "services", "postgresql", "ssl"],
                    ))

            # Build service record
            service_info = {
                "port": port,
                "service": service_name,
                "banner": banner[:500] if banner else "",
                "version": version,
                "probes": probes_used,
            }
            services.append(service_info)

            # ---- 9. Version disclosure finding ----
            if banner and any(
                kw in banner.lower()
                for kw in (
                    "version", "server:", "openssh", "apache", "nginx",
                    "mysql", "postgresql", "redis", "mongodb",
                )
            ):
                findings.append(Finding.low(
                    f"Service banner on port {port}: {service_name}",
                    description=f"Service reveals info: {version or service_name}",
                    evidence=banner[:200],
                    remediation="Minimize service banner information",
                    tags=["scanning", "info-disclosure", service_name],
                ))

            # ---- 10. Default credential flagging ----
            cred_list = _DEFAULT_CREDS.get(service_name, [])
            if (
                cred_list
                and service_name in ("redis", "mongodb", "elasticsearch", "memcached")
                and service_name != "redis"
            ):
                findings.append(Finding.medium(
                    f"{service_name} on port {port} may use default/no credentials",
                    description=f"{service_name} commonly ships without authentication",
                    evidence=f"Service identified: {service_name}",
                    remediation=f"Enable authentication on {service_name}",
                    tags=[
                        "scanning", "services", service_name,
                        "default-creds",
                    ],
                ))

        # ---- 11. STARTTLS detection ----
        if not ctx.should_stop:
            starttls_findings = await self._check_starttls(host, target.ports, ctx)
            findings.extend(starttls_findings)
            data["starttls"] = [
                f.evidence for f in starttls_findings
                if "STARTTLS" in f.title
            ]

        # Summary
        findings.append(Finding.info(
            f"Services detected on {len(services)} ports",
            evidence=", ".join(
                f"{s['port']}/{s['service']}"
                + (f" ({s['version']})" if s.get("version") else "")
                for s in services
            ),
            tags=["scanning", "services"],
        ))

        return PluginResult.success(
            self.meta.name, host,
            findings=findings,
            data={"services": services, **data},
        )

    # ================================================================
    # Probe execution
    # ================================================================

    async def _run_probe(
        self,
        host: str,
        port: int,
        data: bytes,
        read_first: bool,
        timeout: float = 5.0,
    ) -> str:
        """Connect, optionally read banner first, then send probe and read response."""
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        try:
            result = ""

            if read_first or not data:
                try:
                    initial = await asyncio.wait_for(
                        reader.read(2048), timeout=timeout
                    )
                    result = initial.decode("utf-8", errors="replace").strip()
                except TimeoutError:
                    pass

            if data:
                # Replace 'target' placeholder with actual host
                probe = data.replace(b"target", host.encode())
                writer.write(probe)
                await writer.drain()
                try:
                    resp = await asyncio.wait_for(
                        reader.read(4096), timeout=timeout
                    )
                    resp_str = resp.decode("utf-8", errors="replace").strip()
                    if result:
                        result += "\n" + resp_str
                    else:
                        result = resp_str
                except TimeoutError:
                    pass

            return result
        finally:
            writer.close()
            await writer.wait_closed()

    async def _http_probe(
        self, host: str, port: int, ctx: Any,
    ) -> dict[str, str] | None:
        """Probe an HTTP/HTTPS service for Server header and info."""
        scheme = "https" if port in (443, 8443, 9443, 4443) else "http"
        url = f"{scheme}://{host}:{port}/" if port not in (80, 443) else f"{scheme}://{host}/"

        for attempt_url in (url,):
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(attempt_url, timeout=5.0)
                    headers = resp.headers
                    # Ensure headers is dict-like with string values
                    server = headers.get("Server", "") if hasattr(headers, "get") else ""
                    powered = headers.get("X-Powered-By", "") if hasattr(headers, "get") else ""
                    if not isinstance(server, str):
                        server = ""
                    if not isinstance(powered, str):
                        powered = ""
                    return {
                        "server": server,
                        "powered_by": powered,
                        "status": str(resp.status) if isinstance(resp.status, int) else "",
                    }
            except Exception:
                pass

        # Try alternate scheme
        alt_scheme = "http" if scheme == "https" else "https"
        alt_url = (
            f"{alt_scheme}://{host}:{port}/"
            if port not in (80, 443)
            else f"{alt_scheme}://{host}/"
        )
        try:
            async with ctx.rate:
                resp = await ctx.http.get(alt_url, timeout=5.0)
                headers = resp.headers
                server = headers.get("Server", "") if hasattr(headers, "get") else ""
                powered = headers.get("X-Powered-By", "") if hasattr(headers, "get") else ""
                if not isinstance(server, str):
                    server = ""
                if not isinstance(powered, str):
                    powered = ""
                return {
                    "server": server,
                    "powered_by": powered,
                    "status": str(resp.status) if isinstance(resp.status, int) else "",
                }
        except Exception:
            pass
        return None

    # ================================================================
    # Pattern matching
    # ================================================================

    @staticmethod
    def _pattern_match(
        response: str, port: int
    ) -> tuple[str | None, str]:
        """Match response against known service patterns."""
        for pattern, service, _ in _SERVICE_PATTERNS:
            match = pattern.search(response)
            if match:
                version = ""
                if match.lastindex and match.lastindex >= 1:
                    groups = match.groups()
                    # Take the last group as version typically
                    version = groups[-1] if groups else ""
                return service, version

        return None, ""

    @staticmethod
    def _identify_http_service(server_header: str) -> str:
        """Identify HTTP server from Server header."""
        s = server_header.lower()
        if "apache" in s:
            return "apache"
        if "nginx" in s:
            return "nginx"
        if "iis" in s:
            return "iis"
        if "litespeed" in s:
            return "litespeed"
        if "caddy" in s:
            return "caddy"
        if "lighttpd" in s:
            return "lighttpd"
        if "tomcat" in s:
            return "tomcat"
        if "jetty" in s:
            return "jetty"
        if "gunicorn" in s:
            return "gunicorn"
        if "uvicorn" in s:
            return "uvicorn"
        if "kestrel" in s:
            return "kestrel"
        return "http"

    @staticmethod
    def _extract_mysql_version(banner: str) -> str:
        """Extract MySQL/MariaDB version from handshake banner."""
        match = re.search(r"([\d]+\.[\d]+\.[\d]+[\w.-]*)", banner)
        return match.group(1) if match else ""

    # ================================================================
    # SMTP analysis
    # ================================================================

    @staticmethod
    def _analyze_smtp(ehlo_response: str, port: int, findings: list[Finding]) -> None:
        """Analyze SMTP EHLO response for security features."""
        lines = ehlo_response.upper()

        # STARTTLS support
        has_starttls = "STARTTLS" in lines
        if not has_starttls and port in (25, 587):
            findings.append(Finding.medium(
                f"SMTP on port {port} does not advertise STARTTLS",
                description="Mail traffic may be sent in cleartext",
                evidence=ehlo_response[:200],
                remediation="Enable STARTTLS on the SMTP server",
                tags=["scanning", "services", "smtp", "starttls"],
            ))

        # AUTH mechanisms
        auth_line = ""
        for line in ehlo_response.split("\n"):
            if "AUTH" in line.upper():
                auth_line = line.strip()
                break
        if auth_line and "PLAIN" in auth_line.upper() and not has_starttls:
            findings.append(Finding.high(
                f"SMTP on port {port}: PLAIN auth without STARTTLS",
                description="Credentials are sent in cleartext",
                evidence=auth_line,
                remediation="Require STARTTLS before PLAIN authentication",
                tags=["scanning", "services", "smtp", "auth", "owasp:a02"],
            ))

        # VRFY / EXPN commands (user enumeration)
        if "VRFY" in lines or "EXPN" in lines:
            findings.append(Finding.medium(
                f"SMTP on port {port} supports VRFY/EXPN",
                description="VRFY/EXPN allow email address enumeration",
                evidence=ehlo_response[:200],
                remediation="Disable VRFY and EXPN commands",
                tags=["scanning", "services", "smtp", "enumeration"],
            ))

    # ================================================================
    # STARTTLS detection
    # ================================================================

    async def _check_starttls(
        self, host: str, ports: list[int], ctx: Any,
    ) -> list[Finding]:
        """Check STARTTLS support on mail protocols."""
        findings: list[Finding] = []

        for proto_name, (default_port, greeting, starttls_cmd) in _STARTTLS_COMMANDS.items():
            # Check if the relevant port is open
            matching_port = default_port
            if default_port not in ports:
                continue

            if ctx.should_stop:
                break

            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, matching_port),
                    timeout=5.0,
                )
                try:
                    # Read banner
                    with contextlib.suppress(TimeoutError):
                        await asyncio.wait_for(reader.read(1024), timeout=3.0)

                    # Send greeting if needed
                    if greeting:
                        writer.write(greeting)
                        await writer.drain()
                        with contextlib.suppress(TimeoutError):
                            await asyncio.wait_for(reader.read(1024), timeout=3.0)

                    # Send STARTTLS command
                    writer.write(starttls_cmd)
                    await writer.drain()
                    try:
                        resp = await asyncio.wait_for(reader.read(1024), timeout=3.0)
                        resp_str = resp.decode("utf-8", errors="replace")

                        # Check if STARTTLS was accepted
                        if any(
                            code in resp_str
                            for code in ("220", "OK", "+OK", "a001 OK", "Begin TLS")
                        ):
                            findings.append(Finding.info(
                                f"STARTTLS supported on {proto_name} "
                                f"(port {matching_port})",
                                evidence=resp_str[:200],
                                tags=[
                                    "scanning", "services", proto_name,
                                    "starttls",
                                ],
                            ))

                            # Try TLS upgrade
                            try:
                                ssl_ctx = ssl.create_default_context()
                                ssl_ctx.check_hostname = False
                                ssl_ctx.verify_mode = ssl.CERT_NONE
                                transport = writer.transport
                                protocol_obj = transport.get_protocol()
                                await asyncio.wait_for(
                                    asyncio.get_running_loop().start_tls(
                                        transport, protocol_obj, ssl_ctx,
                                        server_hostname=host,
                                    ),
                                    timeout=5.0,
                                )
                                findings.append(Finding.info(
                                    f"STARTTLS upgrade successful on {proto_name}",
                                    tags=[
                                        "scanning", "services", proto_name,
                                        "starttls", "tls",
                                    ],
                                ))
                            except Exception:
                                findings.append(Finding.low(
                                    f"STARTTLS upgrade failed on {proto_name} "
                                    f"(port {matching_port})",
                                    description="Server advertises STARTTLS but upgrade fails",
                                    remediation="Verify TLS configuration on the mail server",
                                    tags=[
                                        "scanning", "services", proto_name,
                                        "starttls",
                                    ],
                                ))
                        else:
                            findings.append(Finding.low(
                                f"STARTTLS not supported on {proto_name} "
                                f"(port {matching_port})",
                                description="Mail protocol does not support encryption upgrade",
                                evidence=resp_str[:200],
                                remediation="Enable STARTTLS on the mail server",
                                tags=[
                                    "scanning", "services", proto_name,
                                    "starttls",
                                ],
                            ))
                    except TimeoutError:
                        pass
                finally:
                    writer.close()
                    await writer.wait_closed()
            except Exception:
                pass

        return findings
