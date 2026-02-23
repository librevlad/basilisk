"""PCAP analyzer — extract credentials, files, and anomalies from packet captures."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class PcapCredential:
    """Credential found in a PCAP."""

    protocol: str  # http, ftp, telnet, smtp, etc.
    username: str
    password: str
    target: str = ""
    port: int = 0


@dataclass
class PcapHttpRequest:
    """HTTP request extracted from a PCAP."""

    method: str
    url: str
    host: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    response_code: int = 0


@dataclass
class PcapDnsQuery:
    """DNS query extracted from a PCAP."""

    name: str
    qtype: str = "A"
    response: str = ""


@dataclass
class PcapFile:
    """File extracted from a PCAP."""

    filename: str
    content_type: str = ""
    data: bytes = b""
    source: str = ""


@dataclass
class PcapAnomaly:
    """Suspicious activity found in a PCAP."""

    description: str
    severity: str = "medium"  # low, medium, high
    evidence: str = ""


class PcapAnalyzer:
    """Analyze PCAP files for credentials, files, and anomalies.

    Uses scapy for packet parsing. All heavy operations can be run
    in threads via asyncio.to_thread() from plugins.
    """

    def __init__(self) -> None:
        self._packets: list = []

    def load(self, pcap_path: str) -> int:
        """Load a PCAP file. Returns packet count."""
        try:
            from scapy.all import rdpcap
            self._packets = rdpcap(pcap_path)
            return len(self._packets)
        except ImportError as exc:
            raise ImportError(
                "scapy is required for PCAP analysis. "
                "Install with: pip install 'basilisk[forensics]'"
            ) from exc

    def extract_http_requests(self) -> list[PcapHttpRequest]:
        """Extract HTTP requests from loaded packets."""
        requests = []
        try:
            from scapy.layers.http import HTTPRequest

            for pkt in self._packets:
                if pkt.haslayer(HTTPRequest):
                    http = pkt[HTTPRequest]
                    req = PcapHttpRequest(
                        method=http.Method.decode() if http.Method else "",
                        url=http.Path.decode() if http.Path else "",
                        host=http.Host.decode() if http.Host else "",
                    )
                    if http.payload:
                        req.body = bytes(http.payload).decode(
                            "utf-8", errors="replace",
                        )
                    requests.append(req)
        except ImportError:
            logger.debug("scapy HTTP layer not available")
        return requests

    def extract_credentials(self) -> list[PcapCredential]:
        """Extract cleartext credentials from various protocols."""
        creds = []
        creds.extend(self._extract_http_creds())
        creds.extend(self._extract_ftp_creds())
        creds.extend(self._extract_telnet_creds())
        creds.extend(self._extract_smtp_creds())
        return creds

    def extract_dns_queries(self) -> list[PcapDnsQuery]:
        """Extract DNS queries and responses."""
        queries = []
        try:
            from scapy.layers.dns import DNS

            for pkt in self._packets:
                if pkt.haslayer(DNS):
                    dns = pkt[DNS]
                    if dns.qr == 0 and dns.qd:  # Query
                        queries.append(PcapDnsQuery(
                            name=dns.qd.qname.decode().rstrip("."),
                            qtype=str(dns.qd.qtype),
                        ))
                    elif dns.qr == 1 and dns.an:  # Response
                        for i in range(dns.ancount):
                            rr = dns.an[i] if hasattr(dns.an, "__getitem__") else dns.an
                            name = rr.rrname.decode().rstrip(".") if rr.rrname else ""
                            for q in queries:
                                if q.name == name:
                                    q.response = str(rr.rdata) if hasattr(rr, "rdata") else ""
                                    break
        except ImportError:
            logger.debug("scapy DNS layer not available")
        return queries

    def extract_files(self) -> list[PcapFile]:
        """Extract files transferred over HTTP."""
        files = []
        try:
            from scapy.layers.http import HTTPResponse
            from scapy.layers.inet import TCP

            for pkt in self._packets:
                if pkt.haslayer(HTTPResponse) and pkt.haslayer(TCP):
                    http = pkt[HTTPResponse]
                    if http.payload and len(bytes(http.payload)) > 100:
                        content_type = ""
                        if hasattr(http, "Content_Type"):
                            content_type = http.Content_Type.decode() if http.Content_Type else ""
                        files.append(PcapFile(
                            filename="extracted",
                            content_type=content_type,
                            data=bytes(http.payload),
                        ))
        except ImportError:
            pass
        return files

    def reconstruct_tcp_streams(self) -> dict[str, bytes]:
        """Reconstruct TCP streams from packets."""
        streams: dict[str, list[tuple[int, bytes]]] = {}
        try:
            from scapy.layers.inet import IP, TCP

            for pkt in self._packets:
                if pkt.haslayer(TCP) and pkt.haslayer(IP):
                    ip = pkt[IP]
                    tcp = pkt[TCP]
                    if tcp.payload:
                        key = (
                            f"{ip.src}:{tcp.sport}->{ip.dst}:{tcp.dport}"
                        )
                        if key not in streams:
                            streams[key] = []
                        streams[key].append(
                            (tcp.seq, bytes(tcp.payload)),
                        )
        except ImportError:
            pass

        # Sort by sequence number and concatenate
        result = {}
        for key, segments in streams.items():
            segments.sort(key=lambda x: x[0])
            result[key] = b"".join(data for _, data in segments)
        return result

    def find_anomalies(self) -> list[PcapAnomaly]:
        """Detect suspicious patterns in the PCAP."""
        anomalies = []
        try:
            from scapy.layers.inet import ICMP, IP, TCP

            # Check for port scanning patterns
            syn_targets: dict[str, set[int]] = {}
            for pkt in self._packets:
                if pkt.haslayer(TCP):
                    tcp = pkt[TCP]
                    if tcp.flags == 0x02:  # SYN
                        src = pkt[IP].src if pkt.haslayer(IP) else ""
                        dst_port = tcp.dport
                        if src:
                            syn_targets.setdefault(src, set()).add(dst_port)

            for src, ports in syn_targets.items():
                if len(ports) > 20:
                    anomalies.append(PcapAnomaly(
                        description=f"Port scan from {src}: {len(ports)} ports",
                        severity="high",
                        evidence=f"Ports: {sorted(list(ports))[:20]}...",
                    ))

            # Check for ICMP tunneling
            icmp_data_sizes: list[int] = []
            for pkt in self._packets:
                if pkt.haslayer(ICMP) and pkt[ICMP].payload:
                    icmp_data_sizes.append(len(bytes(pkt[ICMP].payload)))

            if icmp_data_sizes and max(icmp_data_sizes) > 100:
                anomalies.append(PcapAnomaly(
                    description="Possible ICMP tunneling detected",
                    severity="medium",
                    evidence=f"Large ICMP payloads: max {max(icmp_data_sizes)} bytes",
                ))

        except ImportError:
            pass
        return anomalies

    def get_conversation_summary(self) -> list[dict]:
        """Get a summary of network conversations."""
        conversations: dict[str, dict] = {}
        try:
            from scapy.layers.inet import IP, TCP, UDP

            for pkt in self._packets:
                if pkt.haslayer(IP):
                    ip = pkt[IP]
                    proto = "TCP" if pkt.haslayer(TCP) else (
                        "UDP" if pkt.haslayer(UDP) else "OTHER"
                    )
                    key = f"{ip.src}->{ip.dst} ({proto})"
                    if key not in conversations:
                        conversations[key] = {
                            "src": ip.src, "dst": ip.dst,
                            "protocol": proto, "packets": 0, "bytes": 0,
                        }
                    conversations[key]["packets"] += 1
                    conversations[key]["bytes"] += len(pkt)
        except ImportError:
            pass
        return sorted(
            conversations.values(), key=lambda x: x["bytes"], reverse=True,
        )

    # ------------------------------------------------------------------
    # Protocol-specific credential extractors
    # ------------------------------------------------------------------

    def _extract_http_creds(self) -> list[PcapCredential]:
        creds = []
        try:
            from scapy.layers.http import HTTPRequest

            for pkt in self._packets:
                if pkt.haslayer(HTTPRequest):
                    http = pkt[HTTPRequest]
                    # Basic Auth
                    if hasattr(http, "Authorization") and http.Authorization:
                        auth = http.Authorization.decode()
                        if auth.startswith("Basic "):
                            import base64
                            decoded = base64.b64decode(auth[6:]).decode(
                                "utf-8", errors="replace",
                            )
                            if ":" in decoded:
                                user, pwd = decoded.split(":", 1)
                                creds.append(PcapCredential(
                                    protocol="http-basic",
                                    username=user, password=pwd,
                                    target=http.Host.decode() if http.Host else "",
                                ))
                    # POST body credentials
                    if http.Method == b"POST" and http.payload:
                        body = bytes(http.payload).decode(
                            "utf-8", errors="replace",
                        )
                        for pattern in [
                            r"(?:user(?:name)?|login|email)=([^&]+).*?(?:pass(?:word)?|pwd)=([^&]+)",
                            r"(?:pass(?:word)?|pwd)=([^&]+).*?(?:user(?:name)?|login|email)=([^&]+)",
                        ]:
                            m = re.search(pattern, body, re.IGNORECASE)
                            if m:
                                creds.append(PcapCredential(
                                    protocol="http-form",
                                    username=m.group(1),
                                    password=m.group(2),
                                    target=http.Host.decode() if http.Host else "",
                                ))
                                break
        except ImportError:
            pass
        return creds

    def _extract_ftp_creds(self) -> list[PcapCredential]:
        creds = []
        try:
            from scapy.layers.inet import IP, TCP

            ftp_sessions: dict[str, dict] = {}
            for pkt in self._packets:
                if pkt.haslayer(TCP) and pkt.haslayer(IP):
                    tcp = pkt[TCP]
                    if tcp.dport == 21 and tcp.payload:
                        data = bytes(tcp.payload).decode(
                            "utf-8", errors="replace",
                        ).strip()
                        key = f"{pkt[IP].src}->{pkt[IP].dst}"
                        if data.startswith("USER "):
                            ftp_sessions.setdefault(key, {})["user"] = data[5:]
                        elif data.startswith("PASS "):
                            ftp_sessions.setdefault(key, {})["pass"] = data[5:]

            for key, session in ftp_sessions.items():
                if "user" in session and "pass" in session:
                    dst = key.split("->")[1] if "->" in key else ""
                    creds.append(PcapCredential(
                        protocol="ftp",
                        username=session["user"],
                        password=session["pass"],
                        target=dst, port=21,
                    ))
        except ImportError:
            pass
        return creds

    def _extract_telnet_creds(self) -> list[PcapCredential]:
        """Best-effort telnet credential extraction."""
        # Telnet is complex; simplified extraction
        return []

    def _extract_smtp_creds(self) -> list[PcapCredential]:
        """Extract SMTP AUTH credentials."""
        creds = []
        try:
            import base64

            from scapy.layers.inet import IP, TCP

            for pkt in self._packets:
                if pkt.haslayer(TCP) and pkt.haslayer(IP):
                    tcp = pkt[TCP]
                    if tcp.dport in (25, 587) and tcp.payload:
                        data = bytes(tcp.payload).decode(
                            "utf-8", errors="replace",
                        ).strip()
                        if data.startswith("AUTH PLAIN "):
                            try:
                                decoded = base64.b64decode(data[11:]).decode()
                                parts = decoded.split("\x00")
                                if len(parts) >= 3:
                                    creds.append(PcapCredential(
                                        protocol="smtp",
                                        username=parts[1],
                                        password=parts[2],
                                        target=pkt[IP].dst,
                                        port=tcp.dport,
                                    ))
                            except Exception:
                                pass
        except ImportError:
            pass
        return creds
