"""WHOIS lookup plugin — domain registration info."""

from __future__ import annotations

import asyncio
import socket
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class WhoisPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="whois",
        display_name="WHOIS Lookup",
        category=PluginCategory.RECON,
        description="Retrieves domain WHOIS registration information",
        produces=["whois_info"],
        timeout=15.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        try:
            whois_text = await asyncio.wait_for(
                self._query_whois(target.host),
                timeout=10.0,
            )
        except Exception as e:
            return PluginResult.fail(
                self.meta.name, target.host, error=f"WHOIS query failed: {e}"
            )

        if not whois_text:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info("No WHOIS data returned")],
                data={"whois_raw": ""},
            )

        info = self._parse_whois(whois_text)

        findings = [
            Finding.info(
                f"WHOIS: {info.get('registrar', 'Unknown registrar')}",
                evidence=whois_text[:500],
                tags=["recon", "whois"],
            )
        ]

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"whois_raw": whois_text, "whois_parsed": info},
        )

    async def _query_whois(self, domain: str) -> str:
        """Query WHOIS server for domain info."""
        tld = domain.rsplit(".", 1)[-1]
        whois_server = self._get_whois_server(tld)

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._whois_tcp, domain, whois_server,
        )

    @staticmethod
    def _whois_tcp(domain: str, server: str, port: int = 43) -> str:
        """Raw TCP WHOIS query."""
        with socket.create_connection((server, port), timeout=10) as sock:
            sock.sendall(f"{domain}\r\n".encode())
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            return response.decode("utf-8", errors="replace")

    @staticmethod
    def _get_whois_server(tld: str) -> str:
        servers = {
            "com": "whois.verisign-grs.com",
            "net": "whois.verisign-grs.com",
            "org": "whois.pir.org",
            "ru": "whois.tcinet.ru",
            "io": "whois.nic.io",
            "dev": "whois.nic.google",
            "app": "whois.nic.google",
        }
        return servers.get(tld, f"whois.nic.{tld}")

    @staticmethod
    def _parse_whois(text: str) -> dict:
        """Extract key fields from WHOIS response."""
        info: dict[str, str] = {}
        field_map = {
            "registrar": ["Registrar:", "registrar:"],
            "creation_date": ["Creation Date:", "created:"],
            "expiration_date": ["Registry Expiry Date:", "Expiration Date:", "paid-till:"],
            "name_servers": ["Name Server:", "nserver:"],
            "status": ["Domain Status:", "state:"],
        }
        for key, prefixes in field_map.items():
            values = []
            for line in text.splitlines():
                line = line.strip()
                for prefix in prefixes:
                    if line.lower().startswith(prefix.lower()):
                        val = line[len(prefix):].strip()
                        if val:
                            values.append(val)
            if values:
                info[key] = values[0] if len(values) == 1 else "; ".join(values)
        return info
