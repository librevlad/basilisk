"""SSL certificate chain analyzer."""

from __future__ import annotations

import asyncio
import ssl
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target


class SslCertChainPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="ssl_cert_chain",
        display_name="SSL Certificate Chain",
        category=PluginCategory.ANALYSIS,
        description="Analyzes SSL certificate chain for trust and configuration issues",
        depends_on=["ssl_check"],
        produces=["cert_chain_info"],
        timeout=15.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        chain_info: dict = {"chain_length": 0, "issues": []}

        try:
            # Connect with full chain
            context = ssl.create_default_context()

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    target.host, 443, ssl=context, server_hostname=target.host,
                ),
                timeout=10.0,
            )

            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj:
                cert = ssl_obj.getpeercert()
                if cert:
                    subject = dict(x[0] for x in cert.get("subject", ()))
                    issuer = dict(x[0] for x in cert.get("issuer", ()))
                    san = [
                        v for t, v in cert.get("subjectAltName", ())
                        if t == "DNS"
                    ]

                    chain_info.update({
                        "subject": subject.get("commonName", ""),
                        "issuer": issuer.get("organizationName", ""),
                        "san_count": len(san),
                        "not_before": cert.get("notBefore", ""),
                        "not_after": cert.get("notAfter", ""),
                    })

                    # Check SAN coverage
                    wildcard = f"*.{'.'.join(target.host.split('.')[1:])}"
                    if target.host not in san and wildcard not in san:
                        findings.append(Finding.medium(
                            "Certificate SAN doesn't match hostname",
                            evidence=f"Host: {target.host}, SANs: {', '.join(san[:5])}",
                            tags=["analysis", "ssl", "certificate"],
                        ))

                    # Check if self-signed
                    if subject == issuer:
                        findings.append(Finding.high(
                            "Self-signed certificate",
                            evidence=f"Subject = Issuer = {subject.get('commonName', '?')}",
                            remediation="Use a certificate from a trusted CA",
                            tags=["analysis", "ssl", "certificate"],
                        ))

            writer.close()
            await writer.wait_closed()

        except ssl.SSLCertVerificationError as e:
            findings.append(Finding.high(
                "SSL certificate verification failed",
                evidence=str(e)[:200],
                remediation="Fix certificate chain issues",
                tags=["analysis", "ssl"],
            ))
        except (TimeoutError, OSError) as e:
            findings.append(Finding.info(
                f"Could not analyze SSL certificate chain: {e}",
                tags=["analysis", "ssl"],
            ))

        if not findings:
            findings.append(Finding.info(
                f"SSL certificate chain OK (issuer: {chain_info.get('issuer', '?')})",
                tags=["analysis", "ssl"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data=chain_info,
        )
