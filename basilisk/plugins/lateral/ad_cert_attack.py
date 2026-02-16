"""AD Certificate Services attack — ESC1-ESC8, Certifried."""

from __future__ import annotations

import logging
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)

# ESC (Escalation) attack types
ESC_ATTACKS = {
    "ESC1": {
        "name": "Template allows SAN",
        "description": (
            "Certificate template allows requester to specify a Subject "
            "Alternative Name (SAN) — impersonate any user"
        ),
        "severity": "critical",
    },
    "ESC2": {
        "name": "Any Purpose EKU",
        "description": "Template has 'Any Purpose' or no EKU — use for client auth",
        "severity": "critical",
    },
    "ESC3": {
        "name": "Enrollment Agent",
        "description": "Template allows enrollment agent — request certs for others",
        "severity": "high",
    },
    "ESC4": {
        "name": "Template ACL abuse",
        "description": "Template has permissive ACL — modify to enable ESC1",
        "severity": "critical",
    },
    "ESC5": {
        "name": "CA ACL abuse",
        "description": "CA has permissive ACL — modify CA configuration",
        "severity": "critical",
    },
    "ESC6": {
        "name": "EDITF_ATTRIBUTESUBJECTALTNAME2",
        "description": "CA has flag enabled — specify SAN in any request",
        "severity": "critical",
    },
    "ESC7": {
        "name": "CA Officer approval abuse",
        "description": "ManageCA + ManageCertificates — approve pending requests",
        "severity": "high",
    },
    "ESC8": {
        "name": "NTLM relay to HTTP enrollment",
        "description": "Web enrollment endpoint without EPA — relay NTLM for cert",
        "severity": "critical",
    },
}


class AdCertAttackPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="ad_cert_attack",
        display_name="AD Certificate Services Attack",
        category=PluginCategory.LATERAL,
        description="AD CS abuse: ESC1-ESC8, Certifried, certificate impersonation",
        depends_on=["ldap_enum"],
        produces=["credentials", "lateral_access"],
        timeout=60.0,
        requires_http=False,
        requires_credentials=True,
        risk_level="noisy",
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        data: dict = {"ca_servers": [], "vulnerable_templates": [], "esc_findings": []}

        domain = target.meta.get("ad_domain", "")
        if not domain:
            findings.append(Finding.info(
                "No AD domain for certificate attack",
                tags=["lateral", "adcs"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        # Method 1: Use certipy if available
        if ctx.subprocess_mgr:
            cred = None
            if ctx.creds:
                creds_list = ctx.creds.get_for_target(target.host)
                if creds_list:
                    cred = creds_list[0]

            if cred:
                avail = await ctx.subprocess_mgr.is_available("certipy")
                if avail:
                    dc_ip = target.meta.get("dc_ip", target.host)
                    cmd = (
                        f"certipy find -u {cred.username}@{domain} "
                        f"-p '{cred.secret}' -dc-ip {dc_ip} -vulnerable"
                    )
                    result = await ctx.subprocess_mgr.run(cmd, timeout=30)
                    if result.returncode == 0 and result.stdout:
                        output = result.stdout
                        for esc_id, esc_info in ESC_ATTACKS.items():
                            if esc_id in output:
                                data["esc_findings"].append(esc_id)
                                if esc_info["severity"] == "critical":
                                    findings.append(Finding.critical(
                                        f"AD CS {esc_id}: {esc_info['name']}",
                                        evidence=output[:500],
                                        description=esc_info["description"],
                                        tags=["lateral", "adcs", esc_id.lower()],
                                    ))
                                else:
                                    findings.append(Finding.high(
                                        f"AD CS {esc_id}: {esc_info['name']}",
                                        evidence=output[:500],
                                        description=esc_info["description"],
                                        tags=["lateral", "adcs", esc_id.lower()],
                                    ))

        # Method 2: LDAP-based CA detection
        if ctx.ldap and not data["esc_findings"]:
            try:
                # Search for Certificate Authority objects
                ca_results = await ctx.ldap.search(
                    search_filter="(objectClass=pKIEnrollmentService)",
                    attributes=["cn", "dNSHostName", "certificateTemplates"],
                )
                for ca in ca_results:
                    ca_name = ca.get("cn", "")
                    ca_host = ca.get("dNSHostName", "")
                    templates = ca.get("certificateTemplates", [])
                    data["ca_servers"].append({
                        "name": ca_name, "host": ca_host,
                        "templates": len(templates) if isinstance(templates, list) else 0,
                    })

                if data["ca_servers"]:
                    findings.append(Finding.medium(
                        f"AD CS detected: {len(data['ca_servers'])} CA servers",
                        evidence="\n".join(
                            f"{ca['name']} ({ca['host']})"
                            for ca in data["ca_servers"][:5]
                        ),
                        description="Run certipy or Certify to check for ESC vulnerabilities",
                        tags=["lateral", "adcs"],
                    ))

            except Exception as exc:
                logger.debug("AD CS LDAP query failed: %s", exc)

        # Check ESC8 — HTTP enrollment endpoints
        if ctx.http:
            for ca in data["ca_servers"][:3]:
                ca_host = ca.get("host", target.host)
                for endpoint in [
                    f"http://{ca_host}/certsrv/",
                    f"https://{ca_host}/certsrv/",
                ]:
                    try:
                        async with ctx.rate:
                            resp = await ctx.http.get(endpoint, timeout=5.0)
                            if resp.status in (200, 401):
                                data["esc_findings"].append("ESC8")
                                findings.append(Finding.critical(
                                    f"AD CS web enrollment: {endpoint}",
                                    evidence=f"HTTP {resp.status} at {endpoint}",
                                    description=ESC_ATTACKS["ESC8"]["description"],
                                    tags=["lateral", "adcs", "esc8"],
                                ))
                    except Exception:
                        continue

        if not findings:
            findings.append(Finding.info(
                "No AD CS vulnerabilities detected",
                tags=["lateral", "adcs"],
            ))

        return PluginResult.success(
            self.meta.name, target.host, findings=findings, data=data,
        )
