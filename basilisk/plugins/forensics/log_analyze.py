"""Log analysis — auth failures, suspicious commands, IOCs."""

from __future__ import annotations

import logging
import re
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)

# Patterns for suspicious activity in logs
SUSPICIOUS_PATTERNS = [
    (r"Failed password for .+ from ([\d.]+)", "failed_auth", "medium"),
    (r"BREAK-IN ATTEMPT", "break_in", "critical"),
    (r"Invalid user (\S+) from ([\d.]+)", "invalid_user", "medium"),
    (r"Accepted password for root from ([\d.]+)", "root_login", "high"),
    (r"sudo:.*COMMAND=(/bin/bash|/bin/sh)", "sudo_shell", "high"),
    (r"reverse shell|bind shell|netcat|nc -e", "reverse_shell", "critical"),
    (r"curl .+\| ?sh|wget .+\| ?sh|bash -i >", "download_exec", "critical"),
    (r"/etc/shadow|/etc/passwd", "sensitive_file_access", "high"),
    (r"base64 -d|python -c .+import", "encoded_command", "high"),
    (r"useradd|adduser|usermod.*-aG.*sudo", "user_creation", "high"),
    (r"crontab -e|/etc/cron", "cron_modification", "medium"),
    (r"iptables -F|ufw disable", "firewall_disable", "critical"),
]


class LogAnalyzePlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="log_analyze",
        display_name="Log Analysis",
        category=PluginCategory.FORENSICS,
        description="Auth failures, suspicious commands, IOCs in log files",
        produces=["iocs"],
        timeout=60.0,
        requires_http=False,
        risk_level="safe",
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        data: dict = {
            "failed_auths": [], "suspicious": [],
            "iocs": [], "log_files_analyzed": 0,
        }

        # Get log content from target meta or shell
        log_content = target.meta.get("log_content", "")
        log_files = target.meta.get("log_files", [])

        # Read logs from shell if available
        if not log_content and not log_files:
            shells = ctx.state.get("active_shells", [])
            if shells and ctx.shell:
                session = (
                    ctx.shell.get_session(shells[0]["id"])
                    if isinstance(shells[0], dict) else None
                )
                if session:
                    # Read common log files
                    for log_path in [
                        "/var/log/auth.log",
                        "/var/log/syslog",
                        "/var/log/messages",
                        "/var/log/secure",
                        "/var/log/apache2/access.log",
                        "/var/log/apache2/error.log",
                        "/var/log/nginx/access.log",
                    ]:
                        output = await ctx.shell.execute(
                            session,
                            f"tail -500 {log_path} 2>/dev/null",
                            timeout=5.0,
                        )
                        if output:
                            log_content += f"\n=== {log_path} ===\n{output}"
                            data["log_files_analyzed"] += 1

        if not log_content:
            findings.append(Finding.info(
                "No log content available (set target.meta log_content or log_files)",
                tags=["forensics", "log"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        # Analyze logs
        for pattern, category, severity in SUSPICIOUS_PATTERNS:
            matches = re.findall(pattern, log_content, re.IGNORECASE)
            if matches:
                entry = {
                    "category": category,
                    "count": len(matches),
                    "samples": [str(m)[:100] for m in matches[:5]],
                }
                data["suspicious"].append(entry)

                if severity == "critical":
                    findings.append(Finding.critical(
                        f"Suspicious activity: {category} ({len(matches)} occurrences)",
                        evidence="\n".join(str(m)[:100] for m in matches[:5]),
                        tags=["forensics", "log", category],
                    ))
                elif severity == "high":
                    findings.append(Finding.high(
                        f"Suspicious activity: {category} ({len(matches)} occurrences)",
                        evidence="\n".join(str(m)[:100] for m in matches[:5]),
                        tags=["forensics", "log", category],
                    ))
                else:
                    findings.append(Finding.medium(
                        f"Activity detected: {category} ({len(matches)} occurrences)",
                        evidence="\n".join(str(m)[:100] for m in matches[:5]),
                        tags=["forensics", "log", category],
                    ))

        # Extract IPs for IOC list
        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        all_ips = re.findall(ip_pattern, log_content)
        # Count and find top IPs in failed auth
        if all_ips:
            from collections import Counter
            ip_counts = Counter(all_ips)
            top_ips = ip_counts.most_common(10)
            data["iocs"] = [{"ip": ip, "count": cnt} for ip, cnt in top_ips]

            # IPs with many failed attempts
            suspicious_ips = [
                (ip, cnt) for ip, cnt in top_ips
                if cnt > 5 and ip not in ("127.0.0.1", "0.0.0.0")
            ]
            if suspicious_ips:
                findings.append(Finding.medium(
                    f"Suspicious IPs (high frequency): {len(suspicious_ips)}",
                    evidence="\n".join(
                        f"{ip}: {cnt} occurrences" for ip, cnt in suspicious_ips
                    ),
                    tags=["forensics", "log", "ioc"],
                ))

        if not findings:
            findings.append(Finding.info(
                f"No suspicious activity in {data['log_files_analyzed']} log files",
                tags=["forensics", "log"],
            ))

        return PluginResult.success(
            self.meta.name, target.host, findings=findings, data=data,
        )
