"""DVWA verification script — check scan results for 100% detection."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# Expected vulnerability detections
EXPECTED_VULNS = [
    {
        "id": 1,
        "name": "SQL Injection",
        "patterns": [
            r"sql.?inject",
            r"sqli",
            r"sql\b.*\binjection",
            r"blind.?sql",
            r"union.?based",
            r"error.?based",
        ],
        "endpoint_hint": "sqli",
    },
    {
        "id": 2,
        "name": "SQL Injection (Blind)",
        "patterns": [
            r"blind.?sql",
            r"time.?based",
            r"boolean.?based",
            r"sqli.*blind",
            r"blind.*sqli",
        ],
        "endpoint_hint": "sqli_blind",
    },
    {
        "id": 3,
        "name": "Command Injection",
        "patterns": [
            r"command.?inject",
            r"os.?command",
            r"cmdi",
            r"rce\b",
            r"remote.?code.?exec",
        ],
        "endpoint_hint": "exec",
    },
    {
        "id": 4,
        "name": "File Inclusion (LFI)",
        "patterns": [
            r"file.?inclus",
            r"local.?file",
            r"lfi\b",
            r"path.?travers",
            r"/etc/passwd",
            r"directory.?travers",
        ],
        "endpoint_hint": "fi",
    },
    {
        "id": 5,
        "name": "File Upload",
        "patterns": [
            r"file.?upload",
            r"upload.?bypass",
            r"unrestrict.*upload",
            r"malicious.*upload",
        ],
        "endpoint_hint": "upload",
    },
    {
        "id": 6,
        "name": "Brute Force / Weak Credentials",
        "patterns": [
            r"brute.?force",
            r"weak.?cred",
            r"default.?cred",
            r"weak.?password",
            r"admin.*password",
            r"credential",
        ],
        "endpoint_hint": "brute",
    },
]


def find_report() -> Path | None:
    """Find the most recent scan report JSON."""
    # Check common locations
    candidates = [
        *Path(".").glob("**/report*.json"),
        *Path("projects").glob("**/report*.json"),
        *Path(".").glob("**/results*.json"),
        *Path(".").glob("**/scan_*.json"),
    ]
    if not candidates:
        return None
    # Return most recently modified
    return max(candidates, key=lambda p: p.stat().st_mtime)


def load_findings(report_path: Path) -> list[dict]:
    """Load findings from a JSON report."""
    data = json.loads(report_path.read_text(encoding="utf-8"))

    findings = []
    # Handle different report formats
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                findings.extend(item.get("findings", []))
    elif isinstance(data, dict):
        # Flat list of findings
        if "findings" in data:
            findings = data["findings"]
        # Results keyed by plugin
        elif "results" in data:
            for result in data["results"]:
                if isinstance(result, dict):
                    findings.extend(result.get("findings", []))
        # Direct plugin results
        else:
            for _key, value in data.items():
                if isinstance(value, dict) and "findings" in value:
                    findings.extend(value["findings"])

    return findings


def check_vuln(vuln: dict, findings: list[dict]) -> tuple[bool, str]:
    """Check if a vulnerability type was detected in findings."""
    for finding in findings:
        title = finding.get("title", "").lower()
        desc = finding.get("description", "").lower()
        evidence = finding.get("evidence", "").lower() if finding.get("evidence") else ""
        url = finding.get("url", "").lower() if finding.get("url") else ""
        combined = f"{title} {desc} {evidence} {url}"

        for pattern in vuln["patterns"]:
            if re.search(pattern, combined, re.IGNORECASE):
                sev = finding.get("severity", "?")
                return True, f"Found: '{finding.get('title', '?')}' (severity={sev})"

    return False, "NOT FOUND"


def main() -> None:
    print("=" * 60)
    print("DVWA Vulnerability Detection Verification")
    print("=" * 60)

    # Find report
    report_path = Path(sys.argv[1]) if len(sys.argv) > 1 else find_report()

    if not report_path or not report_path.exists():
        print("ERROR: No scan report found.", file=sys.stderr)
        print("Usage: python dvwa_verify.py [path/to/report.json]", file=sys.stderr)
        print("\nRun a scan first:", file=sys.stderr)
        print("  .venv/Scripts/python.exe -m basilisk audit localhost:4280 "
              "--config config/dvwa.yaml -v", file=sys.stderr)
        sys.exit(1)

    print(f"Report: {report_path}")

    # Load findings
    findings = load_findings(report_path)
    print(f"Total findings: {len(findings)}")
    print()

    # Check each expected vulnerability
    passed = 0
    failed = 0

    for vuln in EXPECTED_VULNS:
        found, detail = check_vuln(vuln, findings)
        status = "PASS" if found else "FAIL"
        icon = "[+]" if found else "[-]"

        print(f"  {icon} [{vuln['id']}] {vuln['name']}: {status}")
        print(f"      {detail}")

        if found:
            passed += 1
        else:
            failed += 1

    # Summary
    total = len(EXPECTED_VULNS)
    print()
    print("=" * 60)
    print(f"Results: {passed}/{total} detected ({passed / total * 100:.0f}%)")

    if failed == 0:
        print("ALL VULNERABILITIES DETECTED!")
    else:
        print(f"{failed} vulnerabilities MISSED")
        print("\nMissed vulns need investigation — check plugin logs")

    print("=" * 60)

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
