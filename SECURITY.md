# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 2.x     | :white_check_mark: |
| < 2.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in Basilisk itself (not in targets you scan),
please report it responsibly.

**Do NOT open a public GitHub issue.**

Instead, please use [GitHub Security Advisories](https://github.com/librevlad/basilisk/security/advisories/new)
to report vulnerabilities privately.

Alternatively, contact the maintainer directly via GitHub: [@librevlad](https://github.com/librevlad).

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### What to expect

- Acknowledgment within 48 hours
- A fix or mitigation plan within 7 days for critical issues
- Credit in the changelog (unless you prefer to remain anonymous)

## Scope

This policy covers vulnerabilities in the Basilisk framework code itself, including:

- The core engine, plugins, and utilities
- Dependencies shipped with Basilisk
- The TUI and CLI interfaces

This policy does **not** cover:

- Findings discovered by Basilisk when scanning third-party targets
- Issues in upstream dependencies (report those to the respective projects)
