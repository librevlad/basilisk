"""Centralized secret pattern registry — single source of truth.

All plugins that scan for secrets should import from here
instead of maintaining their own pattern lists.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from basilisk.models.result import Severity


@dataclass(frozen=True, slots=True)
class SecretPattern:
    """A single secret detection pattern."""

    name: str
    pattern: re.Pattern[str]
    severity: Severity = Severity.HIGH
    description: str = ""


@dataclass(frozen=True, slots=True)
class SecretMatch:
    """A match found by scanning text against secret patterns."""

    pattern_name: str
    severity: Severity
    match: str
    description: str = ""


def _compile(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


# Unified registry — superset of all patterns from
# git_exposure, web_crawler, js_api_extract, js_secret_scan
SECRET_REGISTRY: list[SecretPattern] = [
    # --- Cloud provider keys ---
    SecretPattern(
        "AWS Access Key", _compile(r"AKIA[0-9A-Z]{16}"),
        Severity.HIGH, "AWS access key ID — grants API access to AWS services",
    ),
    SecretPattern(
        "AWS Secret Key",
        _compile(r"(?:aws.?secret|secret.?access.?key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})", re.I),
        Severity.CRITICAL, "AWS secret access key — full AWS API access",
    ),
    SecretPattern(
        "Google API Key", _compile(r"AIza[0-9A-Za-z_-]{35}"),
        Severity.HIGH, "Google API key found in source",
    ),
    SecretPattern(
        "Google OAuth Client ID",
        _compile(r"[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com"),
        Severity.MEDIUM, "Google OAuth client ID exposed",
    ),
    SecretPattern(
        "Firebase URL", _compile(r"https?://[a-z0-9-]+\.firebaseio\.com", re.I),
        Severity.MEDIUM, "Firebase database URL found",
    ),
    SecretPattern(
        "Firebase API Key",
        _compile(
            r"(?:apiKey|firebase.?api.?key)\s*[:=]\s*['\"]?(AIza[0-9A-Za-z_-]{35})['\"]?",
            re.I,
        ),
        Severity.HIGH, "Firebase API key found",
    ),

    # --- Payment ---
    SecretPattern(
        "Stripe Secret Key", _compile(r"sk_(?:live|test)_[0-9a-zA-Z]{24,}"),
        Severity.CRITICAL, "Stripe secret key — can process payments",
    ),
    SecretPattern(
        "Stripe Publishable Key", _compile(r"pk_(?:live|test)_[0-9a-zA-Z]{24,}"),
        Severity.MEDIUM, "Stripe publishable key (limited risk)",
    ),

    # --- Version control ---
    SecretPattern(
        "GitHub Token", _compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}"),
        Severity.HIGH, "GitHub personal access token",
    ),
    SecretPattern(
        "GitLab Token", _compile(r"glpat-[a-zA-Z0-9\-]{20,}"),
        Severity.HIGH, "GitLab personal access token",
    ),

    # --- Messaging / Email ---
    SecretPattern(
        "Slack Token", _compile(r"xox[bpoas]-[0-9a-zA-Z-]{10,}"),
        Severity.HIGH, "Slack API token found",
    ),
    SecretPattern(
        "SendGrid API Key", _compile(r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}"),
        Severity.HIGH, "SendGrid API key found",
    ),
    SecretPattern(
        "Mailgun API Key", _compile(r"key-[a-zA-Z0-9]{32}"),
        Severity.HIGH, "Mailgun API key found",
    ),
    SecretPattern(
        "Twilio Account SID", _compile(r"AC[a-f0-9]{32}"),
        Severity.MEDIUM, "Twilio Account SID found",
    ),
    SecretPattern(
        "Twilio API Key", _compile(r"SK[0-9a-fA-F]{32}"),
        Severity.HIGH, "Twilio API key found",
    ),

    # --- AI / SaaS ---
    SecretPattern(
        "OpenAI API Key", _compile(r"sk-[a-zA-Z0-9]{32,}"),
        Severity.HIGH, "OpenAI API key found",
    ),
    SecretPattern(
        "Heroku API Key",
        _compile(r"(?:heroku.*['\"]?)[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
        Severity.HIGH, "Heroku API key found",
    ),

    # --- Cryptographic material ---
    SecretPattern(
        "Private Key", _compile(r"-----BEGIN\s(?:RSA\s|EC\s|DSA\s)?PRIVATE\sKEY-----"),
        Severity.CRITICAL, "Private key material found in source",
    ),
    SecretPattern(
        "JWT Token",
        _compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        Severity.HIGH, "Hardcoded JWT token",
    ),
    SecretPattern(
        "Bearer Token", _compile(r"(?:bearer)\s+[a-zA-Z0-9_\-.~+/]+=*", re.I),
        Severity.MEDIUM, "Bearer token in source code",
    ),
    SecretPattern(
        "Basic Auth", _compile(r"(?:basic)\s+[a-zA-Z0-9+/]+=+", re.I),
        Severity.MEDIUM, "Basic auth credentials in source",
    ),

    # --- Database / Infrastructure ---
    SecretPattern(
        "Database URL",
        _compile(r"(?:mysql|postgres|mongodb|redis|amqp)://[^\s'\"]{10,}", re.I),
        Severity.CRITICAL, "Database connection string with credentials",
    ),
    SecretPattern(
        "S3 Bucket URL",
        _compile(
            r"(?:https?://)?[a-z0-9.-]+\.s3[.-](?:us|eu|ap|sa|ca|me|af)-[a-z]+-\d\.amazonaws\.com",
            re.I,
        ),
        Severity.MEDIUM, "AWS S3 bucket URL found",
    ),
    SecretPattern(
        "S3 Bucket Path", _compile(r"s3://[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", re.I),
        Severity.MEDIUM, "S3 bucket reference found",
    ),
    SecretPattern(
        "Internal IP Address",
        _compile(
            r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})"
            r"|(?:172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})"
            r"|(?:192\.168\.\d{1,3}\.\d{1,3})"
        ),
        Severity.LOW, "Internal/private IP address found",
    ),
    SecretPattern(
        "Internal Hostname",
        _compile(
            r"['\"]https?://(?:[a-z0-9-]+\."
            r"(?:internal|local|corp|intranet|lan|private|staging|dev|test)"
            r"(?:\.[a-z]+)?)[/'\" ]",
            re.I,
        ),
        Severity.MEDIUM, "Internal hostname found",
    ),

    # --- Generic / catch-all ---
    SecretPattern(
        "Hardcoded Password",
        _compile(r"(?:password|passwd|pwd|secret)\s*[:=]\s*['\"]([^'\"]{6,})['\"]", re.I),
        Severity.HIGH, "Hardcoded password or secret value",
    ),
    SecretPattern(
        "Generic API Key",
        _compile(
            r"(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token|access[_-]?token)"
            r"\s*[:=]\s*['\"]([a-zA-Z0-9_-]{20,})['\"]",
            re.I,
        ),
        Severity.MEDIUM, "Generic API key or token found",
    ),
]

# Known false-positive patterns — matched values that are NOT real secrets
_FALSE_POSITIVE_VALUES = {
    # React prop-types internal constant (every React app has this)
    "SECRET_DO_NOT_PASS_THIS_OR_YOU_WILL_BE_FIRED",
    # Common test/placeholder values
    "password", "secret", "changeme", "example", "password123",
    "YOUR_SECRET_KEY", "your_secret_key", "YOUR_API_KEY",
    "your_api_key", "INSERT_YOUR_KEY_HERE", "CHANGE_ME",
    "xxxxxxxx", "XXXXXXXX", "000000", "123456",
    # Common library constants mistaken for secrets
    "abcdefghijklmnop",
}

# Known FP substrings in the matched text
_FALSE_POSITIVE_SUBSTRINGS = (
    "DO_NOT_PASS_THIS_OR_YOU_WILL_BE_FIRED",
    "PropTypesSecret",
    "example.com",
    "placeholder",
)


def _is_false_positive(match_text: str) -> bool:
    """Check if a matched secret value is a known false positive."""
    # Extract the actual secret value from the match (after = or :)
    for sep in ("=", ":"):
        if sep in match_text:
            value = match_text.split(sep, 1)[1].strip().strip("'\"` ")
            if value in _FALSE_POSITIVE_VALUES:
                return True
            break
    # Check the full match text for known FP substrings
    return any(fp in match_text for fp in _FALSE_POSITIVE_SUBSTRINGS)


def scan_text(text: str, *, min_severity: Severity = Severity.LOW) -> list[SecretMatch]:
    """Scan text for secrets using the full registry.

    Returns deduplicated matches sorted by severity (highest first).
    """
    matches: list[SecretMatch] = []
    seen: set[str] = set()

    for sp in SECRET_REGISTRY:
        if sp.severity < min_severity:
            continue
        for m in sp.pattern.finditer(text):
            match_text = m.group(0)[:120]  # truncate long matches
            if _is_false_positive(match_text):
                continue
            dedup_key = f"{sp.name}:{match_text}"
            if dedup_key not in seen:
                seen.add(dedup_key)
                matches.append(SecretMatch(
                    pattern_name=sp.name,
                    severity=sp.severity,
                    match=match_text,
                    description=sp.description,
                ))

    matches.sort(key=lambda m: m.severity, reverse=True)
    return matches


def redact(value: str, *, visible: int = 4) -> str:
    """Redact a secret value, showing only first `visible` chars."""
    if len(value) <= visible:
        return "*" * len(value)
    return value[:visible] + "*" * (len(value) - visible)
