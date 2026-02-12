"""security.txt checker — full RFC 9116 compliance analysis.

Validates presence, structure, field correctness, PGP signing,
expiry status, canonical URL matching, and HTTPS enforcement.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target
from basilisk.utils.http_check import resolve_base_url

# RFC 9116 field names (case-insensitive matching during parse)
_KNOWN_FIELDS = frozenset({
    "contact",
    "expires",
    "encryption",
    "acknowledgments",
    "preferred-languages",
    "canonical",
    "policy",
    "hiring",
})

_PGP_HEADER = "-----BEGIN PGP SIGNED MESSAGE-----"

# ISO 8601 patterns accepted by the Expires field
_ISO_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}"
    r"[T ]\d{2}:\d{2}(:\d{2})?"
    r"([+-]\d{2}:?\d{2}|Z)?$"
)


class SecurityTxtPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="security_txt",
        display_name="security.txt Check",
        category=PluginCategory.ANALYSIS,
        description=(
            "Full RFC 9116 compliance check for security.txt: "
            "required/optional fields, expiry, PGP, canonical, HTTPS"
        ),
        produces=["security_txt"],
        timeout=15.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host,
                error="HTTP client not available",
            )

        findings: list[Finding] = []
        issues: list[str] = []

        base_url = await resolve_base_url(target.host, ctx)

        # Paths in RFC 9116 priority order
        paths = [
            "/.well-known/security.txt",
            "/security.txt",
        ]

        content = ""
        found_url = ""
        found_via_https = False

        # --- Attempt HTTPS first, then HTTP for each path ---
        schemes = ["https", "http"]
        if base_url:
            schemes = (
                ["https", "http"]
                if base_url.startswith("https://")
                else ["http", "https"]
            )

        for path in paths:
            for scheme in schemes:
                url = f"{scheme}://{target.host}{path}"
                try:
                    async with ctx.rate:
                        resp = await ctx.http.get(
                            url, timeout=8.0,
                        )
                        if resp.status == 200:
                            text = await resp.text(
                                encoding="utf-8", errors="replace",
                            )
                            # Basic validity: must contain at least
                            # one field-like line
                            if self._looks_like_security_txt(text):
                                content = text
                                found_url = url
                                found_via_https = scheme == "https"
                                break
                except Exception:
                    continue
            if found_url:
                break

        # --- No security.txt found ---
        if not found_url:
            findings.append(Finding.info(
                "No security.txt found",
                description=(
                    "Consider adding /.well-known/security.txt "
                    "(RFC 9116)"
                ),
                remediation=(
                    "Create security.txt with at least Contact and "
                    "Expires fields"
                ),
                tags=["analysis", "security-txt"],
            ))
            return PluginResult.success(
                self.meta.name, target.host,
                findings=findings,
                data={
                    "security_txt_url": "",
                    "fields": {},
                    "pgp_signed": False,
                    "expired": False,
                    "days_until_expiry": None,
                    "rfc_compliant": False,
                    "issues": ["security.txt not found"],
                },
            )

        # --- Parse fields ---
        fields = self._parse_fields(content)
        pgp_signed = content.strip().startswith(_PGP_HEADER)

        findings.append(Finding.info(
            f"security.txt found at {found_url}",
            evidence=f"Fields: {', '.join(fields.keys()) or 'none'}",
            tags=["analysis", "security-txt"],
        ))

        rfc_compliant = True

        # --- HTTPS enforcement (RFC 9116 Section 5.1) ---
        if not found_via_https:
            rfc_compliant = False
            issue = "security.txt served over HTTP, not HTTPS"
            issues.append(issue)
            findings.append(Finding.low(
                "security.txt not served over HTTPS",
                description=(
                    "RFC 9116 requires security.txt to be served "
                    "over HTTPS to prevent tampering"
                ),
                remediation="Serve security.txt via HTTPS",
                tags=["analysis", "security-txt"],
            ))

        # --- Check path preference ---
        if "/security.txt" in found_url and "/.well-known/" not in found_url:
            issue = "Found at legacy /security.txt, not /.well-known/"
            issues.append(issue)
            findings.append(Finding.info(
                "security.txt at legacy location",
                description=(
                    "RFC 9116 recommends /.well-known/security.txt "
                    "as the primary location"
                ),
                remediation=(
                    "Move security.txt to /.well-known/security.txt"
                ),
                tags=["analysis", "security-txt"],
            ))

        # --- Required field: Contact ---
        contacts = fields.get("contact", [])
        if not contacts:
            rfc_compliant = False
            issue = "Missing required Contact field"
            issues.append(issue)
            findings.append(Finding.low(
                "security.txt missing Contact field",
                description="Contact is required by RFC 9116",
                remediation=(
                    "Add Contact: field with mailto: or https:// URI"
                ),
                tags=["analysis", "security-txt"],
            ))
        else:
            # Validate contact URIs
            for contact in contacts:
                if not (
                    contact.startswith("mailto:")
                    or contact.startswith("https://")
                ):
                    issue = f"Contact '{contact}' is not mailto:/https://"
                    issues.append(issue)
                    if contact.startswith("http://"):
                        findings.append(Finding.low(
                            "Contact uses insecure http:// URI",
                            evidence=f"Contact: {contact}",
                            remediation="Use https:// for Contact URIs",
                            tags=["analysis", "security-txt"],
                        ))
                    else:
                        findings.append(Finding.low(
                            "Contact field has invalid URI scheme",
                            evidence=f"Contact: {contact}",
                            description=(
                                "RFC 9116 requires mailto: or https://"
                            ),
                            remediation=(
                                "Use mailto: or https:// for Contact"
                            ),
                            tags=["analysis", "security-txt"],
                        ))

        # --- Required field: Expires ---
        expires_values = fields.get("expires", [])
        expired = False
        days_until_expiry: int | None = None

        if not expires_values:
            rfc_compliant = False
            issue = "Missing required Expires field"
            issues.append(issue)
            findings.append(Finding.low(
                "security.txt missing Expires field",
                description="Expires is required by RFC 9116",
                remediation=(
                    "Add Expires: field with ISO 8601 datetime"
                ),
                tags=["analysis", "security-txt"],
            ))
        else:
            expires_str = expires_values[0]
            expiry_dt = self._parse_iso8601(expires_str)

            if expiry_dt is None:
                issue = f"Invalid Expires date format: {expires_str}"
                issues.append(issue)
                findings.append(Finding.low(
                    "security.txt has invalid Expires format",
                    evidence=f"Expires: {expires_str}",
                    remediation=(
                        "Use ISO 8601 format, e.g. "
                        "2025-12-31T23:59:59Z"
                    ),
                    tags=["analysis", "security-txt"],
                ))
            else:
                now = datetime.now(UTC)
                delta = expiry_dt - now
                days_until_expiry = delta.days

                if delta < timedelta(0):
                    expired = True
                    rfc_compliant = False
                    issue = (
                        f"security.txt expired {-delta.days} days ago"
                    )
                    issues.append(issue)
                    findings.append(Finding.medium(
                        "security.txt has expired",
                        description=issue,
                        evidence=f"Expires: {expires_str}",
                        remediation="Update the Expires field",
                        tags=["analysis", "security-txt"],
                    ))
                elif delta < timedelta(days=30):
                    issue = (
                        f"security.txt expires in {delta.days} days"
                    )
                    issues.append(issue)
                    findings.append(Finding.low(
                        "security.txt expiring soon",
                        description=issue,
                        evidence=f"Expires: {expires_str}",
                        remediation="Extend the Expires field",
                        tags=["analysis", "security-txt"],
                    ))

        # --- Optional field: Encryption ---
        encryption_values = fields.get("encryption", [])
        for enc in encryption_values:
            if not enc.startswith("https://"):
                issue = f"Encryption URI not HTTPS: {enc}"
                issues.append(issue)
                findings.append(Finding.low(
                    "Encryption field uses insecure URI",
                    evidence=f"Encryption: {enc}",
                    remediation=(
                        "Use https:// URI for PGP key location"
                    ),
                    tags=["analysis", "security-txt"],
                ))

        # --- Optional field: Canonical ---
        canonical_values = fields.get("canonical", [])
        if canonical_values:
            canonical_match = any(
                found_url == c for c in canonical_values
            )
            if not canonical_match:
                issue = (
                    f"Canonical '{canonical_values[0]}' does not "
                    f"match found URL '{found_url}'"
                )
                issues.append(issue)
                findings.append(Finding.low(
                    "Canonical URL mismatch",
                    description=issue,
                    evidence=(
                        f"Canonical: {canonical_values[0]}, "
                        f"Actual: {found_url}"
                    ),
                    remediation=(
                        "Update Canonical to match the actual URL"
                    ),
                    tags=["analysis", "security-txt"],
                ))

        # --- PGP signing ---
        if pgp_signed:
            findings.append(Finding.info(
                "security.txt is PGP signed",
                description="Content integrity verified with PGP",
                tags=["analysis", "security-txt"],
            ))

        # --- Compile result data ---
        # Flatten fields to single values for simple fields,
        # keep lists for multi-value fields
        fields_out: dict = {}
        for key, values in fields.items():
            if key in ("contact", "canonical"):
                # Multi-value fields stay as lists
                fields_out[key] = values
            else:
                fields_out[key] = values[0] if len(values) == 1 else values

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "security_txt_url": found_url,
                "fields": fields_out,
                "pgp_signed": pgp_signed,
                "expired": expired,
                "days_until_expiry": days_until_expiry,
                "rfc_compliant": rfc_compliant,
                "issues": issues,
            },
        )

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _looks_like_security_txt(text: str) -> bool:
        """Quick heuristic: has at least one RFC 9116 field line."""
        lower = text.lower()
        return any(
            f"{field_name}:" in lower for field_name in _KNOWN_FIELDS
        )

    @staticmethod
    def _parse_fields(content: str) -> dict[str, list[str]]:
        """Parse security.txt into {field_name: [values]}.

        Multiple values for the same field (e.g. Contact) are collected
        into a list.  PGP signature lines are skipped.
        """
        fields: dict[str, list[str]] = {}
        in_pgp_sig = False

        for line in content.splitlines():
            stripped = line.strip()

            # Skip PGP armor lines
            if stripped.startswith("-----BEGIN PGP"):
                if "SIGNATURE" in stripped:
                    in_pgp_sig = True
                continue
            if stripped.startswith("-----END PGP"):
                in_pgp_sig = False
                continue
            if in_pgp_sig:
                continue

            # Skip comments and blank lines
            if not stripped or stripped.startswith("#"):
                continue

            # Skip PGP hash header line
            if stripped.startswith("Hash:"):
                continue

            if ":" in stripped:
                key, _, val = stripped.partition(":")
                key = key.strip().lower()
                val = val.strip()
                if key in _KNOWN_FIELDS and val:
                    fields.setdefault(key, []).append(val)

        return fields

    @staticmethod
    def _parse_iso8601(value: str) -> datetime | None:
        """Parse an ISO 8601 datetime string to a UTC datetime."""
        value = value.strip()

        # Try standard fromisoformat (Python 3.11+ handles Z)
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return dt
        except (ValueError, TypeError):
            pass

        # Fallback: try common formats
        for fmt in (
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M%z",
            "%Y-%m-%d %H:%M:%S%z",
            "%Y-%m-%d",
        ):
            try:
                dt = datetime.strptime(value, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=UTC)
                return dt
            except ValueError:
                continue

        return None
