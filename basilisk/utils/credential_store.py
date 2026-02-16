"""Credential store — central repository for discovered credentials."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import StrEnum

logger = logging.getLogger(__name__)


class SecretType(StrEnum):
    PASSWORD = "password"
    NTLM_HASH = "ntlm_hash"
    SSH_KEY = "ssh_key"
    KERBEROS_TICKET = "kerberos_ticket"
    TOKEN = "token"
    API_KEY = "api_key"


@dataclass
class Credential:
    """A single discovered credential."""

    username: str
    secret: str
    secret_type: SecretType = SecretType.PASSWORD
    source: str = ""        # plugin that found it
    target: str = ""        # host/service it's for
    domain: str = ""        # AD domain if applicable
    verified: bool = False
    tags: list[str] = field(default_factory=list)

    @property
    def identity(self) -> str:
        """Full identity string: domain\\user or user."""
        if self.domain:
            return f"{self.domain}\\{self.username}"
        return self.username

    def as_dict(self) -> dict:
        return {
            "username": self.username,
            "secret_type": self.secret_type.value,
            "source": self.source,
            "target": self.target,
            "domain": self.domain,
            "verified": self.verified,
        }


class CredentialStore:
    """Central store for credentials discovered during an engagement.

    Thread-safe for concurrent plugin access via simple list append.
    """

    def __init__(self) -> None:
        self._creds: list[Credential] = []

    def add(self, cred: Credential) -> None:
        """Add a credential, deduplicating by (user, secret, target)."""
        for existing in self._creds:
            if (
                existing.username == cred.username
                and existing.secret == cred.secret
                and existing.target == cred.target
            ):
                if cred.verified and not existing.verified:
                    existing.verified = True
                return
        self._creds.append(cred)
        logger.info(
            "Credential added: %s@%s (%s) from %s",
            cred.username, cred.target, cred.secret_type.value, cred.source,
        )

    def add_many(self, creds: list[Credential]) -> int:
        """Add multiple credentials. Returns count of newly added."""
        before = len(self._creds)
        for c in creds:
            self.add(c)
        return len(self._creds) - before

    def get_for_target(self, target: str) -> list[Credential]:
        """Get all credentials for a specific target."""
        return [c for c in self._creds if c.target == target or not c.target]

    def get_by_type(self, secret_type: SecretType) -> list[Credential]:
        """Get all credentials of a specific type."""
        return [c for c in self._creds if c.secret_type == secret_type]

    def get_verified(self) -> list[Credential]:
        """Get all verified credentials."""
        return [c for c in self._creds if c.verified]

    def mark_verified(self, username: str, target: str) -> None:
        """Mark a credential as verified."""
        for c in self._creds:
            if c.username == username and c.target == target:
                c.verified = True

    def get_ntlm_hashes(self) -> list[Credential]:
        """Get all NTLM hash credentials (for PTH attacks)."""
        return self.get_by_type(SecretType.NTLM_HASH)

    def get_passwords(self) -> list[Credential]:
        """Get all password credentials."""
        return self.get_by_type(SecretType.PASSWORD)

    @property
    def all(self) -> list[Credential]:
        return list(self._creds)

    def __len__(self) -> int:
        return len(self._creds)

    def as_list(self) -> list[dict]:
        """Serialize all creds (secrets redacted) for reporting."""
        return [c.as_dict() for c in self._creds]
