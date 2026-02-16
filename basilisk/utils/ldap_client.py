"""LDAP client — AD enumeration via ldap3."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class LdapUser:
    """Represents an AD user."""

    username: str
    dn: str = ""
    display_name: str = ""
    email: str = ""
    description: str = ""
    enabled: bool = True
    admin: bool = False
    spn: list[str] = field(default_factory=list)
    no_preauth: bool = False  # AS-REP roastable


@dataclass
class LdapGroup:
    """Represents an AD group."""

    name: str
    dn: str = ""
    members: list[str] = field(default_factory=list)
    description: str = ""


@dataclass
class LdapComputer:
    """Represents an AD computer."""

    name: str
    dn: str = ""
    os: str = ""
    os_version: str = ""
    dns_hostname: str = ""


class LdapClient:
    """Async LDAP client for Active Directory enumeration.

    Wraps ldap3 (synchronous) via asyncio.to_thread().
    """

    def __init__(self, timeout: float = 10.0) -> None:
        self._timeout = timeout
        self._conn: object | None = None
        self._base_dn: str = ""
        self._domain: str = ""

    async def connect(
        self, host: str, port: int = 389, *, use_ssl: bool = False,
    ) -> bool:
        """Connect to an LDAP server."""
        try:
            result = await asyncio.to_thread(
                self._sync_connect, host, port, use_ssl, self._timeout,
            )
            self._conn = result
            return result is not None
        except Exception:
            logger.exception("LDAP connect to %s:%d failed", host, port)
            return False

    async def bind(self, username: str, password: str, domain: str = "") -> bool:
        """Authenticate with username/password."""
        if not self._conn:
            return False
        self._domain = domain
        self._base_dn = self._domain_to_dn(domain) if domain else ""
        try:
            return await asyncio.to_thread(
                self._sync_bind, self._conn, username, password, domain,
            )
        except Exception:
            logger.exception("LDAP bind failed for %s", username)
            return False

    async def anonymous_bind(self) -> bool:
        """Attempt anonymous LDAP bind."""
        if not self._conn:
            return False
        try:
            return await asyncio.to_thread(self._sync_anonymous_bind, self._conn)
        except Exception:
            return False

    async def get_base_dn(self) -> str:
        """Get the base DN from RootDSE."""
        if self._base_dn:
            return self._base_dn
        if not self._conn:
            return ""
        try:
            self._base_dn = await asyncio.to_thread(
                self._sync_get_base_dn, self._conn,
            )
            return self._base_dn
        except Exception:
            return ""

    async def get_users(self, base_dn: str = "") -> list[LdapUser]:
        """Enumerate all AD users."""
        dn = base_dn or self._base_dn
        if not self._conn or not dn:
            return []
        try:
            return await asyncio.to_thread(
                self._sync_get_users, self._conn, dn,
            )
        except Exception:
            logger.exception("LDAP user enumeration failed")
            return []

    async def get_groups(self, base_dn: str = "") -> list[LdapGroup]:
        """Enumerate all AD groups."""
        dn = base_dn or self._base_dn
        if not self._conn or not dn:
            return []
        try:
            return await asyncio.to_thread(
                self._sync_get_groups, self._conn, dn,
            )
        except Exception:
            logger.exception("LDAP group enumeration failed")
            return []

    async def get_computers(self, base_dn: str = "") -> list[LdapComputer]:
        """Enumerate all AD computers."""
        dn = base_dn or self._base_dn
        if not self._conn or not dn:
            return []
        try:
            return await asyncio.to_thread(
                self._sync_get_computers, self._conn, dn,
            )
        except Exception:
            logger.exception("LDAP computer enumeration failed")
            return []

    async def get_domain_admins(self, base_dn: str = "") -> list[str]:
        """Get members of Domain Admins group."""
        dn = base_dn or self._base_dn
        if not self._conn or not dn:
            return []
        try:
            return await asyncio.to_thread(
                self._sync_get_domain_admins, self._conn, dn,
            )
        except Exception:
            return []

    async def get_spns(self, base_dn: str = "") -> list[LdapUser]:
        """Get users with Service Principal Names (for Kerberoasting)."""
        dn = base_dn or self._base_dn
        if not self._conn or not dn:
            return []
        try:
            return await asyncio.to_thread(
                self._sync_get_spns, self._conn, dn,
            )
        except Exception:
            return []

    async def get_asrep_roastable(self, base_dn: str = "") -> list[LdapUser]:
        """Get users without Kerberos pre-authentication."""
        dn = base_dn or self._base_dn
        if not self._conn or not dn:
            return []
        try:
            return await asyncio.to_thread(
                self._sync_get_asrep_roastable, self._conn, dn,
            )
        except Exception:
            return []

    async def search(
        self, base_dn: str, filter_str: str,
        attributes: list[str] | None = None,
    ) -> list[dict]:
        """Run a raw LDAP search."""
        if not self._conn:
            return []
        try:
            return await asyncio.to_thread(
                self._sync_search, self._conn, base_dn, filter_str,
                attributes or ["*"],
            )
        except Exception:
            return []

    async def close(self) -> None:
        """Close the LDAP connection."""
        if self._conn:
            with contextlib.suppress(Exception):
                await asyncio.to_thread(self._sync_close, self._conn)
            self._conn = None

    @staticmethod
    def _domain_to_dn(domain: str) -> str:
        """Convert domain.local to DC=domain,DC=local."""
        return ",".join(f"DC={part}" for part in domain.split("."))

    # ------------------------------------------------------------------
    # Synchronous ldap3 wrappers
    # ------------------------------------------------------------------

    @staticmethod
    def _sync_connect(host: str, port: int, use_ssl: bool, timeout: float) -> object:
        try:
            from ldap3 import Connection, Server
            server = Server(host, port=port, use_ssl=use_ssl, connect_timeout=timeout)
            conn = Connection(server, auto_bind=False, receive_timeout=timeout)
            conn.open()
            return conn
        except ImportError as exc:
            raise ImportError(
                "ldap3 is required for LDAP operations. "
                "Install with: pip install 'basilisk[offensive]'"
            ) from exc

    @staticmethod
    def _sync_bind(conn: object, username: str, password: str, domain: str) -> bool:
        try:
            if domain:
                conn.user = f"{domain}\\{username}"  # type: ignore[union-attr]
            else:
                conn.user = username  # type: ignore[union-attr]
            conn.password = password  # type: ignore[union-attr]
            return conn.bind()  # type: ignore[union-attr]
        except Exception:
            return False

    @staticmethod
    def _sync_anonymous_bind(conn: object) -> bool:
        try:
            conn.user = ""  # type: ignore[union-attr]
            conn.password = ""  # type: ignore[union-attr]
            return conn.bind()  # type: ignore[union-attr]
        except Exception:
            return False

    @staticmethod
    def _sync_get_base_dn(conn: object) -> str:
        try:
            conn.search(  # type: ignore[union-attr]
                "", "(objectClass=*)", search_scope="BASE",
                attributes=["defaultNamingContext"],
            )
            if conn.entries:  # type: ignore[union-attr]
                return str(conn.entries[0].defaultNamingContext)  # type: ignore[union-attr]
        except Exception:
            pass
        return ""

    @staticmethod
    def _sync_search(
        conn: object, base_dn: str, filter_str: str, attributes: list[str],
    ) -> list[dict]:
        results = []
        try:
            from ldap3 import SUBTREE
            conn.search(  # type: ignore[union-attr]
                base_dn, filter_str, search_scope=SUBTREE,
                attributes=attributes,
            )
            for entry in conn.entries:  # type: ignore[union-attr]
                results.append({
                    "dn": str(entry.entry_dn),
                    **{attr: str(entry[attr]) for attr in attributes if attr in entry},
                })
        except Exception:
            pass
        return results

    @staticmethod
    def _sync_get_users(conn: object, base_dn: str) -> list[LdapUser]:
        users = []
        try:
            from ldap3 import SUBTREE
            conn.search(  # type: ignore[union-attr]
                base_dn,
                "(&(objectCategory=person)(objectClass=user))",
                search_scope=SUBTREE,
                attributes=[
                    "sAMAccountName", "displayName", "mail", "description",
                    "userAccountControl", "servicePrincipalName", "memberOf",
                ],
            )
            for entry in conn.entries:  # type: ignore[union-attr]
                has_uac = hasattr(entry, "userAccountControl")
                uac = int(str(entry.userAccountControl)) if has_uac else 0
                users.append(LdapUser(
                    username=str(entry.sAMAccountName),
                    dn=str(entry.entry_dn),
                    display_name=str(getattr(entry, "displayName", "")),
                    email=str(getattr(entry, "mail", "")),
                    description=str(getattr(entry, "description", "")),
                    enabled=not bool(uac & 0x2),
                    spn=(
                        list(entry.servicePrincipalName)
                        if hasattr(entry, "servicePrincipalName") else []
                    ),
                    no_preauth=bool(uac & 0x400000),
                ))
        except Exception:
            pass
        return users

    @staticmethod
    def _sync_get_groups(conn: object, base_dn: str) -> list[LdapGroup]:
        groups = []
        try:
            from ldap3 import SUBTREE
            conn.search(  # type: ignore[union-attr]
                base_dn,
                "(objectClass=group)",
                search_scope=SUBTREE,
                attributes=["cn", "description", "member"],
            )
            for entry in conn.entries:  # type: ignore[union-attr]
                groups.append(LdapGroup(
                    name=str(entry.cn),
                    dn=str(entry.entry_dn),
                    members=list(entry.member) if hasattr(entry, "member") else [],
                    description=str(getattr(entry, "description", "")),
                ))
        except Exception:
            pass
        return groups

    @staticmethod
    def _sync_get_computers(conn: object, base_dn: str) -> list[LdapComputer]:
        computers = []
        try:
            from ldap3 import SUBTREE
            conn.search(  # type: ignore[union-attr]
                base_dn,
                "(objectClass=computer)",
                search_scope=SUBTREE,
                attributes=[
                    "cn", "operatingSystem", "operatingSystemVersion",
                    "dNSHostName",
                ],
            )
            for entry in conn.entries:  # type: ignore[union-attr]
                computers.append(LdapComputer(
                    name=str(entry.cn),
                    dn=str(entry.entry_dn),
                    os=str(getattr(entry, "operatingSystem", "")),
                    os_version=str(getattr(entry, "operatingSystemVersion", "")),
                    dns_hostname=str(getattr(entry, "dNSHostName", "")),
                ))
        except Exception:
            pass
        return computers

    @staticmethod
    def _sync_get_domain_admins(conn: object, base_dn: str) -> list[str]:
        try:
            from ldap3 import SUBTREE
            conn.search(  # type: ignore[union-attr]
                base_dn,
                "(&(objectClass=group)(cn=Domain Admins))",
                search_scope=SUBTREE,
                attributes=["member"],
            )
            if conn.entries:  # type: ignore[union-attr]
                return list(conn.entries[0].member)  # type: ignore[union-attr]
        except Exception:
            pass
        return []

    @staticmethod
    def _sync_get_spns(conn: object, base_dn: str) -> list[LdapUser]:
        users = []
        try:
            from ldap3 import SUBTREE
            conn.search(  # type: ignore[union-attr]
                base_dn,
                "(&(objectClass=user)(servicePrincipalName=*)"
                "(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                search_scope=SUBTREE,
                attributes=["sAMAccountName", "servicePrincipalName"],
            )
            for entry in conn.entries:  # type: ignore[union-attr]
                users.append(LdapUser(
                    username=str(entry.sAMAccountName),
                    dn=str(entry.entry_dn),
                    spn=list(entry.servicePrincipalName),
                ))
        except Exception:
            pass
        return users

    @staticmethod
    def _sync_get_asrep_roastable(conn: object, base_dn: str) -> list[LdapUser]:
        users = []
        try:
            from ldap3 import SUBTREE
            conn.search(  # type: ignore[union-attr]
                base_dn,
                "(&(objectClass=user)"
                "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
                "(!(objectClass=computer)))",
                search_scope=SUBTREE,
                attributes=["sAMAccountName"],
            )
            for entry in conn.entries:  # type: ignore[union-attr]
                users.append(LdapUser(
                    username=str(entry.sAMAccountName),
                    dn=str(entry.entry_dn),
                    no_preauth=True,
                ))
        except Exception:
            pass
        return users

    @staticmethod
    def _sync_close(conn: object) -> None:
        with contextlib.suppress(Exception):
            conn.unbind()  # type: ignore[union-attr]
