"""SMB client — async wrapper over impacket for SMB operations."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class SmbShare:
    """Represents an SMB share."""

    name: str
    type: str = ""
    comment: str = ""
    readable: bool = False
    writable: bool = False


@dataclass
class SmbFile:
    """Represents a file on an SMB share."""

    name: str
    size: int = 0
    is_directory: bool = False
    path: str = ""


@dataclass
class SmbConnection:
    """Represents an active SMB connection."""

    host: str
    port: int = 445
    username: str = ""
    domain: str = ""
    authenticated: bool = False
    _conn: object | None = None  # impacket SMBConnection


class SmbClient:
    """Async SMB client wrapping impacket.

    All impacket calls run in threads via asyncio.to_thread() since
    impacket is synchronous.
    """

    def __init__(self, timeout: float = 10.0) -> None:
        self._timeout = timeout
        self._connections: dict[str, SmbConnection] = {}

    async def connect(
        self, host: str, port: int = 445, *, timeout: float | None = None,
    ) -> SmbConnection:
        """Establish an SMB connection."""
        timeout = timeout or self._timeout
        try:
            conn_obj = await asyncio.to_thread(
                self._sync_connect, host, port, timeout,
            )
            connection = SmbConnection(
                host=host, port=port, _conn=conn_obj,
            )
            self._connections[host] = connection
            return connection
        except Exception:
            logger.exception("SMB connect to %s:%d failed", host, port)
            raise

    async def authenticate(
        self, conn: SmbConnection, username: str, password: str,
        domain: str = "",
    ) -> bool:
        """Authenticate with username/password."""
        try:
            result = await asyncio.to_thread(
                self._sync_login, conn._conn, username, password, domain,
            )
            conn.authenticated = result
            conn.username = username
            conn.domain = domain
            return result
        except Exception:
            logger.exception("SMB auth failed for %s@%s", username, conn.host)
            return False

    async def authenticate_hash(
        self, conn: SmbConnection, username: str, nthash: str,
        domain: str = "",
    ) -> bool:
        """Authenticate with NTLM hash (pass-the-hash)."""
        try:
            result = await asyncio.to_thread(
                self._sync_login_hash, conn._conn, username, nthash, domain,
            )
            conn.authenticated = result
            conn.username = username
            conn.domain = domain
            return result
        except Exception:
            logger.exception("SMB PTH failed for %s@%s", username, conn.host)
            return False

    async def null_session(self, conn: SmbConnection) -> bool:
        """Attempt null session authentication."""
        return await self.authenticate(conn, "", "")

    async def guest_session(self, conn: SmbConnection) -> bool:
        """Attempt guest session authentication."""
        return await self.authenticate(conn, "Guest", "")

    async def list_shares(self, conn: SmbConnection) -> list[SmbShare]:
        """List available SMB shares."""
        if not conn._conn:
            return []
        try:
            shares = await asyncio.to_thread(
                self._sync_list_shares, conn._conn,
            )
            return shares
        except Exception:
            logger.exception("SMB list shares failed on %s", conn.host)
            return []

    async def list_files(
        self, conn: SmbConnection, share: str, path: str = "/",
    ) -> list[SmbFile]:
        """List files in an SMB share directory."""
        if not conn._conn:
            return []
        try:
            files = await asyncio.to_thread(
                self._sync_list_files, conn._conn, share, path,
            )
            return files
        except Exception:
            logger.debug("SMB list files failed: %s/%s", share, path)
            return []

    async def download_file(
        self, conn: SmbConnection, share: str, remote_path: str,
        local_path: str,
    ) -> bool:
        """Download a file from an SMB share."""
        if not conn._conn:
            return False
        try:
            return await asyncio.to_thread(
                self._sync_download, conn._conn, share, remote_path, local_path,
            )
        except Exception:
            logger.debug("SMB download failed: %s/%s", share, remote_path)
            return False

    async def upload_file(
        self, conn: SmbConnection, share: str, local_path: str,
        remote_path: str,
    ) -> bool:
        """Upload a file to an SMB share."""
        if not conn._conn:
            return False
        try:
            return await asyncio.to_thread(
                self._sync_upload, conn._conn, share, local_path, remote_path,
            )
        except Exception:
            logger.debug("SMB upload failed: %s/%s", share, remote_path)
            return False

    async def execute_command(
        self, conn: SmbConnection, command: str,
        method: str = "wmiexec",
    ) -> str:
        """Execute a command via SMB (wmiexec/smbexec/psexec)."""
        if not conn._conn:
            return ""
        try:
            return await asyncio.to_thread(
                self._sync_exec, conn._conn, command, method,
                conn.username, conn.domain,
            )
        except Exception:
            logger.exception("SMB exec via %s failed on %s", method, conn.host)
            return ""

    async def close(self, conn: SmbConnection) -> None:
        """Close an SMB connection."""
        if conn._conn:
            with contextlib.suppress(Exception):
                await asyncio.to_thread(self._sync_close, conn._conn)
        self._connections.pop(conn.host, None)

    async def close_all(self) -> None:
        """Close all connections."""
        for conn in list(self._connections.values()):
            await self.close(conn)

    # ------------------------------------------------------------------
    # Synchronous impacket wrappers (run in threads)
    # ------------------------------------------------------------------

    @staticmethod
    def _sync_connect(host: str, port: int, timeout: float) -> object:
        try:
            from impacket.smbconnection import SMBConnection
            conn = SMBConnection(host, host, sess_port=port, timeout=timeout)
            return conn
        except ImportError as exc:
            raise ImportError(
                "impacket is required for SMB operations. "
                "Install with: pip install 'basilisk[offensive]'"
            ) from exc

    @staticmethod
    def _sync_login(
        conn: object, username: str, password: str, domain: str,
    ) -> bool:
        try:
            conn.login(username, password, domain)  # type: ignore[union-attr]
            return True
        except Exception:
            return False

    @staticmethod
    def _sync_login_hash(
        conn: object, username: str, nthash: str, domain: str,
    ) -> bool:
        try:
            lmhash = "aad3b435b51404eeaad3b435b51404ee"
            conn.login(username, "", domain, lmhash=lmhash, nthash=nthash)  # type: ignore[union-attr]
            return True
        except Exception:
            return False

    @staticmethod
    def _sync_list_shares(conn: object) -> list[SmbShare]:
        shares = []
        try:
            raw_shares = conn.listShares()  # type: ignore[union-attr]
            for s in raw_shares:
                name = s["shi1_netname"][:-1]  # strip null terminator
                comment = s["shi1_remark"][:-1] if s["shi1_remark"] else ""
                shares.append(SmbShare(
                    name=name,
                    comment=comment,
                    type=str(s["shi1_type"]),
                ))
        except Exception:
            pass
        return shares

    @staticmethod
    def _sync_list_files(
        conn: object, share: str, path: str,
    ) -> list[SmbFile]:
        files = []
        try:
            raw_files = conn.listPath(share, path + "/*")  # type: ignore[union-attr]
            for f in raw_files:
                name = f.get_longname()
                if name in (".", ".."):
                    continue
                files.append(SmbFile(
                    name=name,
                    size=f.get_filesize(),
                    is_directory=f.is_directory() > 0,
                    path=f"{path}/{name}".replace("//", "/"),
                ))
        except Exception:
            pass
        return files

    @staticmethod
    def _sync_download(
        conn: object, share: str, remote_path: str, local_path: str,
    ) -> bool:
        try:
            with open(local_path, "wb") as f:
                conn.getFile(share, remote_path, f.write)  # type: ignore[union-attr]
            return True
        except Exception:
            return False

    @staticmethod
    def _sync_upload(
        conn: object, share: str, local_path: str, remote_path: str,
    ) -> bool:
        try:
            with open(local_path, "rb") as f:
                conn.putFile(share, remote_path, f.read)  # type: ignore[union-attr]
            return True
        except Exception:
            return False

    @staticmethod
    def _sync_exec(
        conn: object, command: str, method: str,
        username: str, domain: str,
    ) -> str:
        # Execution methods require separate impacket modules
        # This is a simplified interface; real implementation would
        # use wmiexec.py / smbexec.py / psexec.py from impacket
        logger.info("SMB exec via %s: %s", method, command[:80])
        return ""

    @staticmethod
    def _sync_close(conn: object) -> None:
        with contextlib.suppress(Exception):
            conn.close()  # type: ignore[union-attr]
