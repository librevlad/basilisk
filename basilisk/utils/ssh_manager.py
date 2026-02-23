"""SSH manager — async SSH operations via asyncssh."""

from __future__ import annotations

import contextlib
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class SshSession:
    """Represents an active SSH session."""

    host: str
    port: int = 22
    username: str = ""
    _conn: object | None = None  # asyncssh.SSHClientConnection
    _alive: bool = True

    @property
    def alive(self) -> bool:
        return self._alive and self._conn is not None


class SshManager:
    """Async SSH client for remote command execution and file transfer.

    Uses asyncssh for native async SSH support.
    """

    def __init__(self, timeout: float = 10.0) -> None:
        self._timeout = timeout
        self._sessions: dict[str, SshSession] = {}

    async def connect_password(
        self, host: str, username: str, password: str,
        port: int = 22, *, timeout: float | None = None,
    ) -> SshSession | None:
        """Connect via SSH with password authentication."""
        timeout = timeout or self._timeout
        try:
            import asyncssh
            conn = await asyncssh.connect(
                host, port=port, username=username, password=password,
                known_hosts=None, connect_timeout=timeout,
            )
            session = SshSession(
                host=host, port=port, username=username, _conn=conn,
            )
            self._sessions[f"{host}:{port}"] = session
            return session
        except ImportError as exc:
            raise ImportError(
                "asyncssh is required for SSH operations. "
                "Install with: pip install 'basilisk[offensive]'"
            ) from exc
        except Exception:
            logger.debug("SSH password auth failed: %s@%s:%d", username, host, port)
            return None

    async def connect_key(
        self, host: str, username: str, key_path: str,
        port: int = 22, *, passphrase: str = "", timeout: float | None = None,
    ) -> SshSession | None:
        """Connect via SSH with key-based authentication."""
        timeout = timeout or self._timeout
        try:
            import asyncssh
            key = asyncssh.read_private_key(key_path, passphrase or None)
            conn = await asyncssh.connect(
                host, port=port, username=username,
                client_keys=[key], known_hosts=None,
                connect_timeout=timeout,
            )
            session = SshSession(
                host=host, port=port, username=username, _conn=conn,
            )
            self._sessions[f"{host}:{port}"] = session
            return session
        except ImportError as exc:
            raise ImportError(
                "asyncssh is required for SSH operations. "
                "Install with: pip install 'basilisk[offensive]'"
            ) from exc
        except Exception:
            logger.debug("SSH key auth failed: %s@%s:%d", username, host, port)
            return None

    async def execute(
        self, session: SshSession, command: str, *, timeout: float = 30.0,
    ) -> tuple[str, str, int]:
        """Execute a command and return (stdout, stderr, return_code)."""
        if not session.alive or session._conn is None:
            return "", "Session not alive", -1
        try:
            import asyncssh
            result = await asyncssh.wait_for(
                session._conn.run(command),  # type: ignore[union-attr]
                timeout=timeout,
            )
            return (
                result.stdout or "",
                result.stderr or "",
                result.exit_status or 0,
            )
        except Exception as e:
            return "", str(e), -1

    async def upload(
        self, session: SshSession, local_path: str, remote_path: str,
    ) -> bool:
        """Upload a file via SFTP."""
        if not session.alive or session._conn is None:
            return False
        try:
            async with session._conn.start_sftp_client() as sftp:  # type: ignore[union-attr]
                await sftp.put(local_path, remote_path)
            return True
        except Exception:
            logger.debug("SSH upload failed: %s -> %s", local_path, remote_path)
            return False

    async def download(
        self, session: SshSession, remote_path: str, local_path: str,
    ) -> bool:
        """Download a file via SFTP."""
        if not session.alive or session._conn is None:
            return False
        try:
            async with session._conn.start_sftp_client() as sftp:  # type: ignore[union-attr]
                await sftp.get(remote_path, local_path)
            return True
        except Exception:
            logger.debug("SSH download failed: %s -> %s", remote_path, local_path)
            return False

    async def port_forward(
        self, session: SshSession, local_port: int,
        remote_host: str, remote_port: int,
    ) -> object | None:
        """Set up local port forwarding."""
        if not session.alive or session._conn is None:
            return None
        try:
            listener = await session._conn.forward_local_port(  # type: ignore[union-attr]
                "", local_port, remote_host, remote_port,
            )
            logger.info(
                "SSH port forward: localhost:%d -> %s:%d via %s",
                local_port, remote_host, remote_port, session.host,
            )
            return listener
        except Exception:
            logger.debug("SSH port forward failed")
            return None

    async def close(self, session: SshSession) -> None:
        """Close an SSH session."""
        if session._conn:
            with contextlib.suppress(Exception):
                session._conn.close()  # type: ignore[union-attr]
        session._alive = False
        self._sessions.pop(f"{session.host}:{session.port}", None)

    async def close_all(self) -> None:
        """Close all SSH sessions."""
        for session in list(self._sessions.values()):
            await self.close(session)
