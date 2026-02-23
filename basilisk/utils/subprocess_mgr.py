"""Subprocess manager — async subprocess execution with timeout and fallback."""

from __future__ import annotations

import asyncio
import logging
import shutil
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class SubprocessResult:
    """Result of a subprocess execution."""

    stdout: str = ""
    stderr: str = ""
    returncode: int = -1
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


class SubprocessManager:
    """Async subprocess wrapper with timeout, binary checks, and helpers.

    All commands are run via asyncio.create_subprocess_exec for safety.
    """

    def __init__(self, default_timeout: float = 60.0) -> None:
        self._default_timeout = default_timeout
        self._binary_cache: dict[str, bool] = {}

    async def run(
        self, cmd: list[str], *, timeout: float | None = None,
        cwd: str | None = None, env: dict[str, str] | None = None,
        stdin_data: str | None = None,
    ) -> SubprocessResult:
        """Run a command and return the result."""
        timeout = timeout or self._default_timeout
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=env,
            )
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(
                        stdin_data.encode() if stdin_data else None,
                    ),
                    timeout=timeout,
                )
                return SubprocessResult(
                    stdout=stdout_bytes.decode("utf-8", errors="replace"),
                    stderr=stderr_bytes.decode("utf-8", errors="replace"),
                    returncode=proc.returncode or 0,
                )
            except TimeoutError:
                proc.kill()
                await proc.wait()
                return SubprocessResult(timed_out=True)
        except FileNotFoundError:
            return SubprocessResult(
                stderr=f"Command not found: {cmd[0]}",
                returncode=127,
            )
        except Exception as e:
            return SubprocessResult(stderr=str(e), returncode=-1)

    def is_available(self, binary: str) -> bool:
        """Check if a binary is available on PATH."""
        if binary in self._binary_cache:
            return self._binary_cache[binary]
        result = shutil.which(binary) is not None
        self._binary_cache[binary] = result
        return result

    async def run_nmap(
        self, target: str, *, ports: str = "-", args: list[str] | None = None,
        timeout: float = 300.0,
    ) -> SubprocessResult:
        """Run nmap with common defaults."""
        cmd = ["nmap", "-Pn", "-p", ports]
        if args:
            cmd.extend(args)
        cmd.append(target)
        return await self.run(cmd, timeout=timeout)

    async def run_hashcat(
        self, hash_file: str, mode: int, wordlist: str = "",
        *, rules: str = "", timeout: float = 600.0,
    ) -> SubprocessResult:
        """Run hashcat for hash cracking."""
        cmd = ["hashcat", "-m", str(mode), hash_file]
        if wordlist:
            cmd.append(wordlist)
        else:
            cmd.extend(["-a", "3"])  # brute force mode
        if rules:
            cmd.extend(["-r", rules])
        cmd.append("--force")
        return await self.run(cmd, timeout=timeout)

    async def run_john(
        self, hash_file: str, *, wordlist: str = "",
        format_type: str = "", timeout: float = 600.0,
    ) -> SubprocessResult:
        """Run John the Ripper for hash cracking."""
        cmd = ["john"]
        if wordlist:
            cmd.extend(["--wordlist=" + wordlist])
        if format_type:
            cmd.extend(["--format=" + format_type])
        cmd.append(hash_file)
        return await self.run(cmd, timeout=timeout)

    async def run_responder(
        self, interface: str, *, timeout: float = 120.0,
    ) -> SubprocessResult:
        """Run Responder for NTLM capture."""
        cmd = ["responder", "-I", interface, "-w", "-r", "-d"]
        return await self.run(cmd, timeout=timeout)

    async def run_impacket_tool(
        self, tool: str, args: list[str], *, timeout: float = 60.0,
    ) -> SubprocessResult:
        """Run an impacket tool (e.g., secretsdump.py, getTGT.py)."""
        # Try both module and script forms
        cmd = [tool] + args
        result = await self.run(cmd, timeout=timeout)
        if result.returncode == 127:
            # Try as python module
            cmd = ["python3", "-m", f"impacket.examples.{tool}"] + args
            result = await self.run(cmd, timeout=timeout)
        return result
