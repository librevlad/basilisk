"""WAF vendor fingerprint database — profiles with known bypass strategies.

Each WafProfile describes a WAF vendor's known weaknesses: which encoding
techniques tend to bypass its rules, which headers may skip inspection, etc.

Used by :class:`basilisk.utils.waf_bypass.WafBypassEngine` to select
encoding strategies based on detected WAF type.
"""

from __future__ import annotations

from dataclasses import dataclass, field


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
