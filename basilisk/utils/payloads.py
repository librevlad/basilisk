"""Adaptive payload engine — context-aware generation, mutation, encoding chains.

Central payload database with 489+ entries across 13 categories, loaded from
YAML files in ``basilisk/data/payloads/``.  Plugins call
``PayloadEngine.get(category, context)`` instead of maintaining their own
hardcoded lists.
"""

from __future__ import annotations

import functools
from dataclasses import dataclass, field
from enum import StrEnum
from urllib.parse import quote

from basilisk.data.loader import load_payload_defaults, load_payloads

# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------


class PayloadCategory(StrEnum):
    SQLI = "sqli"
    XSS = "xss"
    SSTI = "ssti"
    LFI = "lfi"
    RCE = "rce"
    SSRF = "ssrf"
    XXE = "xxe"
    CRLF = "crlf"
    OPEN_REDIRECT = "redirect"
    NOSQLI = "nosqli"
    HEADER_INJECTION = "header"
    JWT = "jwt"
    PROTOTYPE_POLLUTION = "pp"


class InjectionContext(StrEnum):
    """Where the payload will land."""
    QUERY_PARAM = "query"
    POST_BODY = "body"
    HEADER_VALUE = "header"
    JSON_VALUE = "json"
    XML_VALUE = "xml"
    PATH_SEGMENT = "path"
    COOKIE_VALUE = "cookie"
    HTML_ATTR = "html_attr"
    HTML_TAG = "html_tag"
    JS_STRING = "js_string"
    URL_FRAGMENT = "fragment"


class DbmsType(StrEnum):
    MYSQL = "mysql"
    POSTGRES = "postgres"
    MSSQL = "mssql"
    ORACLE = "oracle"
    SQLITE = "sqlite"
    GENERIC = "generic"


@dataclass(frozen=True)
class Payload:
    """Single payload with metadata."""
    value: str
    category: PayloadCategory
    context: InjectionContext = InjectionContext.QUERY_PARAM
    dbms: DbmsType = DbmsType.GENERIC
    waf_level: int = 0          # 0=no evasion, 1=light, 2=medium, 3=heavy
    blind: bool = False
    time_delay: float = 0.0     # expected delay for time-based
    description: str = ""
    tags: tuple[str, ...] = ()


@dataclass
class MutationResult:
    """Result of mutating a payload."""
    original: str
    variants: list[str] = field(default_factory=list)
    technique: str = ""


# ---------------------------------------------------------------------------
# Payload database — loaded from YAML on first access
# ---------------------------------------------------------------------------


def _build_category(cat: PayloadCategory) -> list[Payload]:
    """Build list[Payload] for one category from its YAML file."""
    raw_payloads = load_payloads(cat.value)
    defaults = load_payload_defaults(cat.value)

    default_context = defaults.get("context", "query")
    default_dbms = defaults.get("dbms", "generic")
    default_waf = defaults.get("waf_level", 0)
    default_blind = defaults.get("blind", False)
    default_delay = defaults.get("time_delay", 0.0)

    result: list[Payload] = []
    for item in raw_payloads:
        result.append(Payload(
            value=str(item["value"]),
            category=cat,
            context=InjectionContext(item.get("context", default_context)),
            dbms=DbmsType(item.get("dbms", default_dbms)),
            waf_level=item.get("waf_level", default_waf),
            blind=item.get("blind", default_blind),
            time_delay=float(item.get("time_delay", default_delay)),
            description=item.get("description", ""),
            tags=tuple(item.get("tags", ())),
        ))
    return result


@functools.cache
def _get_payload_db() -> dict[PayloadCategory, list[Payload]]:
    """Load all payload YAML files and return the master dict.

    Cached permanently — only built once per process.
    """
    db: dict[PayloadCategory, list[Payload]] = {}
    for cat in PayloadCategory:
        db[cat] = _build_category(cat)
    return db


# Backward-compatible module-level alias used by export script and tests
_PAYLOAD_DB = _get_payload_db


# ---------------------------------------------------------------------------
# Mutation engine
# ---------------------------------------------------------------------------

class MutationEngine:
    """Generates payload variants via encoding and obfuscation."""

    @staticmethod
    def case_swap(payload: str) -> list[str]:
        """Generate case-swapped variants of SQL/HTML keywords."""
        keywords = [
            "SELECT", "UNION", "OR", "AND", "FROM", "WHERE", "ORDER",
            "GROUP", "INSERT", "UPDATE", "DELETE", "DROP", "EXEC",
            "SLEEP", "BENCHMARK", "WAITFOR",
            "script", "onerror", "onload", "alert", "javascript",
            "onclick", "onfocus", "onmouseover", "svg", "img", "iframe",
        ]
        variants = []
        upper = payload.upper()
        for kw in keywords:
            kw_upper = kw.upper()
            if kw_upper in upper:
                idx = upper.index(kw_upper)
                orig = payload[idx:idx + len(kw)]
                swapped = "".join(
                    c.upper() if i % 2 == 0 else c.lower()
                    for i, c in enumerate(orig)
                )
                if swapped != orig:
                    variants.append(payload[:idx] + swapped + payload[idx + len(kw):])
        return variants

    @staticmethod
    def comment_split(payload: str) -> list[str]:
        """Insert SQL comments within keywords."""
        keywords = ["OR", "AND", "SELECT", "UNION", "FROM", "WHERE"]
        variants = []
        upper = payload.upper()
        for kw in keywords:
            padded = f" {kw} "
            if padded in upper:
                idx = upper.index(padded)
                commented = f" {kw[0]}/**/{kw[1:]} "
                variants.append(payload[:idx] + commented + payload[idx + len(padded):])
        return variants

    @staticmethod
    def url_encode(payload: str, double: bool = False) -> str:
        """URL-encode special characters, optionally double-encode."""
        encoded = quote(payload, safe="")
        if double:
            encoded = quote(encoded, safe="")
        return encoded

    @staticmethod
    def null_byte_insert(payload: str) -> list[str]:
        """Insert null bytes at strategic positions."""
        variants = []
        if "'" in payload:
            variants.append(payload.replace("'", "%00'", 1))
        if " " in payload:
            variants.append(payload.replace(" ", "%00 ", 1))
        return variants

    @staticmethod
    def unicode_normalize(payload: str) -> list[str]:
        """Generate Unicode normalization bypass variants."""
        replacements = {
            "'": ["\u02bc", "\u2018", "\uff07"],
            '"': ["\u201c", "\uff02"],
            "<": ["\uff1c", "\u00ab"],
            ">": ["\uff1e", "\u00bb"],
            "/": ["\u2215", "\uff0f"],
        }
        variants = []
        for char, alts in replacements.items():
            if char in payload:
                for alt in alts:
                    variants.append(payload.replace(char, alt, 1))
        return variants

    @staticmethod
    def whitespace_variants(payload: str) -> list[str]:
        """Replace spaces with alternative whitespace."""
        alternatives = ["\t", "\n", "\r", "%09", "%0a", "%0d", "%0b", "%0c", "+", "/**/"]
        variants = []
        if " " in payload:
            for alt in alternatives:
                variants.append(payload.replace(" ", alt))
        return variants

    @staticmethod
    def space2comment(payload: str) -> str:
        """Replace spaces with SQL inline comments (sqlmap tamper: space2comment)."""
        return payload.replace(" ", "/**/")

    @staticmethod
    def between_bypass(payload: str) -> str:
        """Replace '>' with 'NOT BETWEEN 0 AND' (sqlmap tamper: between)."""
        import re
        result = payload
        result = re.sub(r"(\d+)\s*>\s*(\d+)", r"\1 NOT BETWEEN 0 AND \2", result)
        result = re.sub(r"(\d+)\s*=\s*(\d+)", r"\1 BETWEEN \2 AND \2", result)
        return result

    @staticmethod
    def charencode(payload: str) -> str:
        """Encode payload chars as CHAR() calls (sqlmap tamper: charencode)."""
        return "CONCAT(" + ",".join(f"CHAR({ord(c)})" for c in payload) + ")"

    @staticmethod
    def concat_bypass(payload: str) -> str:
        """Break string literals using CONCAT (sqlmap tamper: unmagicquotes)."""
        import re
        def _replace(m: re.Match) -> str:
            s = m.group(1)
            if len(s) < 2:
                return m.group(0)
            mid = len(s) // 2
            return f"CONCAT('{s[:mid]}','{s[mid:]}')"
        return re.sub(r"'([^']{2,})'", _replace, payload)

    @staticmethod
    def hex_encode(payload: str) -> str:
        """Encode string payload as hex (e.g. 0x...) for MySQL."""
        return "0x" + payload.encode().hex()

    @staticmethod
    def space2dash(payload: str) -> str:
        """Replace spaces with -- followed by newline (sqlmap tamper: space2dash)."""
        return payload.replace(" ", " --\n")

    @staticmethod
    def space2hash(payload: str) -> str:
        """Replace spaces with # followed by newline (MySQL) (sqlmap tamper: space2hash)."""
        return payload.replace(" ", " #\n")

    @staticmethod
    def percentage_encode(payload: str) -> str:
        """Insert % between characters (IDS evasion)."""
        return "%".join(payload)

    @classmethod
    def mutate(cls, payload: str, max_variants: int = 10) -> list[str]:
        """Generate up to max_variants mutations of a payload."""
        all_variants: list[str] = []
        all_variants.extend(cls.case_swap(payload))
        all_variants.extend(cls.comment_split(payload))
        all_variants.extend(cls.null_byte_insert(payload))
        all_variants.extend(cls.whitespace_variants(payload)[:3])
        all_variants.append(cls.url_encode(payload))
        all_variants.append(cls.url_encode(payload, double=True))
        all_variants.extend(cls.unicode_normalize(payload)[:2])
        # sqlmap-style tampers
        if " " in payload:
            all_variants.append(cls.space2comment(payload))
            all_variants.append(cls.space2dash(payload))
        if "'" in payload:
            concat = cls.concat_bypass(payload)
            if concat != payload:
                all_variants.append(concat)

        # Deduplicate and limit
        seen: set[str] = {payload}
        unique: list[str] = []
        for v in all_variants:
            if v not in seen:
                seen.add(v)
                unique.append(v)
        return unique[:max_variants]


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------

class PayloadEngine:
    """Adaptive payload selection and generation.

    Usage::

        engine = PayloadEngine()
        for p in engine.get(PayloadCategory.SQLI, dbms=DbmsType.MYSQL, max_waf=1):
            print(p.value)

        # With mutations
        for p in engine.get_with_mutations(PayloadCategory.XSS, max_variants=3):
            print(p.value, p.variants)
    """

    def __init__(self, custom_payloads: dict[PayloadCategory, list[Payload]] | None = None):
        self._db: dict[PayloadCategory, list[Payload]] = {}
        # Copy defaults
        for cat, payloads in _get_payload_db().items():
            self._db[cat] = list(payloads)
        # Add custom
        if custom_payloads:
            for cat, payloads in custom_payloads.items():
                if cat in self._db:
                    self._db[cat].extend(payloads)
                else:
                    self._db[cat] = list(payloads)

    @property
    def categories(self) -> list[PayloadCategory]:
        """Available payload categories."""
        return list(self._db.keys())

    def count(self, category: PayloadCategory | None = None) -> int:
        """Count payloads, optionally by category."""
        if category:
            return len(self._db.get(category, []))
        return sum(len(v) for v in self._db.values())

    def get(
        self,
        category: PayloadCategory,
        *,
        dbms: DbmsType | None = None,
        context: InjectionContext | None = None,
        max_waf: int = 3,
        blind_only: bool = False,
        limit: int = 0,
    ) -> list[Payload]:
        """Get payloads filtered by criteria.

        Args:
            category: Payload category (sqli, xss, etc.)
            dbms: Filter to specific DBMS (None = all)
            context: Filter to injection context (None = all)
            max_waf: Maximum WAF evasion level to include
            blind_only: Only return blind payloads
            limit: Max payloads to return (0 = all)
        """
        source = self._db.get(category, [])
        result: list[Payload] = []

        for p in source:
            if p.waf_level > max_waf:
                continue
            if dbms and p.dbms != DbmsType.GENERIC and p.dbms != dbms:
                continue
            if context and p.context != context:
                continue
            if blind_only and not p.blind:
                continue
            result.append(p)

        if limit > 0:
            result = result[:limit]
        return result

    def get_for_waf(
        self,
        category: PayloadCategory,
        waf_name: str,
        *,
        dbms: DbmsType | None = None,
    ) -> list[Payload]:
        """Get payloads optimized for a specific WAF.

        Returns WAF-evasion payloads first, then standard ones.
        """
        all_payloads = self.get(category, dbms=dbms, max_waf=3)
        # Sort: higher WAF level first for WAF-protected targets
        return sorted(all_payloads, key=lambda p: -p.waf_level)

    def get_with_mutations(
        self,
        category: PayloadCategory,
        *,
        dbms: DbmsType | None = None,
        max_variants: int = 5,
        limit: int = 0,
    ) -> list[tuple[Payload, list[str]]]:
        """Get payloads with mutation variants.

        Returns list of (payload, [variant1, variant2, ...]).
        """
        payloads = self.get(category, dbms=dbms, limit=limit)
        return [
            (p, MutationEngine.mutate(p.value, max_variants=max_variants))
            for p in payloads
        ]

    def smart_select(
        self,
        category: PayloadCategory,
        *,
        detected_waf: str | None = None,
        detected_dbms: DbmsType | None = None,
        detected_tech: list[str] | None = None,
        limit: int = 20,
    ) -> list[Payload]:
        """Context-aware payload selection based on discovered intelligence.

        Uses pipeline data (WAF type, DBMS, tech stack) to pick the most
        effective payloads. Falls back to generic if no context available.
        """
        max_waf = 0
        if detected_waf:
            max_waf = 3  # enable all evasion levels

        payloads = self.get(
            category,
            dbms=detected_dbms,
            max_waf=max_waf,
        )

        if detected_waf:
            # Prioritize WAF-evasion payloads
            payloads.sort(key=lambda p: -p.waf_level)

        if detected_dbms and category == PayloadCategory.SQLI:
            # Prioritize DBMS-specific payloads
            def dbms_score(p: Payload) -> int:
                if p.dbms == detected_dbms:
                    return 2
                if p.dbms == DbmsType.GENERIC:
                    return 1
                return 0
            payloads.sort(key=dbms_score, reverse=True)

        if detected_tech and category == PayloadCategory.SSTI:
            # Prioritize template engine-specific payloads
            tech_lower = [t.lower() for t in detected_tech]
            if any(t in tech_lower for t in ("jinja2", "flask", "django", "python")):
                payloads.sort(key=lambda p: "jinja" in p.description.lower(), reverse=True)
            elif any(t in tech_lower for t in ("java", "spring", "thymeleaf")):
                payloads.sort(key=lambda p: "spring" in p.description.lower(), reverse=True)
            elif any(t in tech_lower for t in ("twig", "symfony", "php")):
                payloads.sort(key=lambda p: "twig" in p.description.lower(), reverse=True)
            elif any(t in tech_lower for t in ("express", "node", "ejs", "pug", "handlebars")):
                payloads.sort(
                    key=lambda p: any(
                        e in p.description.lower() for e in ("ejs", "pug", "handlebars", "node")
                    ), reverse=True,
                )

        if category == PayloadCategory.JWT:
            # Prioritize based on common JWT attack surface
            def jwt_score(p: Payload) -> int:
                if "alg:none" in p.description.lower():
                    return 5  # Most likely to succeed
                if "algorithm_confusion" in p.tags:
                    return 4
                if "kid_injection" in p.tags:
                    return 3
                if "brute" in p.tags:
                    return 2
                return 1
            payloads.sort(key=jwt_score, reverse=True)

        if detected_tech and category == PayloadCategory.PROTOTYPE_POLLUTION:
            tech_lower = [t.lower() for t in detected_tech]
            if any(t in tech_lower for t in ("express", "node", "fastify")):
                payloads.sort(
                    key=lambda p: "server" in p.description.lower()
                    or "express" in p.description.lower(),
                    reverse=True,
                )

        return payloads[:limit]

    def mutate(
        self,
        payload: str,
        waf_engine: object = None,
        *,
        max_variants: int = 10,
    ) -> list[str]:
        """Generate WAF-bypass variants of a payload using WafBypassEngine.

        Falls back to MutationEngine if no WAF engine provided.
        """
        if waf_engine and waf_engine.waf_detected:
            variants = waf_engine.encode(payload)
            # Also add MutationEngine variants
            variants.extend(MutationEngine.mutate(payload, max_variants=max_variants // 2))
        else:
            variants = MutationEngine.mutate(payload, max_variants=max_variants)
        # Deduplicate preserving order
        seen: set[str] = {payload}
        unique: list[str] = []
        for v in variants:
            if v not in seen:
                seen.add(v)
                unique.append(v)
        return unique[:max_variants]

    def get_with_bypass(
        self,
        category: PayloadCategory,
        context: InjectionContext | None = None,
        waf_engine: object = None,
        *,
        dbms: DbmsType | None = None,
        max_variants: int = 5,
        limit: int = 0,
    ) -> list[tuple[Payload, list[str]]]:
        """Get payloads with WAF-bypass mutations.

        Combines base payloads with WafBypassEngine encoding for each payload.
        This is the primary API for injection plugins.
        """
        payloads = self.get(category, dbms=dbms, context=context, limit=limit)
        result: list[tuple[Payload, list[str]]] = []
        for p in payloads:
            variants = self.mutate(p.value, waf_engine, max_variants=max_variants)
            result.append((p, variants))
        return result

    def add(self, category: PayloadCategory, payloads: list[Payload]) -> None:
        """Add custom payloads to a category."""
        if category not in self._db:
            self._db[category] = []
        self._db[category].extend(payloads)
