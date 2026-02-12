"""Response diff engine — baseline capture, semantic comparison, similarity scoring."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from html.parser import HTMLParser


@dataclass(frozen=True)
class ResponseSnapshot:
    """Immutable snapshot of an HTTP response for comparison."""

    status: int
    headers: dict[str, str]
    body: str
    length: int
    content_type: str = ""
    elapsed: float = 0.0

    @property
    def body_hash(self) -> str:
        return hashlib.md5(self.body.encode(), usedforsecurity=False).hexdigest()

    @property
    def words(self) -> int:
        return len(self.body.split())

    @property
    def lines(self) -> int:
        return self.body.count("\n") + 1


@dataclass
class DiffResult:
    """Result of comparing two responses."""

    status_changed: bool = False
    length_delta: int = 0
    length_ratio: float = 1.0
    similarity: float = 1.0
    word_delta: int = 0
    line_delta: int = 0
    new_content: list[str] = field(default_factory=list)
    removed_content: list[str] = field(default_factory=list)
    header_changes: dict[str, tuple[str, str]] = field(default_factory=dict)
    is_significant: bool = False
    score: float = 0.0

    @property
    def has_changes(self) -> bool:
        return self.score > 0.05


_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
_DYNAMIC_PATTERNS = re.compile(
    r"(csrf[_-]?token|nonce|timestamp|_token|__RequestVerification"
    r"|captcha|session[_-]?id|rand|cache[_-]?bust)\s*[:=]\s*[\"'][^\"']+[\"']",
    re.IGNORECASE,
)


class _TextExtractor(HTMLParser):
    """Extract visible text from HTML, stripping tags."""

    def __init__(self) -> None:
        super().__init__()
        self.pieces: list[str] = []
        self._skip = False

    def handle_starttag(self, tag: str, _attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("script", "style", "noscript"):
            self._skip = True

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style", "noscript"):
            self._skip = False

    def handle_data(self, data: str) -> None:
        if not self._skip:
            text = data.strip()
            if text:
                self.pieces.append(text)


def _extract_text(html: str) -> str:
    """Extract visible text from HTML."""
    parser = _TextExtractor()
    try:
        parser.feed(html)
    except Exception:
        return _TAG_RE.sub("", html)
    return " ".join(parser.pieces)


def _normalize(body: str) -> str:
    """Normalize response body for comparison.

    Strips dynamic tokens (CSRF, nonces), collapses whitespace.
    """
    text = _DYNAMIC_PATTERNS.sub("", body)
    text = _WS_RE.sub(" ", text)
    return text.strip()


def _structural_tokens(html: str) -> list[str]:
    """Extract structural tokens (tag names + text chunks) for comparison."""
    tokens: list[str] = []
    for part in re.split(r"(<[^>]+>)", html):
        part = part.strip()
        if not part:
            continue
        if part.startswith("<"):
            tag_match = re.match(r"</?(\w+)", part)
            if tag_match:
                tokens.append(f"<{tag_match.group(1)}>")
        else:
            text = _WS_RE.sub(" ", part).strip()
            if text and len(text) > 2:
                tokens.append(text[:80])
    return tokens


class ResponseDiffer:
    """Stateful differ: capture baselines, compare mutations.

    Usage::

        differ = ResponseDiffer()
        baseline = differ.capture(status=200, headers={}, body=html)
        result = differ.compare(baseline, mutated_snapshot)
        if result.is_significant:
            print("Mutation had effect!")
    """

    def __init__(
        self,
        *,
        length_threshold: float = 0.05,
        similarity_threshold: float = 0.95,
        score_threshold: float = 0.15,
    ) -> None:
        self.length_threshold = length_threshold
        self.similarity_threshold = similarity_threshold
        self.score_threshold = score_threshold

    @staticmethod
    def capture(
        status: int,
        headers: dict[str, str],
        body: str,
        elapsed: float = 0.0,
    ) -> ResponseSnapshot:
        """Create an immutable snapshot from raw response data."""
        ct = headers.get("Content-Type", headers.get("content-type", ""))
        return ResponseSnapshot(
            status=status,
            headers=dict(headers),
            body=body,
            length=len(body),
            content_type=ct,
            elapsed=elapsed,
        )

    def compare(
        self,
        baseline: ResponseSnapshot,
        response: ResponseSnapshot,
    ) -> DiffResult:
        """Compare a response against baseline. Returns scored diff."""
        result = DiffResult()

        # Status code change
        result.status_changed = baseline.status != response.status

        # Length analysis
        result.length_delta = response.length - baseline.length
        if baseline.length > 0:
            result.length_ratio = response.length / baseline.length
        else:
            result.length_ratio = float("inf") if response.length > 0 else 1.0

        # Word and line delta
        result.word_delta = response.words - baseline.words
        result.line_delta = response.lines - baseline.lines

        # Normalize and compute similarity
        norm_base = _normalize(baseline.body)
        norm_resp = _normalize(response.body)
        result.similarity = self._similarity(norm_base, norm_resp)

        # Content diff (new/removed chunks)
        base_lines = set(norm_base.split(". "))
        resp_lines = set(norm_resp.split(". "))
        result.new_content = sorted(resp_lines - base_lines)[:20]
        result.removed_content = sorted(base_lines - resp_lines)[:20]

        # Header changes
        all_keys = set(baseline.headers) | set(response.headers)
        for key in all_keys:
            old = baseline.headers.get(key, "")
            new = response.headers.get(key, "")
            if old != new:
                result.header_changes[key] = (old, new)

        # Compute composite score (0.0 = identical, 1.0 = completely different)
        score = 0.0
        if result.status_changed:
            score += 0.35
        if result.similarity < self.similarity_threshold:
            score += (1.0 - result.similarity) * 0.4
        length_pct = abs(result.length_delta) / max(baseline.length, 1)
        if length_pct > self.length_threshold:
            score += min(length_pct, 1.0) * 0.15
        if result.header_changes:
            score += min(len(result.header_changes) * 0.02, 0.1)

        result.score = min(score, 1.0)
        result.is_significant = result.score >= self.score_threshold
        return result

    def _similarity(self, a: str, b: str) -> float:
        """Compute text similarity ratio (0.0–1.0)."""
        if a == b:
            return 1.0
        if not a or not b:
            return 0.0
        # For very long texts, compare structural tokens instead
        if len(a) > 10_000 or len(b) > 10_000:
            tokens_a = _structural_tokens(a)
            tokens_b = _structural_tokens(b)
            return SequenceMatcher(None, tokens_a, tokens_b).ratio()
        return SequenceMatcher(None, a, b).ratio()

    def is_same_page(
        self,
        a: ResponseSnapshot,
        b: ResponseSnapshot,
        threshold: float = 0.92,
    ) -> bool:
        """Quick check: are two responses essentially the same page?

        Useful for SPA detection, soft-404 detection, etc.
        """
        if a.status != b.status:
            return False
        if a.body_hash == b.body_hash:
            return True
        norm_a = _normalize(a.body)
        norm_b = _normalize(b.body)
        return self._similarity(norm_a, norm_b) >= threshold

    def detect_reflection(
        self,
        baseline: ResponseSnapshot,
        response: ResponseSnapshot,
        payload: str,
    ) -> str | None:
        """Check if a payload appears in the response but not in baseline.

        Returns the reflected context string, or None.
        """
        if payload not in response.body:
            return None
        if payload in baseline.body:
            return None

        # Find context around reflection
        idx = response.body.find(payload)
        start = max(0, idx - 40)
        end = min(len(response.body), idx + len(payload) + 40)
        return response.body[start:end]

    def detect_error_pattern(
        self,
        baseline: ResponseSnapshot,
        response: ResponseSnapshot,
    ) -> str | None:
        """Check if response contains error patterns not in baseline.

        Useful for error-based SQLi, SSTI, command injection detection.
        """
        error_patterns = [
            # SQL errors
            r"SQL syntax.*?MySQL",
            r"Warning.*?\Wmysqli?_",
            r"PostgreSQL.*?ERROR",
            r"ORA-\d{5}",
            r"Microsoft.*?ODBC.*?SQL Server",
            r"Unclosed quotation mark",
            r"quoted string not properly terminated",
            r"pg_query\(\).*?failed",
            # Template errors
            r"TemplateSyntaxError",
            r"Jinja2.*?UndefinedError",
            r"Twig_Error",
            r"freemarker\.core\.",
            # Path/file errors
            r"No such file or directory",
            r"java\.io\.FileNotFoundException",
            r"System\.IO\.FileNotFoundException",
            # Stack traces
            r"Traceback \(most recent call last\)",
            r"at \w+\.\w+\([\w.]+:\d+\)",
            r"Exception in thread",
            # Command execution
            r"sh: \d+: .+: not found",
            r"bash: .+: command not found",
        ]
        for pattern in error_patterns:
            match = re.search(pattern, response.body, re.IGNORECASE)
            if match and not re.search(pattern, baseline.body, re.IGNORECASE):
                return match.group(0)
        return None

    def timing_anomaly(
        self,
        baseline: ResponseSnapshot,
        response: ResponseSnapshot,
        threshold_factor: float = 3.0,
        min_absolute: float = 3.0,
    ) -> bool:
        """Check if response time indicates a timing-based side channel.

        True if response is significantly slower than baseline.
        """
        if baseline.elapsed <= 0 or response.elapsed <= 0:
            return False
        return (
            response.elapsed > baseline.elapsed * threshold_factor
            and response.elapsed > min_absolute
        )
