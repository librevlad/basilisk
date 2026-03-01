"""Edge case tests for FindingTracker matching logic.

Tests severity tolerance, empty categories, unknown abbreviations,
cross-category matching, category alias reverse lookup, and
multi-strategy interactions.
"""
from __future__ import annotations

from basilisk.knowledge.entities import Entity, EntityType
from basilisk.training.profile import ExpectedFinding, TrainingProfile
from basilisk.training.validator import (
    FindingTracker,
    _abbreviation_match,
    _categories_match,
    _tokenize,
    _word_overlap,
)


def _entity(title: str, severity: str, category: str = "", eid: str = "") -> Entity:
    eid = eid or Entity.make_id(EntityType.FINDING, host="localhost", title=title)
    return Entity(
        id=eid, type=EntityType.FINDING,
        data={"host": "localhost", "title": title, "severity": severity, "category": category},
    )


def _tracker(*findings: tuple[str, str, str]) -> FindingTracker:
    """Create tracker with given (title, severity, category) expected findings."""
    profile = TrainingProfile(
        name="test", target="localhost",
        expected_findings=[
            ExpectedFinding(title=t, severity=s, category=c, plugin_hints=["test"])
            for t, s, c in findings
        ],
    )
    return FindingTracker(profile)


# ── Severity tolerance ─────────────────────────────────────────────────────

class TestSeverityTolerance:
    """Validator allows ±1 severity tolerance."""

    def test_exact_severity_matches(self):
        tracker = _tracker(("SQLi", "critical", "sqli"))
        assert tracker.check_discovery(_entity("SQLi found", "critical"), step=1) is True

    def test_one_below_matches(self):
        """HIGH finding matches CRITICAL expectation (one below)."""
        tracker = _tracker(("SQLi", "critical", "sqli"))
        assert tracker.check_discovery(_entity("SQLi found", "high"), step=1) is True

    def test_two_below_rejects(self):
        """MEDIUM finding does NOT match CRITICAL expectation (two below)."""
        tracker = _tracker(("SQLi", "critical", "sqli"))
        assert tracker.check_discovery(_entity("SQLi found", "medium"), step=1) is False

    def test_above_matches(self):
        """CRITICAL finding matches HIGH expectation (above is always ok)."""
        tracker = _tracker(("XSS", "high", "xss"))
        assert tracker.check_discovery(_entity("XSS found", "critical"), step=1) is True

    def test_info_matches_low(self):
        """INFO matches LOW expectation (one below)."""
        tracker = _tracker(("Disclosure", "low", "config"))
        assert tracker.check_discovery(_entity("Disclosure found", "info"), step=1) is True

    def test_info_rejects_medium(self):
        """INFO does NOT match MEDIUM expectation (two below)."""
        tracker = _tracker(("Disclosure", "medium", "config"))
        assert tracker.check_discovery(_entity("Disclosure found", "info"), step=1) is False

    def test_low_rejects_critical(self):
        """LOW finding does NOT match CRITICAL (three below)."""
        tracker = _tracker(("SQLi", "critical", "sqli"))
        assert tracker.check_discovery(_entity("SQLi found", "low"), step=1) is False

    def test_medium_matches_high(self):
        """MEDIUM finding matches HIGH expectation (one below)."""
        tracker = _tracker(("CSRF", "high", "csrf"))
        assert tracker.check_discovery(_entity("CSRF: no token", "medium"), step=1) is True

    def test_unknown_severity_rejected(self):
        """Unknown severity rank should not match."""
        tracker = _tracker(("SQLi", "critical", "sqli"))
        assert tracker.check_discovery(_entity("SQLi found", "unknown"), step=1) is False


# ── Category matching ──────────────────────────────────────────────────────

class TestCategoryMatching:
    def test_exact_match(self):
        assert _categories_match("sqli", "sqli") is True

    def test_alias_forward(self):
        """'sqli' category recognizes 'sql-injection' as alias."""
        assert _categories_match("sqli", "sql-injection") is True

    def test_alias_reverse(self):
        """Actual 'nosqli' matches expected 'sqli' via alias."""
        assert _categories_match("sqli", "nosqli") is True

    def test_auth_aliases(self):
        """Auth category has many aliases."""
        for alias in ("default-creds", "idor", "session", "jwt", "bola", "access-control"):
            assert _categories_match("auth", alias) is True, f"auth should match '{alias}'"

    def test_config_aliases(self):
        for alias in ("cors", "clickjacking", "disclosure", "misconfiguration"):
            assert _categories_match("config", alias) is True, f"config should match '{alias}'"

    def test_xss_aliases(self):
        assert _categories_match("xss", "cross-site-scripting") is True
        assert _categories_match("xss", "html-injection") is True

    def test_lfi_aliases(self):
        assert _categories_match("lfi", "file-inclusion") is True
        assert _categories_match("lfi", "path-traversal") is True
        assert _categories_match("lfi", "directory-traversal") is True

    def test_no_match(self):
        assert _categories_match("sqli", "xss") is False
        assert _categories_match("auth", "sqli") is False

    def test_empty_categories(self):
        """Empty categories should not match anything except themselves."""
        assert _categories_match("", "") is True
        assert _categories_match("", "sqli") is False
        assert _categories_match("sqli", "") is False

    def test_reverse_canonical_match(self):
        """If expected is an alias, it should match the canonical category."""
        # 'nosqli' is an alias of 'sqli', so expected='nosqli' should match actual='sqli'
        assert _categories_match("nosqli", "sqli") is True

    def test_idor_auth_bidirectional(self):
        """IDOR and auth are aliased to each other."""
        assert _categories_match("idor", "auth") is True
        assert _categories_match("auth", "idor") is True


# ── Abbreviation matching ──────────────────────────────────────────────────

class TestAbbreviationMatching:
    def test_ssrf_expansion(self):
        assert _abbreviation_match("SSRF", "Server-Side Request Forgery") is True

    def test_csrf_expansion(self):
        assert _abbreviation_match("CSRF", "Cross-Site Request Forgery") is True

    def test_xss_expansion(self):
        assert _abbreviation_match("XSS", "Cross-Site Scripting") is True

    def test_sqli_expansion(self):
        assert _abbreviation_match("SQLi", "SQL Injection") is True

    def test_idor_expansion(self):
        assert _abbreviation_match("IDOR", "Insecure Direct Object Reference") is True

    def test_bola_expansion(self):
        assert _abbreviation_match("BOLA", "Broken Object Level Authorization") is True

    def test_xxe_expansion(self):
        assert _abbreviation_match("XXE", "XML External Entity") is True

    def test_jwt_expansion(self):
        assert _abbreviation_match("JWT", "JSON Web Token") is True

    def test_lfi_expansion(self):
        assert _abbreviation_match("LFI", "Local File Inclusion") is True

    def test_rfi_expansion(self):
        assert _abbreviation_match("RFI", "Remote File Inclusion") is True

    def test_ssti_expansion(self):
        assert _abbreviation_match("SSTI", "Server-Side Template Injection") is True

    def test_no_match_single_keyword(self):
        """Single keyword overlap insufficient (prevents false positives)."""
        # 'token' alone shouldn't match JWT (needs 2+ keywords)
        assert _abbreviation_match("JWT", "Missing token") is False

    def test_reverse_direction(self):
        """Actual abbreviation matched against expected full name."""
        assert _abbreviation_match("Insecure Direct Object Reference", "IDOR in /api") is True

    def test_unknown_abbreviation(self):
        """Unknown abbreviation should not match."""
        assert _abbreviation_match("ZXYZ", "Zero X Year Zeta") is False

    def test_partial_abbreviation_no_false_positive(self):
        """Abbreviation in expected but keywords don't match actual."""
        assert _abbreviation_match("XSS", "Command Injection via /cmd") is False


# ── Tokenization ───────────────────────────────────────────────────────────

class TestTokenization:
    def test_basic_tokenize(self):
        tokens = _tokenize("SQL Injection in /login?id=1")
        assert "sql" in tokens
        assert "injection" in tokens
        assert "login" in tokens
        # Stop words removed
        assert "in" not in tokens

    def test_short_words_removed(self):
        tokens = _tokenize("XSS via a /page")
        assert "xss" in tokens
        assert "page" in tokens
        # Single-char words removed
        assert "a" not in tokens

    def test_empty_string(self):
        assert _tokenize("") == set()

    def test_punctuation_stripped(self):
        tokens = _tokenize("CSRF: 2/5 forms!")
        assert "csrf" in tokens
        assert "forms" in tokens


# ── Word overlap ───────────────────────────────────────────────────────────

class TestWordOverlap:
    def test_full_overlap(self):
        assert _word_overlap("SQL Injection", "SQL Injection found") == 1.0

    def test_partial_overlap(self):
        overlap = _word_overlap("SQL Injection Attack", "SQL Injection found")
        assert 0.5 <= overlap < 1.0

    def test_no_overlap(self):
        assert _word_overlap("SQL Injection", "XSS Reflected") == 0.0

    def test_empty_expected(self):
        assert _word_overlap("", "Something") == 0.0

    def test_threshold_50_percent(self):
        """50% overlap should be sufficient."""
        # "SQL Injection Attack" has tokens: sql, injection, attack (3 words)
        # "SQL Injection" has tokens: sql, injection (2 words)
        # Overlap of expected in actual: 2/3 = 66.7%
        overlap = _word_overlap("SQL Injection Attack", "SQL Injection in /login")
        assert overlap >= 0.5


# ── Multi-finding interaction ──────────────────────────────────────────────

class TestMultiFindingInteraction:
    def test_first_match_wins(self):
        """First matching expected finding is consumed; duplicates don't double-match."""
        tracker = _tracker(
            ("SQL Injection", "critical", "sqli"),
            ("SQL Injection Advanced", "critical", "sqli"),
        )
        e1 = _entity("SQL Injection (MySQL): /login", "critical", "sqli", "e1")
        e2 = _entity("SQL Injection Advanced: UNION", "critical", "sqli", "e2")

        assert tracker.check_discovery(e1, step=1) is True
        assert tracker.check_discovery(e2, step=2) is True
        assert tracker.coverage == 1.0

    def test_already_matched_not_rematched(self):
        """An already-matched expected finding is not matched again."""
        tracker = _tracker(("XSS", "high", "xss"))
        e1 = _entity("XSS Reflected: /search", "high", "xss", "e1")
        e2 = _entity("XSS Stored: /comments", "high", "xss", "e2")

        assert tracker.check_discovery(e1, step=1) is True
        # Second XSS should not match (only one expected)
        assert tracker.check_discovery(e2, step=2) is False

    def test_strategy_cascade(self):
        """Matching cascades through strategies: containment → abbreviation → category."""
        # This finding only matches via category (not title containment or abbreviation)
        tracker = _tracker(("Access Control Issue", "high", "auth"))
        e = _entity("Unauthorized endpoint access", "high", "bola")

        # Should match via category alias (auth → bola)
        assert tracker.check_discovery(e, step=1) is True

    def test_no_expected_findings(self):
        """Tracker with no expected findings should have 100% coverage."""
        profile = TrainingProfile(name="test", target="localhost", expected_findings=[])
        tracker = FindingTracker(profile)
        assert tracker.coverage == 1.0
        assert tracker.verification_rate == 0.0

    def test_undiscovered_returns_all_initially(self):
        tracker = _tracker(
            ("SQLi", "critical", "sqli"),
            ("XSS", "high", "xss"),
        )
        assert len(tracker.undiscovered) == 2

    def test_unverified_empty_when_not_discovered(self):
        tracker = _tracker(("SQLi", "critical", "sqli"))
        assert len(tracker.unverified) == 0

    def test_matched_title_stored(self):
        """Tracker stores the actual matched title from the entity."""
        tracker = _tracker(("SQLi", "critical", "sqli"))
        e = _entity("SQL Injection (MySQL): /login?id=", "critical", "sqli", "sqli1")
        tracker.check_discovery(e, step=1)

        assert tracker.tracked[0].matched_title == "SQL Injection (MySQL): /login?id="
        assert tracker.tracked[0].matched_entity_id == "sqli1"

    def test_verification_step_recorded(self):
        tracker = _tracker(("SQLi", "critical", "sqli"))
        e = _entity("SQLi in /login", "critical", "sqli", "f1")
        tracker.check_discovery(e, step=3)
        tracker.check_verification("f1", step=10)

        assert tracker.tracked[0].verification_step == 10

    def test_large_profile_coverage(self):
        """Test coverage with many expected findings (similar to bwapp at 39)."""
        findings = [(f"Finding {i}", "high", "config") for i in range(39)]
        tracker = _tracker(*findings)

        # Discover half
        for i in range(20):
            e = _entity(f"Finding {i} detected", "high", "config", f"f{i}")
            tracker.check_discovery(e, step=i)

        expected_cov = 20 / 39
        assert abs(tracker.coverage - expected_cov) < 0.01


# ── Category edge cases ────────────────────────────────────────────────────

class TestCategoryEdgeCases:
    def test_crypto_aliases(self):
        assert _categories_match("crypto", "weak-crypto") is True
        assert _categories_match("crypto", "hash") is True
        assert _categories_match("crypto", "padding-oracle") is True

    def test_upload_aliases(self):
        assert _categories_match("upload", "file-upload") is True
        assert _categories_match("upload", "unrestricted-upload") is True

    def test_dos_aliases(self):
        assert _categories_match("dos", "denial-of-service") is True
        assert _categories_match("dos", "rate-limiting") is True

    def test_csrf_alias(self):
        assert _categories_match("csrf", "cross-site-request-forgery") is True

    def test_csp_alias(self):
        assert _categories_match("csp", "content-security-policy") is True
        assert _categories_match("csp", "headers") is True
