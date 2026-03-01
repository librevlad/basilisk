"""Validator matching simulation for all 20 training profiles.

For each profile, simulates realistic finding discovery by creating FINDING entities
with titles matching what actual plugins produce.  Verifies FindingTracker matches
every expected finding through the correct matching strategy.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from basilisk.knowledge.entities import Entity, EntityType
from basilisk.training.profile import TrainingProfile
from basilisk.training.validator import FindingTracker

PROFILES_DIR = Path(__file__).resolve().parents[2] / "training_profiles"


def _entity(title: str, severity: str, category: str = "", eid: str = "") -> Entity:
    """Create a FINDING entity with given data."""
    eid = eid or Entity.make_id(EntityType.FINDING, host="localhost", title=title)
    return Entity(
        id=eid, type=EntityType.FINDING,
        data={"host": "localhost", "title": title, "severity": severity, "category": category},
    )


def _simulate_plugin_title(expected_title: str) -> str:
    """Generate a realistic plugin output title from an expected finding title.

    Wraps the expected title in context that plugins typically produce,
    testing the FindingTracker's matching strategies.
    """
    t = expected_title.lower()

    # SQL injection variants - add path context
    if "sql injection" in t:
        suffix = t.replace("sql injection", "").strip()
        return f"SQL injection (MySQL): /app/page?p= {suffix}".strip()

    # XSS variants
    if "xss" in t or "cross-site scripting" in t:
        tag = expected_title.split()[-1] if len(expected_title.split()) > 2 else "page"
        return f"Reflected XSS: {expected_title} via /app/{tag}"

    # Command injection
    if "command injection" in t:
        return f"OS Command Injection in /app/cmd?target= ({expected_title})"

    # Path traversal / directory traversal / file inclusion
    if "traversal" in t or "file inclusion" in t or "lfi" in t or "rfi" in t:
        return f"Path traversal confirmed: /app?file= ({expected_title})"

    # For most findings, just append path context to ensure containment match
    return f"{expected_title} detected in /app/endpoint"


# ── Per-profile simulated plugin titles ──────────────────────────────────────
# Each list: realistic_plugin_title for each expected finding (same order as YAML)

ALTORO_MUTUAL = [
    "SQL Injection Login Bypass via /doLogin?uid=",
    "SQL Injection Search via /search.jsp?query=",
    "Default Credentials found: admin/admin",
    "Reflected XSS: tag injection via /search.jsp?query=",
    "XSS Stored in /comment.jsp?content=",
    "CSRF: 3/5 POST form(s) without CSRF token",
    "Potential IDOR: /api/account/1",
    "Session Fixation: 'JSESSIONID' accepts arbitrary values",
    "Unauthenticated Access to /admin/admin.jsp",
    "File Inclusion via path traversal in /index.jsp?content=",
    "HTML Injection reflected in /feedback.jsp",
    "Open Redirect: /login.jsp?url= (absolute_url)",
    "No framing protection (clickjacking) on localhost:4380",
    "Session cookie 'JSESSIONID' lacks SameSite attribute (Cookie issue)",
    "Directory listing enabled: /bank/",
]

BADSTORE = [
    "SQL injection (MySQL): /cgi-bin/badstore.cgi?searchquery=",
    "OS Command Injection in /cgi-bin/badstore.cgi?action=",
    "Reflected XSS: tag injection via /cgi-bin/badstore.cgi?searchquery=",
    "XSS Stored in guestbook /cgi-bin/badstore.cgi",
    "Path Traversal confirmed: /cgi-bin/badstore.cgi (traversal_basic)",
    "Default credentials found: admin/admin",
    "Session Prediction: sequential IDs in 'SSOid'",
    "Session Fixation: 'SSOid' accepts arbitrary values",
    "Potential IDOR: /cgi-bin/badstore.cgi?action=myaccount",
    "Session cookie 'SSOid' missing HttpOnly flag (Cookie issue)",
    "Sensitive path /backup/ exposed via dir brute",
    "No framing protection (clickjacking) on localhost:4480",
    "Directory listing enabled: /backup/",
    "Missing security header: HSTS on localhost:4480",
    "Sensitive paths in robots.txt",
    "User Enumeration via /cgi-bin/badstore.cgi?action=register",
]

BWAPP = [
    "SQL Injection GET Search in /sqli_1.php?title=",
    "SQL Injection POST Search in /sqli_2.php",
    "SQL Injection AJAX JSON in /sqli_6.php",
    "SQL Injection Login Form in /login.php",
    "SQL Injection Blind Boolean in /sqli_4.php?title=",
    "SQL Injection Blind Time in /sqli_14.php",
    "SQL Injection Stored Blog in /sqli_15.php",
    "XSS Reflected GET in /xss_get.php?firstname=",
    "XSS Reflected POST in /xss_post.php",
    "XSS Stored Blog in /xss_stored_1.php",
    "XSS Reflected User-Agent header reflection",
    "XSS Reflected Referer header reflection",
    "OS Command Injection in /commandi.php?target=",
    "OS Command Injection Blind in /commandi_blind.php",
    "PHP Code Injection in /phpi.php?message=",
    "SSI Injection in /ssii.php?FirstName=",
    "LDAP Injection in /ldapi.php?search=",
    "XML XPath Injection in /xmli_1.php",
    "HTML Injection Reflected in /htmli_get.php?firstname=",
    "iFrame Injection in /iframei.php?ParamUrl=",
    "Local File Inclusion via /rlfi.php?language=",
    "Remote File Inclusion in /rlfi.php?language=http://evil.com",
    "Unrestricted File Upload in /unrestricted_file_upload.php",
    "CSRF Change Password in /csrf_1.php",
    "CSRF Transfer Amount in /csrf_3.php",
    "Broken Authentication Insecure Login at /insecure_login.php",
    "Broken Authentication Weak Passwords at /ba_weak_pwd.php",
    "Session Fixation: 'PHPSESSID' accepts arbitrary values",
    "Insecure Direct Object Reference in /idor.php?ticket=1",
    "Server-Side Request Forgery in /ssrf.php?url=",
    "XXE injection confirmed in /xxe-2.php",
    "CORS Misconfiguration: wildcard on localhost:8180",
    "Directory Traversal via /directory_traversal_2.php?directory=",
    "HTTP Response Splitting via /hrs.php?header=",
    "No framing protection (clickjacking) on localhost:8180",
    "Shellshock vulnerability in /cgi-bin/",
    "Unvalidated Redirect in /open_redirect.php?url=",
    "HTTP Parameter Pollution in /hpp-1.php",
    "Sensitive paths in robots.txt (Information Disclosure Robots)",
]

CRAPI = [
    "Potential IDOR: /api/v2/vehicle/ (IDOR endpoint)",
    "BOLA: Broken Object Level Authorization in /api/v2/vehicle/",
    "SQL injection (MySQL): /api/v2/coupon/validate-coupon",
    "NoSQL Injection in /api/v2/coupon/validate-coupon",
    "JWT secret brute-forced: weak_secret",
    "Server-Side Request Forgery in /api/v2/community/posts/",
    "Mass Assignment via /api/v2/user/change-email",
    "Unauthenticated Access to /api/v2/mechanic/receive_report",
    "No framing protection (clickjacking) on localhost:8888",
    "Wildcard CORS on localhost:8888",
]

DSVW = [
    "SQL Injection UNION: /?id= (5 columns)",
    "SQL Injection Blind Boolean: /?id=",
    "SQL Injection Blind Time: /?id=",
    "SQL Injection Login Bypass via /?username=admin",
    "Arbitrary Code Execution via /?domain=|whoami",
    "Remote File Inclusion in /?path=http://evil.com/shell",
    "XXE Local: /?xml=<!DOCTYPE..>",
    "XXE Remote: /?xml=<!DOCTYPE..>",
    "Pickle Deserialization in /?pickle=",
    "Reflected XSS: tag injection via /?v=",
    "XSS Stored in /?comment=",
    "DOM XSS sinks detected: XSS DOM in /#/page",
    "Server-Side Request Forgery in /?url=",
    "XPath Injection Blind via /?name=",
    "Path Traversal confirmed: /?path= (traversal_basic)",
    "Frame Injection via /?frame=",
    "No framing protection (clickjacking) on localhost:65412",
    "Unvalidated Redirect via /?url=http://evil.com",
    "HTTP Header Injection via /?charset=",
    "Source Code Disclosure via /?path=dsvw.py",
    "Full Path Disclosure in error response",
]

DVWS = [
    "Cross-Site WebSocket Hijacking: /ws endpoint",
    "SQL Injection via WebSocket message payload",
    "OS Command Injection via WebSocket message",
    "Broken Authentication: WebSocket session bypass",
    "XSS via WebSocket message reflection",
    "Potential IDOR: /api/messages/1 via WebSocket",
    "Server-Side Request Forgery via WebSocket URL param",
    "Sensitive Data Exposure in WebSocket handshake",
    "Missing Rate Limiting on WebSocket connections",
    "CORS Misconfiguration: wildcard on localhost:4580",
]

DVGA = [
    "OS Command Injection via GraphQL importPaste mutation",
    "SQL injection via GraphQL at /graphql",
    "JWT algorithm none bypass: /graphql",
    "XSS Stored in GraphQL paste mutation",
    "Server-Side Request Forgery via GraphQL importPaste URL",
    "Potential IDOR: /graphql query pastes by owner",
    "GraphQL Introspection Enabled at /graphql",
    "GraphQL batch query abuse at /graphql",
    "GraphQL depth limit bypass at /graphql",
    "GraphQL alias overloading at /graphql",
    "HTML Injection in GraphQL paste content",
    "Field Suggestions enabled in GraphQL errors",
    "Default credentials found for admin user",
]

DVWA = [
    "SQL injection (MySQL): /vulnerabilities/sqli/?id=",
    "SQL Injection Blind: Boolean blind SQLi /vulnerabilities/sqli_blind/?id=",
    "OS Command Injection in /vulnerabilities/exec/?ip=",
    "Unrestricted File Upload in /vulnerabilities/upload/",
    "Reflected Cross-Site Scripting Reflected via /vulnerabilities/xss_r/?name=",
    "Cross-Site Scripting Stored in /vulnerabilities/xss_s/",
    "DOM Cross-Site Scripting DOM via /vulnerabilities/xss_d/",
    "Path traversal: File Inclusion via /vulnerabilities/fi/?page=",
    "CSRF: 3/4 POST form(s) without CSRF token",
    "Brute Force attack possible on /vulnerabilities/brute/",
    "Authorization Bypass via parameter tampering",
    "Insecure CAPTCHA implementation in /vulnerabilities/captcha/",
    "CSP Bypass: allows unsafe-inline on localhost:4280",
    "JavaScript Attacks: client-side validation bypass",
    "Open HTTP Redirect via /vulnerabilities/redirect/",
]

GRUYERE = [
    "Elevation of Privilege via admin cookie manipulation",
    "Reflected XSS: tag injection via /gruyere/login?uid=",
    "XSS Stored Snippets in /gruyere/newsnippet",
    "XSS via HTML Attribute in /gruyere/saveprofile",
    "XSS via AJAX in /gruyere/feed.gtl",
    "Cookie Manipulation: admin flag in cookie",
    "Path Traversal Info Disclosure via /gruyere/..%2f",
    "Path Traversal Data Tampering via file overwrite",
    "Information Disclosure Config at /gruyere/dump",
    "Information Disclosure Source at /gruyere/..%2fstart.py",
    "Database Dump Exposure at /gruyere/dump.gtl",
]

HACKAZON = [
    "SQL injection (MySQL): /search?id=",
    "SQL Injection Blind via /search?id= (time-based)",
    "OS Command Injection in /helpdesk/upload",
    "XXE injection confirmed in /wishlist",
    "Reflected XSS: tag injection via /search?searchString=",
    "XSS Stored in /review/add",
    "CSRF: 4/7 POST form(s) without CSRF token",
    "Session Fixation: 'PHPSESSID' accepts arbitrary values",
    "REST API Unauthenticated Access to /api/",
    "Potential IDOR: /account/orders/1",
    "Information Disclosure: Server header on localhost:4680",
    "Referrer Header Bypass in /account/",
]

JUICE_SHOP = [
    "SQL Injection Login Bypass via /rest/user/login",
    "SQL Injection User Credentials extraction via /rest/products/search?q=",
    "NoSQL Injection in /rest/products/reviews",
    "XXE Data Exfiltration via /file-upload",
    "Insecure Deserialization in /api/complaints",
    "Admin Login via SQL injection /rest/user/login",
    "Password Reset Exploit via /rest/user/reset-password",
    "Two Factor Auth Bypass via /rest/2fa/status",
    "DOM XSS sinks detected via /#/search?q=",
    "Reflected XSS: tag injection via /rest/products/search?q=",
    "XSS Stored XSS in customer feedback",
    "Admin Section Access at /#/administration",
    "View Another User Basket via /rest/basket/2",
    "Forged Feedback submission via /api/Feedbacks/",
    "Product Tampering via /api/products/1",
    "Confidential Document at /ftp/acquisitions.md",
    "Forgotten Developer Backup at /ftp/",
    "Exposed Metrics at /metrics endpoint",
    "Error Handling Disclosure in API response",
    "Deprecated Interface at /file-upload",
    "Known Vulnerable Component in dependencies",
    "Zero Stars Rating bypass via API",
    "Negative Quantity Order via /api/basket/checkout",
    "Upload Size Bypass via /file-upload",
    "Allowlist Bypass Redirect via /redirect",
    "CAPTCHA Bypass via direct API call",
    "Score Board Discovery at /#/score-board",
]

MUTILLIDAE = [
    "SQL Injection Login Bypass via /index.php?page=login.php",
    "SQL Injection Extract Data via /index.php?page=user-info.php",
    "SQL Injection UNION: /index.php?page=user-info.php (5 columns)",
    "SQL Injection Blind Boolean: /index.php?page=user-info.php",
    "SQL Injection Blind Time: /index.php?page=user-info.php",
    "OS Command Injection in /index.php?page=dns-lookup.php&target_host=",
    "Reflected XSS: tag injection via /index.php?page=document-viewer.php",
    "XSS Stored Blog in /index.php?page=add-to-your-blog.php",
    "DOM XSS sinks detected: XSS DOM in /index.php?page=html5-storage.php",
    "LDAP Injection in /index.php?page=ldap-connect.php",
    "XXE: XML Injection in /index.php?page=xml-validator.php",
    "XPath Injection in /index.php?page=xpath-injection.php",
    "JSON Injection in /index.php?page=pen-test-tool-lookup.php",
    "Input reflected (html_body): HTML Injection in /index.php",
    "JavaScript Injection in /index.php?page=pen-test-tool-lookup.php",
    "Log Injection in /index.php?page=log-visit.php",
    "HTTP Parameter Pollution in /index.php?page=user-info.php",
    "CSRF Register User: no token on registration form",
    "Path traversal: Local File Inclusion via /index.php?page=arbitrary-file-inclusion.php",
    "Remote File Inclusion in /index.php?page=http://evil.com",
    "Directory Traversal via /index.php?page=text-file-viewer.php",
    "Potential IDOR: /index.php?page=view-someones-blog.php",
    "Authentication Bypass via parameter manipulation",
    "Privilege Escalation via role parameter tampering",
    "Username Enumeration via /index.php?page=register.php",
    "No framing protection (clickjacking) on localhost:8280",
    "Sensitive paths in robots.txt (Robots Disclosure)",
    "phpinfo Disclosure at /index.php?page=phpinfo.php",
    "Verbose Error Messages exposing stack traces",
    "Open Redirect: /index.php?page=redirectandlog.php",
]

NODEGOAT = [
    "XSS Stored in /contributions via user input",
    "Reflected XSS: tag injection via /contributions?user=",
    "CSRF: 3/4 POST form(s) without CSRF token",
    "Potential IDOR: /profile/1",
    "Unvalidated Redirect via /login?url=",
    "Security Misconfiguration: missing security headers",
    "Log Injection in /contributions",
    "NoSQL Injection in /contributions?user=",
]

PIXI = [
    "NoSQL Injection in /api/user/login",
    "Potential IDOR: /api/user/ endpoint",
    "JWT algorithm none bypass: /api/user/",
    "No framing protection (clickjacking) on localhost:8000",
    "Missing security header: HSTS on localhost:8000",
]

RAILSGOAT = [
    "SQL injection: /users?search=",
    "Reflected XSS: tag injection via /search?q=",
    "XSS Stored in /benefits/upload",
    "Potential IDOR: /users/1/benefits",
    "Sensitive Data Exposure in /password-resets",
    "Session cookie missing HttpOnly flag (Missing HTTPOnly Flag)",
    "Security Misconfiguration: verbose errors in production",
    "Unvalidated Redirect via /login?url=",
]

VAMPI = [
    "NoSQL Injection in /users/v1/login",
    "Potential IDOR: /users/v1/ endpoint",
    "Mass Assignment via /users/v1/register",
    "JWT secret brute-forced: weak_secret",
    "BOLA: Broken Object Level Authorization in /users/v1/",
    "Sensitive path /users/v1/_debug exposed",
    "User Enumeration via /users/v1/login response",
]

VAPI = [
    "Broken Authentication in /vapi/api1/user/login",
    "JWT Vulnerability: algorithm confusion RS256→HS256",
    "BOLA: Broken Object Level Authorization in /vapi/api2/user/",
    "Server-Side Request Forgery in /vapi/api7/user/",
    "CORS Misconfiguration: wildcard on localhost:4880",
    "Rate Limiting Missing on /vapi/api4/login",
    "Security Misconfiguration: verbose errors enabled",
    "Insufficient Logging on API endpoints",
]

WACKOPICKO = [
    "SQL Injection Login bypass via /users/login.php",
    "SQL Injection Stored in /pictures/comment.php",
    "OS Command Injection in /passcheck.php?name=",
    "SessionID Predictable: sequential IDs detected",
    "XSS Reflected Search via /users/search.php?query=",
    "XSS Stored Guestbook in /guestbook.php",
    "XSS Behind Flash Form injection",
    "XSS Behind JavaScript handler",
    "XSS Multi-Step Stored in user profile",
    "Directory Traversal via /pictures/upload.php",
    "Path traversal: File Inclusion in /pictures/upload.php",
    "Parameter Manipulation in /cart/action.php?action=",
    "Default Credentials found: admin/admin",
    "Forceful Browsing: /admin/ accessible without auth",
    "Cookie Manipulation: role flag in session cookie",
]

WEBGOAT = [
    "SQL injection: /WebGoat/SqlInjection/attack5a?account=",
    "SQL Injection Advanced: /WebGoat/SqlInjectionAdvanced/challenge",
    "XML External Entity: XXE in /WebGoat/xxe/simple",
    "JWT algorithm none bypass: /WebGoat/JWT/",
    "Path Traversal confirmed: /WebGoat/PathTraversal/random",
    "Potential IDOR: /WebGoat/IDOR/profile/",
    "Server-Side Request Forgery in /WebGoat/SSRF/task1",
    "Mass Assignment via /WebGoat/auth-bypass/verify-account",
    "No framing protection (clickjacking) on localhost:8080",
]

XVWA = [
    "SQL injection (MySQL): /xvwa/vulnerabilities/sqli/?item=",
    "SQL Injection Blind: Boolean blind SQLi /xvwa/vulnerabilities/sqli_blind/",
    "OS Command Injection in /xvwa/vulnerabilities/cmdi/?target=",
    "PHP Object Injection in /xvwa/vulnerabilities/objection/",
    "Remote File Inclusion in /xvwa/vulnerabilities/fi/?file=http://evil",
    "Unrestricted File Upload in /xvwa/vulnerabilities/fi/upload",
    "Reflected XSS: tag injection via /xvwa/vulnerabilities/reflected_xss/",
    "XSS Stored in /xvwa/vulnerabilities/stored_xss/",
    "DOM XSS sinks: XSS DOM in /xvwa/vulnerabilities/dom_xss/",
    "Server-Side Request Forgery in /xvwa/vulnerabilities/ssrf/?url=",
    "Local File Inclusion via /xvwa/vulnerabilities/fi/?file=",
    "XPath Injection in /xvwa/vulnerabilities/xpath/",
    "Formula Injection in /xvwa/vulnerabilities/fi/?export=csv",
    "Potential IDOR: /xvwa/vulnerabilities/idor/?item=",
    "Missing Access Control on admin panel",
    "Session Fixation: 'PHPSESSID' accepts arbitrary values",
    "CSRF: 4/6 POST form(s) without CSRF token",
    "Server-Side Template Injection: SSTI in /xvwa/vulnerabilities/ssti/",
    "Open Redirect: /xvwa/vulnerabilities/redirect/?url=",
]


PROFILE_SIMULATIONS: dict[str, list[str]] = {
    "altoro_mutual": ALTORO_MUTUAL,
    "badstore": BADSTORE,
    "bwapp": BWAPP,
    "crapi": CRAPI,
    "dsvw": DSVW,
    "dvws": DVWS,
    "dvga": DVGA,
    "dvwa": DVWA,
    "gruyere": GRUYERE,
    "hackazon": HACKAZON,
    "juice_shop": JUICE_SHOP,
    "mutillidae": MUTILLIDAE,
    "nodegoat": NODEGOAT,
    "pixi": PIXI,
    "railsgoat": RAILSGOAT,
    "vampi": VAMPI,
    "vapi": VAPI,
    "wackopicko": WACKOPICKO,
    "webgoat": WEBGOAT,
    "xvwa": XVWA,
}


class TestValidatorMatchingAllProfiles:
    """Simulate finding discovery for each profile and verify 100% matching."""

    @pytest.mark.parametrize("profile_name", sorted(PROFILE_SIMULATIONS.keys()))
    def test_simulated_count_matches_profile(self, profile_name: str):
        """Simulated findings count must match expected findings count."""
        profile = TrainingProfile.load(PROFILES_DIR / f"{profile_name}.yaml")
        simulated = PROFILE_SIMULATIONS[profile_name]
        assert len(simulated) == len(profile.expected_findings), (
            f"{profile_name}: simulated {len(simulated)} "
            f"but profile expects {len(profile.expected_findings)}"
        )

    @pytest.mark.parametrize("profile_name", sorted(PROFILE_SIMULATIONS.keys()))
    def test_full_coverage(self, profile_name: str):
        """Every expected finding should be matched by the simulated plugin output."""
        profile = TrainingProfile.load(PROFILES_DIR / f"{profile_name}.yaml")
        tracker = FindingTracker(profile)

        simulated = PROFILE_SIMULATIONS[profile_name]
        for i, plugin_title in enumerate(simulated):
            ef = profile.expected_findings[i]
            entity = _entity(plugin_title, ef.severity, ef.category, eid=f"{profile_name}_{i}")
            tracker.check_discovery(entity, step=i + 1)

        assert tracker.coverage == 1.0, (
            f"{profile_name}: coverage {tracker.coverage:.1%}, "
            f"undiscovered: {[tf.expected.title for tf in tracker.undiscovered]}"
        )

    @pytest.mark.parametrize("profile_name", sorted(PROFILE_SIMULATIONS.keys()))
    def test_full_verification(self, profile_name: str):
        """After discovering all findings, verify them all."""
        profile = TrainingProfile.load(PROFILES_DIR / f"{profile_name}.yaml")
        tracker = FindingTracker(profile)

        simulated = PROFILE_SIMULATIONS[profile_name]
        entity_ids = []
        for i, plugin_title in enumerate(simulated):
            ef = profile.expected_findings[i]
            eid = f"{profile_name}_{i}"
            entity_ids.append(eid)
            entity = _entity(plugin_title, ef.severity, ef.category, eid=eid)
            tracker.check_discovery(entity, step=i + 1)

        for eid in entity_ids:
            tracker.check_verification(eid, step=100)

        assert tracker.verification_rate == 1.0, (
            f"{profile_name}: verification_rate {tracker.verification_rate:.1%}, "
            f"unverified: {[tf.expected.title for tf in tracker.unverified]}"
        )


class TestMatchingStrategies:
    """Test specific matching strategies with realistic examples."""

    def test_title_containment(self):
        """Expected 'SQL Injection' matches actual 'SQL injection (MySQL): /path'."""
        profile = TrainingProfile(
            name="test", target="localhost",
            expected_findings=[
                {"title": "SQL Injection", "severity": "critical", "category": "sqli",
                 "plugin_hints": ["sqli_basic"]},
            ],
        )
        tracker = FindingTracker(profile)
        entity = _entity("SQL injection (MySQL): /login?id=", "critical", "sqli")
        assert tracker.check_discovery(entity, step=1) is True

    def test_reverse_containment(self):
        """Short actual title contained in longer expected title."""
        profile = TrainingProfile(
            name="test", target="localhost",
            expected_findings=[
                {"title": "OS Command Injection via CGI", "severity": "critical",
                 "category": "injection", "plugin_hints": ["cmdi_check"]},
            ],
        )
        tracker = FindingTracker(profile)
        entity = _entity("Command Injection: /cgi-bin/test", "critical", "injection")
        assert tracker.check_discovery(entity, step=1) is True

    def test_abbreviation_ssrf(self):
        """Expected 'SSRF' matches actual 'Server-Side Request Forgery'."""
        profile = TrainingProfile(
            name="test", target="localhost",
            expected_findings=[
                {"title": "SSRF", "severity": "high", "category": "injection",
                 "plugin_hints": ["ssrf_check"]},
            ],
        )
        tracker = FindingTracker(profile)
        entity = _entity("Server-Side Request Forgery in /api/fetch", "high", "injection")
        assert tracker.check_discovery(entity, step=1) is True

    def test_abbreviation_bola(self):
        """Expected 'BOLA' matches actual with 'Broken Object Level Authorization'."""
        profile = TrainingProfile(
            name="test", target="localhost",
            expected_findings=[
                {"title": "BOLA", "severity": "critical", "category": "auth",
                 "plugin_hints": ["idor_check"]},
            ],
        )
        tracker = FindingTracker(profile)
        entity = _entity(
            "BOLA: Broken Object Level Authorization in /api/v2/vehicle/",
            "critical", "auth",
        )
        assert tracker.check_discovery(entity, step=1) is True

    def test_category_match_with_alias(self):
        """Category 'auth' matches actual category 'bola' via alias."""
        profile = TrainingProfile(
            name="test", target="localhost",
            expected_findings=[
                {"title": "Access Control Issue", "severity": "high", "category": "auth",
                 "plugin_hints": ["idor_check"]},
            ],
        )
        tracker = FindingTracker(profile)
        entity = _entity("Unknown access flaw detected", "high", "bola")
        assert tracker.check_discovery(entity, step=1) is True

    def test_word_overlap(self):
        """Word overlap >= 50% triggers match."""
        profile = TrainingProfile(
            name="test", target="localhost",
            expected_findings=[
                {"title": "Insecure Deserialization Attack", "severity": "high",
                 "category": "injection", "plugin_hints": ["deser_check"]},
            ],
        )
        tracker = FindingTracker(profile)
        entity = _entity(
            "Deserialization vulnerability in /api (insecure)", "high", "injection",
        )
        assert tracker.check_discovery(entity, step=1) is True

    def test_severity_tolerance(self):
        """Medium finding matches HIGH expectation (within +/-1 tolerance)."""
        profile = TrainingProfile(
            name="test", target="localhost",
            expected_findings=[
                {"title": "CSRF", "severity": "high", "category": "csrf",
                 "plugin_hints": ["csrf_check"]},
            ],
        )
        tracker = FindingTracker(profile)
        entity = _entity("CSRF: 2/5 POST form(s) without CSRF token", "medium", "csrf")
        assert tracker.check_discovery(entity, step=1) is True

    def test_severity_too_low_rejected(self):
        """LOW finding does NOT match CRITICAL expectation (too far)."""
        profile = TrainingProfile(
            name="test", target="localhost",
            expected_findings=[
                {"title": "SQL Injection", "severity": "critical", "category": "sqli",
                 "plugin_hints": ["sqli_basic"]},
            ],
        )
        tracker = FindingTracker(profile)
        entity = _entity("SQL Injection info disclosure", "low", "sqli")
        assert tracker.check_discovery(entity, step=1) is False

    def test_jwt_abbreviation(self):
        """Expected 'JWT' matches actual 'JWT secret brute-forced'."""
        profile = TrainingProfile(
            name="test", target="localhost",
            expected_findings=[
                {"title": "JWT", "severity": "critical", "category": "auth",
                 "plugin_hints": ["jwt_attack"]},
            ],
        )
        tracker = FindingTracker(profile)
        entity = _entity("JWT secret brute-forced: weak_secret", "critical", "auth")
        assert tracker.check_discovery(entity, step=1) is True

    def test_xxe_abbreviation(self):
        """Expected 'XXE' matches actual 'XXE injection confirmed'."""
        profile = TrainingProfile(
            name="test", target="localhost",
            expected_findings=[
                {"title": "XXE", "severity": "critical", "category": "injection",
                 "plugin_hints": ["xxe_check"]},
            ],
        )
        tracker = FindingTracker(profile)
        entity = _entity("XXE injection confirmed in /api/xml", "critical", "injection")
        assert tracker.check_discovery(entity, step=1) is True


class TestEdgeCases:
    """Edge cases in matching across profiles."""

    def test_multiple_sqli_disambiguation(self):
        """Two different SQLi findings should match to different expected entries."""
        profile = TrainingProfile(
            name="test", target="localhost",
            expected_findings=[
                {"title": "SQL Injection Login Bypass", "severity": "critical",
                 "category": "sqli", "plugin_hints": ["sqli_basic"]},
                {"title": "SQL Injection Search", "severity": "critical",
                 "category": "sqli", "plugin_hints": ["sqli_basic"]},
            ],
        )
        tracker = FindingTracker(profile)

        e1 = _entity("SQL Injection Login Bypass via /doLogin", "critical", "sqli", "e1")
        e2 = _entity("SQL Injection Search via /search.jsp", "critical", "sqli", "e2")

        tracker.check_discovery(e1, step=1)
        tracker.check_discovery(e2, step=2)

        assert tracker.coverage == 1.0

    def test_graphql_findings(self):
        """GraphQL-specific findings should match correctly."""
        profile = TrainingProfile(
            name="test", target="localhost",
            expected_findings=[
                {"title": "GraphQL Introspection Enabled", "severity": "medium",
                 "category": "config", "plugin_hints": ["graphql_check"]},
                {"title": "SQL Injection", "severity": "critical",
                 "category": "sqli", "plugin_hints": ["graphql_check"]},
            ],
        )
        tracker = FindingTracker(profile)

        e1 = _entity("GraphQL Introspection Enabled at /graphql", "medium", "config", "e1")
        e2 = _entity("SQL injection via GraphQL at /graphql", "critical", "sqli", "e2")

        tracker.check_discovery(e1, step=1)
        tracker.check_discovery(e2, step=2)

        assert tracker.coverage == 1.0

    def test_order_independent_matching(self):
        """Finding discovery order shouldn't affect coverage."""
        profile = TrainingProfile.load(PROFILES_DIR / "pixi.yaml")
        simulated = PIXI

        # Reverse order
        tracker = FindingTracker(profile)
        findings = list(reversed(list(enumerate(simulated))))
        for idx, (i, title) in enumerate(findings):
            ef = profile.expected_findings[i]
            tracker.check_discovery(
                _entity(title, ef.severity, ef.category, f"rev_{idx}"), step=idx,
            )

        assert tracker.coverage == 1.0
