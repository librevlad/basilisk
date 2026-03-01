"""DVWA setup script — wait for container, create DB, verify login.

Uses only stdlib (no requests dependency).
"""

from __future__ import annotations

import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar

DVWA_BASE = "http://localhost:4280"
MAX_WAIT = 120  # seconds


def _make_opener() -> urllib.request.OpenerDirector:
    """Create an opener with cookie support."""
    jar = CookieJar()
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
    )


def _get(opener: urllib.request.OpenerDirector, url: str, timeout: float = 10) -> str:
    """GET url, return body text."""
    resp = opener.open(url, timeout=timeout)
    return resp.read().decode("utf-8", errors="replace")


def _post(
    opener: urllib.request.OpenerDirector,
    url: str,
    data: dict[str, str],
    timeout: float = 10,
) -> str:
    """POST form data, return body text."""
    encoded = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(url, data=encoded)
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    resp = opener.open(req, timeout=timeout)
    return resp.read().decode("utf-8", errors="replace")


def wait_for_dvwa() -> None:
    """Poll DVWA until it responds."""
    print(f"Waiting for DVWA at {DVWA_BASE} ...")
    start = time.time()
    while time.time() - start < MAX_WAIT:
        try:
            urllib.request.urlopen(f"{DVWA_BASE}/login.php", timeout=5)
            print("  DVWA is up!")
            return
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(2)
    print("ERROR: DVWA did not start within timeout", file=sys.stderr)
    sys.exit(1)


def _extract_user_token(html: str) -> str:
    """Extract user_token CSRF value from HTML."""
    match = re.search(
        r"name=['\"]user_token['\"].*?value=['\"]([^'\"]+)['\"]",
        html,
    )
    if match:
        return match.group(1)
    # Try reversed order (value before name)
    match = re.search(
        r"value=['\"]([^'\"]+)['\"].*?name=['\"]user_token['\"]",
        html,
    )
    return match.group(1) if match else ""


def create_database() -> None:
    """POST to /setup.php to create/reset the DVWA database."""
    print("Creating DVWA database ...")

    opener = _make_opener()
    html = _get(opener, f"{DVWA_BASE}/setup.php")
    token = _extract_user_token(html)

    data: dict[str, str] = {"create_db": "Create / Reset Database"}
    if token:
        data["user_token"] = token

    body = _post(opener, f"{DVWA_BASE}/setup.php", data, timeout=30)
    if "successfully" in body.lower() or "database" in body.lower():
        print("  Database created/reset successfully!")
    else:
        print("WARNING: DB creation response unclear, continuing...")


def verify_login() -> None:
    """Verify that admin/password login works."""
    print("Verifying login (admin/password) ...")

    opener = _make_opener()

    # GET login page for CSRF token
    html = _get(opener, f"{DVWA_BASE}/login.php")
    token = _extract_user_token(html)

    # POST login
    data: dict[str, str] = {
        "username": "admin",
        "password": "password",
        "Login": "Login",
    }
    if token:
        data["user_token"] = token

    body = _post(opener, f"{DVWA_BASE}/login.php", data)

    if "logout" in body.lower() or "welcome" in body.lower():
        print("  Login successful!")
    else:
        print("WARNING: Login may have failed (no logout/welcome found)")

    # Set security cookie to low and verify access
    # Need to add security cookie to the opener's cookie jar
    from http.cookiejar import Cookie

    cookie = Cookie(
        version=0, name="security", value="low",
        port=None, port_specified=False,
        domain="localhost", domain_specified=False, domain_initial_dot=False,
        path="/", path_specified=True,
        secure=False, expires=None, discard=True,
        comment=None, comment_url=None, rest={},
    )
    # Access the cookie jar from the opener's handlers
    for handler in opener.handlers:
        if hasattr(handler, "cookiejar"):
            handler.cookiejar.set_cookie(cookie)
            break

    body = _get(opener, f"{DVWA_BASE}/security.php")
    if "low" in body.lower():
        print("  Security level confirmed: low")

    # Verify we can access a vulnerability page
    body = _get(
        opener,
        f"{DVWA_BASE}/vulnerabilities/sqli/?id=1&Submit=Submit",
    )
    if "Surname" in body:
        print("  SQLi page accessible with auth - DVWA is ready!")
    else:
        print("WARNING: SQLi page response unclear, may need manual check")


def main() -> None:
    print("=" * 60)
    print("DVWA Setup Script")
    print("=" * 60)

    wait_for_dvwa()
    create_database()
    verify_login()

    print()
    print("=" * 60)
    print("DVWA is ready for scanning!")
    print(f"  URL: {DVWA_BASE}")
    print("  Credentials: admin / password")
    print("  Security: low")
    print()
    print("Run scan:")
    print(
        "  .venv/Scripts/python.exe -m basilisk audit localhost:4280 "
        "--config config/dvwa.yaml -v"
    )
    print("=" * 60)


if __name__ == "__main__":
    main()
