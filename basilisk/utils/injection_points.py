"""Injection point extraction from crawled URLs and discovered forms.

Pentesting plugins use this to build their scan target list from
actual crawled data (URLs + forms) instead of relying solely on
hardcoded paths and parameter names.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from urllib.parse import parse_qs, quote, urlparse

logger = logging.getLogger(__name__)

# Params that are submit buttons / CSRF tokens — exclude from POST body
# unless they are the param under test.  Some apps (e.g. XVWA) reject
# requests when both a data param and a submit-button param are present.
_SKIP_POST_PARAMS: frozenset[str] = frozenset({
    "submit", "login", "logout", "reset", "user_token", "csrf_token",
    "csrf", "_token", "token", "captcha", "recaptcha", "g-recaptcha-response",
    "btnsubmit", "button", "go", "send", "save",
})


@dataclass
class InjectionPoint:
    """A single testable endpoint: path + param + method."""

    path: str
    params: dict[str, str] = field(default_factory=dict)
    method: str = "GET"
    source: str = "crawled"  # "crawled" | "form" | "hardcoded" | "api"

    @property
    def primary_param(self) -> str | None:
        """First parameter name (for single-param testing)."""
        return next(iter(self.params), None)

    def build_url(self, base_url: str, param: str, value: str) -> str:
        """Build GET URL with all form params, injecting value into target param.

        Includes all other params with their original values so forms
        that check for required fields (e.g. Submit=Submit) work correctly.
        """
        parts = []
        for p, v in self.params.items():
            if p == param:
                parts.append(f"{p}={quote(value)}")
            else:
                parts.append(f"{p}={quote(v or '1')}")
        return f"{base_url}{self.path}?{'&'.join(parts)}"

    def build_post_data(self, param: str, value: str) -> dict[str, str]:
        """Build POST form data, excluding skip-params not being tested.

        Some apps reject requests when both a data param and a submit-button
        param are present.  We exclude known button/token params from the body
        unless they are the specific param under test.

        Non-tested params keep their original value (empty string if empty).
        This avoids breaking apps that check for mutual exclusion between
        parameters (e.g. XVWA rejects when both 'item' and 'search' are set).
        """
        return {
            p: (value if p == param else v)
            for p, v in self.params.items()
            if p == param or p.lower() not in _SKIP_POST_PARAMS
        }


def collect_injection_points(
    host: str,
    ctx,
    *,
    hardcoded_paths: list[str] | None = None,
    hardcoded_params: list[str] | None = None,
    param_filter: list[str] | None = None,
    max_points: int = 50,
) -> list[InjectionPoint]:
    """Collect injection points from all pipeline sources.

    Priority order (highest first):
    1. Discovered forms with input names (most accurate — real method + params)
    2. Crawled URLs with query parameters
    3. API paths from js_api_extract / api_detect
    4. Hardcoded fallback paths × params

    Args:
        host: Target hostname.
        ctx: PluginContext with state dict.
        hardcoded_paths: Plugin's own fallback scan paths.
        hardcoded_params: Plugin's own fallback parameter names.
        param_filter: If set, only include points where at least one
            param name is in this list (for focused plugins like LFI).
        max_points: Maximum number of points to return.

    Returns:
        Deduplicated list of InjectionPoint, highest priority first.
    """
    state = ctx.state if hasattr(ctx, "state") else {}
    points: list[InjectionPoint] = []
    seen: set[str] = set()

    def _add(point: InjectionPoint, *, skip_filter: bool = False) -> bool:
        """Add point if not duplicate. Returns True if added."""
        key = f"{point.method}:{point.path}:{sorted(point.params.keys())}"
        if key in seen or len(points) >= max_points:
            return False
        # Apply param filter only to hardcoded/api points, not crawled/form
        if param_filter and not skip_filter and not any(
            p in param_filter for p in point.params
        ):
            return False
        seen.add(key)
        points.append(point)
        return True

    # ── 1. Discovered forms (action + input names/values) ────────────
    # Forms are highest priority: they have the correct method and
    # accurate param names from HTML parsing (form_analyzer).
    forms = state.get("discovered_forms", {}).get(host, [])
    for form in forms:
        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", [])

        # Parse action URL to extract path
        if action:
            parsed = urlparse(action)
            path = parsed.path or "/"
            if path and not path.startswith("/"):
                path = f"/{path}"
        else:
            path = "/"

        if inputs:
            # inputs can be:
            #   dict[str, str]  — from form_analyzer (name→value)
            #   list[str]       — legacy format (just names)
            #   list[dict]      — from web_crawler ({"name": ..., "type": ..., "value": ...})
            if isinstance(inputs, dict):
                params = inputs
            elif isinstance(inputs, list) and inputs and isinstance(inputs[0], dict):
                params = {
                    inp["name"]: inp.get("value", "")
                    for inp in inputs if isinstance(inp, dict) and "name" in inp
                }
            else:
                params = {inp: "" for inp in inputs}
            _add(
                InjectionPoint(path=path, params=params, method=method, source="form"),
                skip_filter=True,
            )

    # ── 2. Crawled URLs (full path + actual query params) ────────────
    crawled_urls = state.get("crawled_urls", {}).get(host, [])
    for url in crawled_urls:
        parsed = urlparse(url)
        if not parsed.query:
            continue
        path = parsed.path or "/"
        params = {}
        for k, v_list in parse_qs(parsed.query, keep_blank_values=True).items():
            params[k] = v_list[0] if v_list else ""
        if params:
            _add(InjectionPoint(path=path, params=params, source="crawled"), skip_filter=True)
            # Also create POST variant for extensionless paths (likely API endpoints)
            last_seg = path.rsplit("/", 1)[-1]
            if "." not in last_seg:
                _add(
                    InjectionPoint(path=path, params=params, method="POST", source="crawled"),
                    skip_filter=True,
                )

    # Also add crawled URLs without params as paths for hardcoded param testing
    crawled_paths: list[str] = []
    for url in crawled_urls:
        parsed = urlparse(url)
        path = parsed.path or "/"
        if path not in crawled_paths and (
            path.endswith((".php", ".asp", ".aspx", ".jsp", ".cgi"))
            or "." not in path.rsplit("/", 1)[-1]  # extensionless = likely dynamic
        ):
            crawled_paths.append(path)

    # ── 3. API paths from analysis plugins ───────────────────────────
    api_paths = state.get("discovered_api_paths", {}).get(host, [])
    hp = hardcoded_params or []
    for api_path in api_paths:
        if hp:
            for param in hp[:4]:
                _add(InjectionPoint(path=api_path, params={param: "1"}, source="api"))
        # Never add points with empty params — plugins skip them entirely

    # ── 4. All paths × hardcoded params (breadth-first) ──────────────
    # Merge crawled paths + hardcoded paths into a single pool,
    # deduplicated, so both get tested within the max_points budget.
    all_paths: list[tuple[str, str]] = []  # (path, source)
    seen_paths: set[str] = set()
    for cpath in crawled_paths:
        if cpath not in seen_paths:
            seen_paths.add(cpath)
            all_paths.append((cpath, "crawled"))
    for hpath in (hardcoded_paths or []):
        if hpath not in seen_paths:
            seen_paths.add(hpath)
            all_paths.append((hpath, "hardcoded"))

    # ── 4b. POST variants for extensionless crawled paths ─────────────
    # Only for crawled paths (scan_paths → crawled_urls); hardcoded plugin
    # paths are GET-only by convention — plugins handle POST themselves.
    for apath, asource in all_paths:
        if asource != "crawled":
            continue
        last_seg = apath.rsplit("/", 1)[-1]
        if "." not in last_seg:  # extensionless = likely API/form
            for param in (hardcoded_params or [])[:4]:
                _add(InjectionPoint(
                    path=apath, params={param: "1"}, method="POST", source=asource,
                ))

    # Iterate params first so each path gets at least one test
    for param in (hardcoded_params or [])[:8]:
        for apath, asource in all_paths:
            _add(InjectionPoint(path=apath, params={param: "1"}, source=asource))

    return points
