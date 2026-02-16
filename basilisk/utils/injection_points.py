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
        """Build POST form data, injecting value into target param."""
        return {
            p: (value if p == param else v or "1")
            for p, v in self.params.items()
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
    1. Crawled URLs with query parameters (most likely to be real endpoints)
    2. Discovered forms with input names
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

    def _add(point: InjectionPoint) -> bool:
        """Add point if not duplicate. Returns True if added."""
        key = f"{point.method}:{point.path}:{sorted(point.params.keys())}"
        if key in seen or len(points) >= max_points:
            return False
        # Apply param filter if specified
        if param_filter and not any(p in param_filter for p in point.params):
            return False
        seen.add(key)
        points.append(point)
        return True

    # ── 1. Crawled URLs (full path + actual query params) ────────────
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
            _add(InjectionPoint(path=path, params=params, source="crawled"))

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

    # ── 2. Discovered forms (action + input names/values) ────────────
    forms = state.get("discovered_forms", {}).get(host, [])
    for form in forms:
        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", [])

        # Parse action URL to extract path
        if action:
            parsed = urlparse(action)
            path = parsed.path or "/"
        else:
            path = "/"

        if inputs:
            # inputs can be dict[str, str] (name→value) or list[str] (legacy)
            if isinstance(inputs, dict):
                params = inputs
            else:
                params = {inp: "" for inp in inputs}
            _add(InjectionPoint(path=path, params=params, method=method, source="form"))

    # ── 3. API paths from analysis plugins ───────────────────────────
    api_paths = state.get("discovered_api_paths", {}).get(host, [])
    hp = hardcoded_params or []
    for api_path in api_paths:
        if hp:
            params = {hp[0]: "1"}
            _add(InjectionPoint(path=api_path, params=params, source="api"))
        else:
            _add(InjectionPoint(path=api_path, params={}, source="api"))

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

    # Iterate params first so each path gets at least one test
    for param in (hardcoded_params or [])[:8]:
        for apath, asource in all_paths:
            _add(InjectionPoint(path=apath, params={param: "1"}, source=asource))

    return points
