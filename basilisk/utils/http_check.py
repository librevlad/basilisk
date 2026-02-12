"""HTTP reachability utilities — cached scheme resolution for plugins."""

from __future__ import annotations


async def resolve_base_url(host: str, ctx) -> str | None:
    """Get base URL for target using pipeline cache, fallback to manual probe.

    Returns 'https://host' or 'http://host', or None if unreachable.
    """
    scheme_map = ctx.state.get("http_scheme", {})
    if host in scheme_map:
        scheme = scheme_map[host]
        return f"{scheme}://{host}" if scheme else None

    # No cache — try manually (single-plugin mode)
    if ctx.http is None:
        return None
    for scheme in ("https", "http"):
        try:
            await ctx.http.head(f"{scheme}://{host}/", timeout=5.0)
            return f"{scheme}://{host}"
        except Exception:
            continue
    return None
