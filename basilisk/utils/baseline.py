"""Baseline comparison utility for injection detection plugins.

Provides a common pattern: fetch a baseline response (no payload), then
fetch the same URL with a payload, and compare the two to determine if
the payload caused a meaningful change.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class InjectionDiff:
    """Result of comparing a baseline response with an injected response."""

    new_content: list[str] = field(default_factory=list)
    status_changed: bool = False
    size_delta: int = 0
    new_headers: set[str] = field(default_factory=set)
    baseline_status: int = 0
    injected_status: int = 0

    @property
    def has_new_content(self) -> bool:
        return bool(self.new_content)

    @property
    def is_significant(self) -> bool:
        """True if the diff indicates a meaningful change."""
        return (
            self.status_changed
            or self.has_new_content
            or abs(self.size_delta) > 200
            or bool(self.new_headers)
        )


def diff_texts(baseline: str, injected: str) -> list[str]:
    """Return lines present in injected but not in baseline."""
    base_lines = set(baseline.splitlines())
    return [
        line for line in injected.splitlines()
        if line and line not in base_lines
    ]


async def compare_with_baseline(
    url: str,
    payload_url: str,
    ctx,
) -> InjectionDiff:
    """Fetch baseline and injected URLs, return their diff.

    Args:
        url: Clean URL (no payload) for baseline.
        payload_url: URL with injection payload.
        ctx: PluginContext with http and rate.
    """
    try:
        async with ctx.rate:
            baseline_resp = await ctx.http.get(url, timeout=8.0)
            baseline_text = await baseline_resp.text(
                encoding="utf-8", errors="replace",
            )
            baseline_headers = set(baseline_resp.headers.keys())
            baseline_status = baseline_resp.status
    except Exception:
        return InjectionDiff()

    try:
        async with ctx.rate:
            injected_resp = await ctx.http.get(payload_url, timeout=8.0)
            injected_text = await injected_resp.text(
                encoding="utf-8", errors="replace",
            )
            injected_headers = set(injected_resp.headers.keys())
            injected_status = injected_resp.status
    except Exception:
        return InjectionDiff()

    return InjectionDiff(
        new_content=diff_texts(baseline_text, injected_text),
        status_changed=baseline_status != injected_status,
        size_delta=len(injected_text) - len(baseline_text),
        new_headers=injected_headers - baseline_headers,
        baseline_status=baseline_status,
        injected_status=injected_status,
    )


def marker_in_diff(marker: str, baseline: str, injected: str) -> bool:
    """Check if marker appears in injected response but NOT in baseline."""
    return marker in injected and marker not in baseline
