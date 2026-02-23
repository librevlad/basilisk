"""Provider pool — multi-provider aggregation with strategies."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Literal

from basilisk.core.plugin import BasePlugin
from basilisk.models.result import Finding, PluginResult

if TYPE_CHECKING:
    from basilisk.core.executor import PluginContext
    from basilisk.core.registry import PluginRegistry
    from basilisk.models.target import Target

logger = logging.getLogger(__name__)

Strategy = Literal["all", "first", "fastest"]


class ProviderPool:
    """Aggregator for plugins that provide the same data type.

    Like Laravel Socialite manages OAuth providers —
    single interface, multiple backends, smart merge of results.
    """

    def __init__(self, registry: PluginRegistry) -> None:
        self.registry = registry

    def get_providers(self, provides: str) -> list[type[BasePlugin]]:
        return self.registry.by_provides(provides)

    async def gather(
        self,
        provides: str,
        target: Target,
        ctx: PluginContext,
        strategy: Strategy = "all",
    ) -> PluginResult:
        """Run providers and merge results based on strategy.

        Strategies:
        - "all": run all providers, merge unique results (for subdomains)
        - "first": first successful result (for whois)
        - "fastest": race, take the fastest response
        """
        providers = self.get_providers(provides)
        if not providers:
            return PluginResult.fail(
                f"provider_pool:{provides}", target.host,
                error=f"No providers found for '{provides}'",
            )

        if strategy == "all":
            return await self._gather_all(providers, target, ctx, provides)
        elif strategy == "first":
            return await self._gather_first(providers, target, ctx, provides)
        else:  # fastest
            return await self._gather_fastest(providers, target, ctx, provides)

    async def _gather_all(
        self,
        providers: list[type[BasePlugin]],
        target: Target,
        ctx: PluginContext,
        provides: str,
    ) -> PluginResult:
        """Run all providers, merge unique findings and data."""
        instances = [cls() for cls in providers]
        for inst in instances:
            await inst.setup(ctx)

        async def _run_with_teardown(p: BasePlugin) -> PluginResult:
            try:
                return await p.run(target, ctx)
            finally:
                await p.teardown()

        tasks = [_run_with_teardown(p) for p in instances]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        merged_findings: list[Finding] = []
        merged_data: dict = {}
        seen_titles: set[str] = set()
        errors: list[str] = []
        total_duration = 0.0

        for r in results:
            if isinstance(r, BaseException):
                errors.append(str(r))
                continue
            if not isinstance(r, PluginResult):
                continue
            total_duration += r.duration
            if r.ok:
                for f in r.findings:
                    if f.title not in seen_titles:
                        merged_findings.append(f)
                        seen_titles.add(f.title)
                # Merge data — lists get extended, other values overwritten
                for key, value in r.data.items():
                    if key in merged_data and isinstance(merged_data[key], list):
                        existing = set(merged_data[key])
                        merged_data[key].extend(
                            v for v in value if v not in existing
                        )
                    else:
                        merged_data[key] = value
            elif r.error:
                errors.append(f"{r.plugin}: {r.error}")

        status = "success" if merged_data or merged_findings else "partial"
        return PluginResult(
            plugin=f"provider_pool:{provides}",
            target=target.host,
            status=status,
            findings=merged_findings,
            data=merged_data,
            duration=total_duration,
            error="; ".join(errors) if errors else None,
        )

    async def _gather_first(
        self,
        providers: list[type[BasePlugin]],
        target: Target,
        ctx: PluginContext,
        provides: str,
    ) -> PluginResult:
        """Run providers sequentially, return first success."""
        for cls in providers:
            instance = cls()
            await instance.setup(ctx)
            try:
                result = await instance.run(target, ctx)
                if result.ok:
                    return result
            except Exception as e:
                logger.warning("Provider %s failed: %s", cls.meta.name, e)
                continue
            finally:
                await instance.teardown()

        return PluginResult.fail(
            f"provider_pool:{provides}", target.host,
            error="All providers failed",
        )

    async def _gather_fastest(
        self,
        providers: list[type[BasePlugin]],
        target: Target,
        ctx: PluginContext,
        provides: str,
    ) -> PluginResult:
        """Race all providers, return the fastest success."""
        instances = [cls() for cls in providers]
        for inst in instances:
            await inst.setup(ctx)
        tasks = {asyncio.create_task(p.run(target, ctx)) for p in instances}

        try:
            remaining = tasks
            while remaining:
                done, remaining = await asyncio.wait(
                    remaining, return_when=asyncio.FIRST_COMPLETED,
                )
                for task in done:
                    if task.exception() is None:
                        result = task.result()
                        if isinstance(result, PluginResult) and result.ok:
                            for t in remaining:
                                t.cancel()
                            return result
        except Exception as e:
            logger.warning("Provider race for %s failed: %s", provides, e)
        finally:
            for t in tasks:
                if not t.done():
                    t.cancel()
            for inst in instances:
                await inst.teardown()

        return PluginResult.fail(
            f"provider_pool:{provides}", target.host,
            error="All providers failed or timed out",
        )
