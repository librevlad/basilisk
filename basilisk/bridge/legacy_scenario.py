"""Legacy plugin adapter — wraps any v3 BasePlugin as a v4 Scenario."""

from __future__ import annotations

from typing import Any, ClassVar

from basilisk.bridge.context_adapter import ContextAdapter
from basilisk.bridge.result_adapter import ResultAdapter
from basilisk.domain.scenario import Scenario, ScenarioMeta, ScenarioResult


class LegacyPluginScenario(Scenario):
    """Wraps a v3 BasePlugin so it looks like a v4 Scenario.

    This is the critical migration bridge — all 194 existing plugins
    work through this adapter without any code changes.
    """

    meta: ClassVar[ScenarioMeta]

    def __init__(self, plugin_cls: type) -> None:
        self._plugin_cls = plugin_cls
        self._plugin_instance = plugin_cls()

    @classmethod
    def wrap(cls, plugin_cls: type) -> LegacyPluginScenario:
        """Wrap a v3 plugin class into a LegacyPluginScenario instance."""
        instance = cls.__new__(cls)
        instance._plugin_cls = plugin_cls
        instance._plugin_instance = plugin_cls()

        # Derive ScenarioMeta from PluginMeta
        pm = plugin_cls.meta
        cap = _get_capability_info(pm.name)

        instance.__class__ = type(
            f"Legacy_{pm.name}",
            (LegacyPluginScenario,),
            {"meta": ScenarioMeta(
                name=pm.name,
                display_name=pm.display_name,
                category=pm.category.value if hasattr(pm.category, "value") else str(pm.category),
                description=pm.description,
                depends_on=pm.depends_on,
                produces=pm.produces,
                timeout=pm.timeout,
                requires_auth=pm.requires_auth,
                risk_level=pm.risk_level,
                requires_knowledge=cap.get("requires", ["Host"]),
                produces_knowledge=cap.get("produces", ["Finding"]),
                cost_score=cap.get("cost", min(pm.timeout / 10.0, 10.0)),
                noise_score=cap.get("noise", _noise_from_risk(pm.risk_level)),
            )},
        )
        return instance

    async def run(
        self,
        target: Any,
        actor: Any,
        surfaces: list[Any],
        tools: dict[str, Any],
    ) -> ScenarioResult:
        """Run the wrapped v3 plugin through the bridge."""

        # Convert v4 target → v3 target
        v3_target = _to_v3_target(target)

        # Build PluginContext from actor
        settings = tools.get("settings") or tools.get("config")
        if settings is None:
            from basilisk.config import Settings
            settings = Settings.load()

        ctx = ContextAdapter.build(
            actor, settings, tools=tools, state=tools.get("state", {}),
        )

        # Run the v3 plugin
        result = await self._plugin_instance.run(v3_target, ctx)

        # Convert v3 result → v4 result
        return ResultAdapter.to_scenario_result(result)

    def accepts(self, target: Any) -> bool:
        v3_target = _to_v3_target(target)
        return self._plugin_instance.accepts(v3_target)

    @property
    def plugin_cls(self) -> type:
        return self._plugin_cls


def _to_v3_target(target: Any) -> Any:
    """Convert a v4 BaseTarget to a v3 Target."""
    from basilisk.models.target import Target as V3Target

    if isinstance(target, V3Target):
        return target
    return V3Target(
        host=target.host,
        ports=target.ports,
        meta=target.meta,
    )


def _get_capability_info(plugin_name: str) -> dict:
    """Get capability info from CAPABILITY_MAP, with fallback."""
    try:
        from basilisk.capabilities.mapping import CAPABILITY_MAP
        return CAPABILITY_MAP.get(plugin_name, {})
    except Exception:
        return {}


def _noise_from_risk(risk_level: str) -> float:
    """Convert risk_level to noise_score."""
    return {"safe": 1.0, "noisy": 5.0, "destructive": 8.0}.get(risk_level, 1.0)
