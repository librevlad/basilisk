"""Plugin -> Capability mapping for all registered plugins.

Declarative mapping loaded from YAML data files. Plugins not explicitly
listed get auto-inferred defaults from PluginMeta.
"""

from __future__ import annotations

from basilisk.capabilities.capability import ActionType, Capability
from basilisk.capabilities.loader import load_capability_map
from basilisk.core.registry import PluginRegistry

# Explicit capability map loaded from YAML data/ files.
# Format: plugin_name -> {requires, produces, cost, noise, ...}
CAPABILITY_MAP: dict[str, dict] = load_capability_map()


def _noise_from_risk(risk_level: str) -> float:
    """Derive noise score from plugin risk_level."""
    return {"safe": 1.0, "noisy": 5.0, "destructive": 9.0}.get(risk_level, 1.0)


_CATEGORY_TO_ACTION: dict[str, ActionType] = {
    "recon": ActionType.ENUMERATION,
    "scanning": ActionType.ENUMERATION,
    "analysis": ActionType.EXPERIMENT,
    "pentesting": ActionType.EXPERIMENT,
    "exploitation": ActionType.EXPLOIT,
    "lateral": ActionType.EXPLOIT,
    "privesc": ActionType.EXPLOIT,
    "post_exploit": ActionType.EXPLOIT,
    "crypto": ActionType.EXPERIMENT,
    "forensics": ActionType.ENUMERATION,
}


def _infer_action_type(category: str, reduces_uncertainty: list[str]) -> ActionType:
    """Auto-infer action type from category, with verification override."""
    if reduces_uncertainty:
        return ActionType.VERIFICATION
    return _CATEGORY_TO_ACTION.get(category, ActionType.ENUMERATION)


def _infer_state_delta(
    produces: list[str], reduces: list[str],
) -> dict[str, object]:
    """Auto-infer expected state delta from produces/reduces knowledge."""
    delta: dict[str, object] = {}
    if produces:
        delta["produces_entities"] = produces
    if reduces:
        delta["strengthens_entities"] = reduces
        delta["uncertainty_reduction"] = 0.3
    else:
        delta["uncertainty_reduction"] = 0.1
    return delta


_CATEGORY_TO_DOMAIN: dict[str, str] = {
    "recon": "recon",
    "scanning": "network",
    "analysis": "web",
    "pentesting": "web",
    "exploitation": "web",
    "lateral": "auth",
    "privesc": "auth",
    "post_exploit": "general",
    "crypto": "crypto",
    "forensics": "forensics",
}


def _infer_risk_domain(category: str) -> str:
    """Auto-infer risk_domain from plugin category."""
    return _CATEGORY_TO_DOMAIN.get(category, "general")


def _build_from_map(
    name: str, category: str, timeout: float, m: dict,
) -> Capability:
    """Build a Capability from an explicit CAPABILITY_MAP entry."""
    reduces = m.get("reduces_uncertainty", [])
    produces = m["produces"]
    detects = m.get("detects", [])
    return Capability(
        name=name,
        plugin_name=name,
        category=category,
        requires_knowledge=m["requires"],
        produces_knowledge=produces,
        cost_score=m["cost"],
        noise_score=m["noise"],
        execution_time_estimate=timeout,
        reduces_uncertainty=reduces,
        risk_domain=m.get("risk_domain", _infer_risk_domain(category)),
        action_type=_infer_action_type(category, reduces),
        expected_state_delta=_infer_state_delta(produces, reduces),
        detects=detects,
    )


def _build_inferred(
    name: str, category: str, timeout: float,
    *, requires_http: bool = True, produces_list: list[str] | None = None,
    risk_level: str = "safe",
) -> Capability:
    """Build a Capability with auto-inferred defaults from PluginMeta."""
    requires = ["Host"]
    if requires_http:
        requires.append("Service:http")
    produces = produces_list or ["Finding"]
    return Capability(
        name=name,
        plugin_name=name,
        category=category,
        requires_knowledge=requires,
        produces_knowledge=produces,
        cost_score=min(timeout / 10.0, 10.0),
        noise_score=_noise_from_risk(risk_level),
        execution_time_estimate=timeout,
        risk_domain=_infer_risk_domain(category),
        action_type=_infer_action_type(category, []),
        expected_state_delta=_infer_state_delta(produces, []),
    )


def build_capabilities_from_scenarios(registry: object) -> dict[str, Capability]:
    """Build Capability metadata from a ScenarioRegistry.

    For LegacyPluginScenario instances: uses CAPABILITY_MAP + auto-inference.
    For native scenarios: builds directly from ScenarioMeta fields.
    """
    from basilisk.bridge.legacy_scenario import LegacyPluginScenario

    capabilities: dict[str, Capability] = {}

    for scenario in registry.all_scenarios():
        name = scenario.meta.name

        if isinstance(scenario, LegacyPluginScenario):
            meta = scenario.plugin_cls.meta
            if name in CAPABILITY_MAP:
                cap = _build_from_map(
                    name, meta.category.value, meta.timeout, CAPABILITY_MAP[name],
                )
            else:
                produces = list(meta.produces) if meta.produces else None
                cap = _build_inferred(
                    name, meta.category.value, meta.timeout,
                    requires_http=meta.requires_http,
                    produces_list=produces,
                    risk_level=meta.risk_level,
                )
        else:
            # Native v4 scenario — build from ScenarioMeta directly
            sm = scenario.meta
            category = sm.category
            requires = sm.requires_knowledge or ["Host"]
            produces = sm.produces_knowledge or ["Finding"]
            reduces: list[str] = []
            cap = Capability(
                name=name,
                plugin_name=name,
                category=category,
                requires_knowledge=requires,
                produces_knowledge=produces,
                cost_score=sm.cost_score,
                noise_score=sm.noise_score,
                execution_time_estimate=sm.timeout,
                risk_domain=_infer_risk_domain(category),
                action_type=_infer_action_type(category, reduces),
                expected_state_delta=_infer_state_delta(produces, reduces),
            )

        capabilities[name] = cap

    return capabilities


def build_capabilities(registry: PluginRegistry) -> dict[str, Capability]:
    """Build Capability metadata for all registered plugins.

    Plugins in CAPABILITY_MAP use explicit values.
    Others get auto-inferred defaults from PluginMeta.
    """
    capabilities: dict[str, Capability] = {}

    for plugin_cls in registry.all():
        meta = plugin_cls.meta
        name = meta.name

        if name in CAPABILITY_MAP:
            cap = _build_from_map(
                name, meta.category.value, meta.timeout, CAPABILITY_MAP[name],
            )
        else:
            produces = list(meta.produces) if meta.produces else None
            cap = _build_inferred(
                name, meta.category.value, meta.timeout,
                requires_http=meta.requires_http,
                produces_list=produces,
                risk_level=meta.risk_level,
            )

        capabilities[name] = cap

    return capabilities
