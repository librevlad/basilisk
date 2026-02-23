"""In-memory campaign aggregator — query interface for the scorer."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from basilisk.campaign.extractor import (
    extract_plugin_efficacy,
    extract_target_profiles,
    extract_tech_fingerprints,
)
from basilisk.campaign.models import PluginEfficacy, TargetProfile, TechFingerprint

if TYPE_CHECKING:
    from basilisk.campaign.store import CampaignStore
    from basilisk.knowledge.graph import KnowledgeGraph
    from basilisk.memory.history import History

logger = logging.getLogger(__name__)


class CampaignMemory:
    """Cross-audit memory loaded from CampaignStore.

    Provides query methods consumed by Scorer for campaign-aware scoring,
    and update methods called after each audit to persist new knowledge.
    """

    def __init__(self) -> None:
        self._profiles: dict[str, TargetProfile] = {}
        self._efficacy: dict[str, PluginEfficacy] = {}
        self._fingerprints: dict[str, TechFingerprint] = {}

    # --- Load / Save ---

    async def load(self, store: CampaignStore, hosts: list[str]) -> None:
        """Load relevant data from the campaign store."""
        # Load profiles for requested hosts
        for host in hosts:
            profile = await store.load_target_profile(host)
            if profile is not None:
                self._profiles[host] = profile

        # Load all plugin efficacy (global stats)
        for eff in await store.load_all_plugin_efficacy():
            self._efficacy[eff.plugin_name] = eff

        # Load tech fingerprints for relevant domains
        seen_domains: set[str] = set()
        for host in hosts:
            base = _extract_base_domain(host)
            if base not in seen_domains:
                seen_domains.add(base)
                fp = await store.load_tech_fingerprint(base)
                if fp is not None:
                    self._fingerprints[base] = fp

        logger.info(
            "Campaign memory loaded: %d profiles, %d efficacy records, %d fingerprints",
            len(self._profiles), len(self._efficacy), len(self._fingerprints),
        )

    async def save(self, store: CampaignStore) -> None:
        """Persist current state to the campaign store."""
        for profile in self._profiles.values():
            await store.save_target_profile(profile)
        for eff in self._efficacy.values():
            await store.save_plugin_efficacy(eff)
        for fp in self._fingerprints.values():
            await store.save_tech_fingerprint(fp)

    # --- Query methods for Scorer ---

    def plugin_success_rate(self, plugin_name: str) -> float:
        """Global success rate across all past audits."""
        eff = self._efficacy.get(plugin_name)
        if eff is None:
            return 0.0
        return eff.success_rate

    def plugin_tech_rate(self, plugin_name: str, techs: list[str]) -> float | None:
        """Success rate for a plugin on a specific tech stack.

        Returns None if insufficient data (< 3 runs on this stack).
        """
        eff = self._efficacy.get(plugin_name)
        if eff is None:
            return None
        key = eff.tech_stack_key(techs)
        if not key:
            return None
        ts = eff.tech_stack_stats.get(key)
        if ts is None or ts.runs < 3:
            return None
        return ts.success_rate

    def adjusted_cost(self, plugin_name: str, base_cost: float) -> float:
        """Campaign-aware cost adjustment.

        - Tech-specific rate > 0.7 → discount (base * 0.6)
        - Tech-specific rate < 0.2 → penalty (base * 1.8)
        - Fallback → linear interpolation from global rate
        """
        eff = self._efficacy.get(plugin_name)
        if eff is None or eff.total_runs < 2:
            return base_cost

        rate = eff.success_rate
        multiplier = 2.0 - 1.3 * rate
        return base_cost * max(multiplier, 0.5)

    def is_known_infrastructure(self, host: str, port: int) -> bool:
        """Check if we've seen this (host, port) in a previous audit."""
        profile = self._profiles.get(host)
        if profile is None:
            return False
        return any(s.port == port for s in profile.known_services)

    def known_technologies(self, host: str) -> list[str]:
        """Return technology names known for this host from past audits."""
        profile = self._profiles.get(host)
        if profile is None:
            return []
        return [t.name for t in profile.known_technologies]

    def get_profile(self, host: str) -> TargetProfile | None:
        """Get the stored profile for a host."""
        return self._profiles.get(host)

    # --- Update after audit ---

    def update_from_graph(self, graph: KnowledgeGraph, history: History) -> None:
        """Extract and merge new data from the completed audit."""
        # Merge target profiles
        for profile in extract_target_profiles(graph):
            existing = self._profiles.get(profile.host)
            if existing is not None:
                profile.audit_count = existing.audit_count + 1
                # Merge services (union by port+protocol)
                existing_svc_keys = {
                    (s.port, s.protocol) for s in existing.known_services
                }
                for svc in profile.known_services:
                    if (svc.port, svc.protocol) not in existing_svc_keys:
                        existing.known_services.append(svc)
                profile.known_services = existing.known_services
            self._profiles[profile.host] = profile

        # Merge plugin efficacy
        for eff in extract_plugin_efficacy(history):
            existing = self._efficacy.get(eff.plugin_name)
            if existing is not None:
                eff.total_runs += existing.total_runs
                eff.total_successes += existing.total_successes
                eff.total_new_entities += existing.total_new_entities
                eff.total_findings += existing.total_findings
                eff.total_runtime += existing.total_runtime
                # Merge tech stack stats
                for key, ts in existing.tech_stack_stats.items():
                    if key in eff.tech_stack_stats:
                        merged = eff.tech_stack_stats[key]
                        merged.runs += ts.runs
                        merged.successes += ts.successes
                        merged.new_entities += ts.new_entities
                        merged.findings += ts.findings
                    else:
                        eff.tech_stack_stats[key] = ts
            self._efficacy[eff.plugin_name] = eff

        # Merge tech fingerprints
        for fp in extract_tech_fingerprints(graph):
            existing = self._fingerprints.get(fp.base_domain)
            if existing is not None:
                merged_techs = sorted(set(existing.technologies) | set(fp.technologies))
                fp.technologies = merged_techs
                fp.observation_count = existing.observation_count + 1
            self._fingerprints[fp.base_domain] = fp


def _extract_base_domain(host: str) -> str:
    """Extract the base domain (last two labels) from a hostname."""
    parts = host.rstrip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host
