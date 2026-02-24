"""Context adapter — Actor -> PluginContext for legacy plugins."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from basilisk.core.executor import PluginContext

if TYPE_CHECKING:
    from basilisk.actor.composite import CompositeActor
    from basilisk.config import Settings


class ContextAdapter:
    """Builds a v3 PluginContext from a v4 CompositeActor + tools dict.

    Maps all 22+ PluginContext fields from actor and tools.
    """

    @staticmethod
    def build(
        actor: CompositeActor,
        settings: Settings,
        tools: dict[str, Any] | None = None,
        state: dict[str, Any] | None = None,
    ) -> PluginContext:
        """Create a PluginContext bridging v4 actor to v3 interface."""
        tools = tools or {}
        return PluginContext(
            config=settings,
            http=actor.http_client,
            dns=actor.dns_client,
            net=actor.net_utils,
            rate=actor.rate_limiter,
            db=tools.get("db"),
            wordlists=tools.get("wordlists"),
            providers=tools.get("providers"),
            auth=tools.get("auth"),
            browser=actor.browser,
            callback=tools.get("callback"),
            differ=tools.get("differ"),
            payloads=tools.get("payloads"),
            waf_bypass=tools.get("waf_bypass"),
            dynamic_wordlist=tools.get("dynamic_wordlist"),
            oob=tools.get("oob"),
            shell=tools.get("shell"),
            creds=tools.get("creds"),
            smb=tools.get("smb"),
            ldap=tools.get("ldap"),
            ssh=tools.get("ssh"),
            subprocess_mgr=tools.get("subprocess_mgr"),
            crypto=tools.get("crypto"),
            pcap=tools.get("pcap"),
            pipeline=tools.get("pipeline", {}),
            state=state if state is not None else {},
            _deadline=actor._deadline,
        )
