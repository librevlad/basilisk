"""Audit facade — elegant fluent API (Laravel-style)."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from basilisk.config import Settings
from basilisk.core.executor import AsyncExecutor, PluginContext
from basilisk.core.pipeline import (
    OnProgressCallback,
    Pipeline,
    PipelineState,
    _is_ip_or_local,
    _noop_progress,
)
from basilisk.core.providers import ProviderPool
from basilisk.core.registry import PluginRegistry
from basilisk.models.result import Finding
from basilisk.models.target import Target, TargetScope
from basilisk.utils.dns import DnsClient
from basilisk.utils.http import AsyncHttpClient
from basilisk.utils.net import NetUtils
from basilisk.utils.rate_limiter import RateLimiter
from basilisk.utils.wordlists import WordlistManager

if TYPE_CHECKING:
    from basilisk.models.project import Project

logger = logging.getLogger(__name__)


def _split_host_port(raw: str) -> tuple[str, int | None]:
    """Split 'host:port' into (host, port). Returns (raw, None) if no port."""
    if raw.startswith("["):
        # [::1]:8080 → ::1, 8080
        bracket_end = raw.find("]")
        if bracket_end != -1 and bracket_end + 1 < len(raw) and raw[bracket_end + 1] == ":":
            host = raw[1:bracket_end]
            try:
                return host, int(raw[bracket_end + 2:])
            except ValueError:
                return raw, None
        return raw[1:bracket_end] if bracket_end != -1 else raw, None
    if "." in raw and ":" in raw:
        # 127.0.0.1:4280 → 127.0.0.1, 4280 (IPv4 with port)
        host, _, port_s = raw.rpartition(":")
        try:
            return host, int(port_s)
        except ValueError:
            return raw, None
    if raw == "localhost":
        return raw, None
    # localhost:8080
    if raw.startswith("localhost:"):
        try:
            return "localhost", int(raw[len("localhost:"):])
        except ValueError:
            return raw, None
    return raw, None


class Audit:
    """Fluent API for running security audits.

    Usage:
        results = await (
            Audit("magnit.ru")
            .discover()
            .scan()
            .analyze()
            .pentest()
            .report(["json", "html"])
        )
    """

    def __init__(
        self,
        *targets: str,
        config: str | Settings | None = None,
    ):
        self._targets = list(targets)
        self._config = config
        self._phases: list[str] = []
        self._plugins: list[str] | None = None
        self._ports: list[int] | None = None
        self._checks: list[str] | None = None
        self._formats: list[str] = ["json"]
        self._on_progress: OnProgressCallback | None = None
        self._on_finding: Callable[[Finding, str], None] | None = None
        self._wordlists: list[str] | None = None
        self._project: Project | None = None
        self._live_report_path: Path | None = None
        self._credentials: dict[str, tuple[str, str]] = {}
        self._bearer_tokens: dict[str, str] = {}
        self._exclude_patterns: list[str] = []
        self._no_cache: bool = False
        self._cache_ttl_hours: float = 0
        self._force_phases: list[str] = []
        self._autonomous: bool = False
        self._max_steps: int = 100
        self._campaign_enabled: bool = False

    @classmethod
    def targets(cls, target_list: list[str], **kwargs: Any) -> Audit:
        return cls(*target_list, **kwargs)

    def with_config(self, config: str | Settings) -> Audit:
        self._config = config
        return self

    def discover(self) -> Audit:
        self._phases.append("recon")
        return self

    def scan(self, ports: list[int] | None = None) -> Audit:
        self._phases.append("scanning")
        self._ports = ports
        return self

    def analyze(self) -> Audit:
        self._phases.append("analysis")
        return self

    def pentest(self, checks: list[str] | None = None) -> Audit:
        self._phases.append("pentesting")
        self._checks = checks
        return self

    def exploit(self) -> Audit:
        self._phases.append("exploitation")
        return self

    def post_exploit(self) -> Audit:
        self._phases.append("post_exploit")
        return self

    def privesc(self) -> Audit:
        self._phases.append("privesc")
        return self

    def lateral(self) -> Audit:
        self._phases.append("lateral")
        return self

    def crypto(self) -> Audit:
        self._phases.append("crypto")
        return self

    def forensics(self) -> Audit:
        self._phases.append("forensics")
        return self

    def full_offensive(self) -> Audit:
        """Run all offensive phases (HTB full attack chain)."""
        from basilisk.core.pipeline import OFFENSIVE_PHASES
        self._phases = list(OFFENSIVE_PHASES)
        return self

    def autonomous(self, max_steps: int = 100) -> Audit:
        """Enable autonomous orchestration (replaces fixed pipeline)."""
        self._autonomous = True
        self._max_steps = max_steps
        return self

    def enable_campaign(self) -> Audit:
        """Enable persistent campaign memory for cross-audit learning."""
        self._campaign_enabled = True
        return self

    def plugins(self, *names: str) -> Audit:
        self._plugins = list(names)
        return self

    def exclude(self, *patterns: str) -> Audit:
        """Exclude plugins by name or prefix (e.g. 'dns_enum', 'subdomain_')."""
        self._exclude_patterns = list(patterns)
        return self

    def on_progress(self, callback: OnProgressCallback) -> Audit:
        """Set callback for pipeline progress updates."""
        self._on_progress = callback
        return self

    def on_finding(self, callback: Callable[[Finding, str], None]) -> Audit:
        """Set callback for individual finding emissions."""
        self._on_finding = callback
        return self

    def wordlists(self, *names: str) -> Audit:
        """Set wordlist names for brute-force plugins."""
        self._wordlists = list(names)
        return self

    def for_project(self, project: Project) -> Audit:
        """Persist results to a project DB with resume support."""
        self._project = project
        return self

    def authenticate(
        self, host: str, username: str, password: str,
    ) -> Audit:
        """Set credentials for authenticated scanning of a host."""
        self._credentials[host] = (username, password)
        return self

    def bearer(self, host: str, token: str) -> Audit:
        """Set bearer token for a host."""
        self._bearer_tokens[host] = token
        return self

    def live_report(self, path: str | Path) -> Audit:
        """Enable live HTML report at specified path."""
        self._live_report_path = Path(path)
        return self

    def no_cache(self) -> Audit:
        """Disable result caching — always run all plugins from scratch."""
        self._no_cache = True
        return self

    def cache_ttl(self, hours: float) -> Audit:
        """Override default cache TTL for all phases (hours)."""
        self._cache_ttl_hours = hours
        return self

    def force_phases(self, *phases: str) -> Audit:
        """Force re-run of specific phases, ignoring cache."""
        self._force_phases = list(phases)
        return self

    def report(self, formats: list[str] | str | None = None) -> Audit:
        if formats:
            self._formats = [formats] if isinstance(formats, str) else formats
        return self

    async def run(self) -> PipelineState:
        """Execute the configured audit pipeline."""
        settings = self._resolve_config()
        scope = self._build_scope(settings)
        registry, ctx = self._build_context(settings)

        if self._autonomous:
            return await self._run_autonomous(registry, ctx, scope, settings)

        if self._project:
            db, run_id, completed_pairs = await self._setup_project_db(ctx, scope)
        else:
            db, run_id, completed_pairs = None, None, set()

        cache = await self._open_cache(db)
        pipeline = self._build_pipeline(
            registry, ctx, settings, completed_pairs, cache,
        )
        return await self._execute(pipeline, scope, ctx, db, run_id, settings, cache)

    async def _run_autonomous(
        self,
        registry: PluginRegistry,
        ctx: PluginContext,
        scope: TargetScope,
        settings: Settings,
    ) -> PipelineState:
        """Run the autonomous orchestrator instead of the fixed pipeline."""
        from basilisk.capabilities.mapping import build_capabilities
        from basilisk.events.bus import EventBus
        from basilisk.knowledge.graph import KnowledgeGraph
        from basilisk.memory.history import History
        from basilisk.orchestrator.executor import OrchestratorExecutor
        from basilisk.orchestrator.loop import AutonomousLoop
        from basilisk.orchestrator.planner import Planner
        from basilisk.orchestrator.safety import SafetyLimits
        from basilisk.orchestrator.selector import Selector
        from basilisk.scoring.scorer import Scorer

        graph = KnowledgeGraph()
        planner = Planner()
        capabilities = build_capabilities(registry)
        selector = Selector(capabilities)
        history = History()

        # Campaign memory (opt-in cross-audit learning)
        campaign_memory = None
        campaign_store = None
        if settings.campaign.enabled or self._campaign_enabled:
            from basilisk.campaign.memory import CampaignMemory
            from basilisk.campaign.store import CampaignStore

            db_path = settings.campaign.data_dir / settings.campaign.db_name
            campaign_store = await CampaignStore.open(db_path)
            campaign_memory = CampaignMemory()
            await campaign_memory.load(
                campaign_store, [t.host for t in scope],
            )

        scorer = Scorer(graph, history=history, campaign_memory=campaign_memory)
        core_executor = AsyncExecutor(max_concurrency=settings.scan.max_concurrency)
        orch_executor = OrchestratorExecutor(registry, core_executor, ctx)
        bus = EventBus()
        safety = SafetyLimits(
            max_steps=self._max_steps,
            max_duration_seconds=settings.scan.global_timeout
            if hasattr(settings.scan, "global_timeout") else 3600.0,
            batch_size=5,
        )

        loop = AutonomousLoop(
            graph=graph,
            planner=planner,
            selector=selector,
            scorer=scorer,
            executor=orch_executor,
            bus=bus,
            safety=safety,
            on_progress=None,
            history=history,
        )

        # Open project DB for knowledge graph persistence if project is set
        kg_store = None
        db = None
        if self._project:
            from basilisk.storage.db import open_db

            db = await open_db(self._project.db_path)
            from basilisk.knowledge.store import KnowledgeStore

            kg_store = KnowledgeStore(db)
            await kg_store.init_schema()

        try:
            if ctx.callback:
                await ctx.callback.start()
            if ctx.browser:
                await ctx.browser.start()

            # Probe HTTP scheme for each target
            http_scheme: dict[str, str | None] = {}
            for target in scope:
                scheme = await self._probe_target_scheme(ctx, target.host)
                http_scheme[target.host] = scheme
            ctx.state["http_scheme"] = http_scheme

            # Auth phase (same as pipeline mode)
            if ctx.auth:
                for target in scope:
                    host_key = target.host
                    scheme = http_scheme.get(host_key, "http") or "http"
                    base = f"{scheme}://{host_key}"
                    try:
                        session = await ctx.auth.login(host_key, ctx)
                        if session.is_authenticated:
                            if ctx.http and session.cookies:
                                await ctx.http.set_cookies(base, session.cookies)
                            extra = settings.auth.extra_cookies
                            if ctx.http and extra:
                                session.cookies.update(extra)
                                await ctx.http.set_cookies(base, extra)
                            logger.info("Autonomous auth OK for %s", host_key)
                        else:
                            logger.warning("Autonomous auth failed for %s", host_key)
                    except Exception:
                        logger.warning("Autonomous auth error for %s", host_key, exc_info=True)

            # Inject scan_paths from config into ctx.state and graph
            scan_paths = settings.scan.scan_paths
            if scan_paths:
                from datetime import UTC, datetime

                from basilisk.knowledge.entities import Entity, EntityType
                from basilisk.knowledge.relations import Relation, RelationType

                now = datetime.now(UTC)
                for target in scope:
                    host_key = target.host
                    scheme = http_scheme.get(host_key, "http") or "http"
                    base = f"{scheme}://{host_key}"
                    urls = ctx.state.setdefault("crawled_urls", {}).setdefault(host_key, [])
                    urls_set = set(urls)
                    for sp in scan_paths:
                        if not sp.startswith("/"):
                            sp = f"/{sp}"
                        url = f"{base}{sp}"
                        if url not in urls_set:
                            urls.append(url)
                            urls_set.add(url)
                    # Create ENDPOINT entities in graph for scan_paths
                    for sp in scan_paths:
                        if not sp.startswith("/"):
                            sp = f"/{sp}"
                        path_part = sp.split("?")[0]
                        has_params = "?" in sp
                        ep = Entity(
                            id=Entity.make_id(EntityType.ENDPOINT, host=host_key, path=path_part),
                            type=EntityType.ENDPOINT,
                            data={
                                "host": host_key, "path": path_part,
                                "has_params": has_params,
                                "scan_path": True,
                            },
                            first_seen=now, last_seen=now,
                        )
                        graph.add_entity(ep)
                        host_id = Entity.make_id(EntityType.HOST, host=host_key)
                        graph.add_relation(Relation(
                            source_id=host_id, target_id=ep.id,
                            type=RelationType.HAS_ENDPOINT,
                        ))
                    logger.info(
                        "Injected %d scan_paths as endpoints for %s",
                        len(scan_paths), host_key,
                    )

            result = await loop.run(list(scope))

            # Persist knowledge graph to SQLite
            if kg_store:
                await kg_store.save(result.graph)

            # Save decision history alongside project DB
            if self._project and result.history:
                history_path = self._project.db_path.parent / "decision_history.json"
                result.history.save(history_path)

            # Update and persist campaign memory
            if campaign_memory is not None and result.history:
                campaign_memory.update_from_graph(result.graph, result.history)
                await campaign_memory.save(campaign_store)

            state = self._loop_result_to_pipeline_state(result)

            # Fire progress callback with final state so LiveReportEngine writes files
            if self._on_progress:
                self._on_progress(state)

            return state
        finally:
            if campaign_store:
                await campaign_store.close()
            if db:
                await db.close()
            if ctx.http:
                await ctx.http.close()
            if ctx.callback:
                await ctx.callback.stop()
            if ctx.browser:
                await ctx.browser.stop()

    @staticmethod
    def _loop_result_to_pipeline_state(result: Any) -> PipelineState:
        """Convert LoopResult to PipelineState for backward compat with reporting."""
        from basilisk.core.pipeline import PhaseProgress
        from basilisk.models.result import PluginResult
        from basilisk.reporting.autonomous import prepare_autonomous_data

        state = PipelineState()
        state.status = "completed"

        # Build a single "autonomous" phase
        state.phases["autonomous"] = PhaseProgress(
            phase="autonomous",
            total=result.steps,
            completed=result.steps,
            status="done",
        )

        # Collect PluginResults stored during execution
        all_results = []
        for pr in result.plugin_results.values():
            if isinstance(pr, PluginResult):
                all_results.append(pr)

        state.results = all_results
        state.total_findings = sum(len(pr.findings) for pr in all_results)

        # Build autonomous-specific report data
        state.autonomous = prepare_autonomous_data(result)

        return state

    def _build_scope(self, settings: Settings) -> TargetScope:
        """Build target scope from configured targets."""
        scope = TargetScope()
        for t in self._targets:
            if _is_ip_or_local(t):
                bare, port = _split_host_port(t)
                # Keep original "host:port" as host so HTTP URLs and pipeline keys match
                scope.add(Target.ip(t if port else bare, ports=[port] if port else []))
            else:
                scope.add(Target.domain(t))
        if self._ports:
            settings.scan.default_ports = self._ports
        return scope

    def _build_context(
        self, settings: Settings,
    ) -> tuple[PluginRegistry, PluginContext]:
        """Initialize all services and build the DI container."""
        registry = PluginRegistry()
        registry.discover()

        http = AsyncHttpClient(
            timeout=settings.http.timeout,
            max_connections=settings.http.max_connections,
            max_per_host=settings.http.max_connections_per_host,
            user_agent=settings.http.user_agent,
            verify_ssl=settings.http.verify_ssl,
        )
        dns = DnsClient(
            nameservers=settings.dns.nameservers,
            timeout=settings.dns.timeout,
        )
        net = NetUtils(timeout=settings.scan.port_timeout)
        rate = RateLimiter(
            rate=settings.rate_limit.requests_per_second,
            burst=settings.rate_limit.burst,
        )
        wordlists_mgr = WordlistManager()
        provider_pool = ProviderPool(registry)

        # Initialize engines (lazy imports to avoid circular deps)
        from basilisk.core.exploit_chain import ExploitChainEngine
        from basilisk.utils.diff import ResponseDiffer
        from basilisk.utils.dynamic_wordlist import DynamicWordlistGenerator
        from basilisk.utils.payloads import PayloadEngine
        from basilisk.utils.waf_bypass import WafBypassEngine
        differ = ResponseDiffer()
        payload_engine = PayloadEngine()
        waf_engine = WafBypassEngine()
        exploit_chain_engine = ExploitChainEngine()
        dynamic_wordlist_gen = DynamicWordlistGenerator()

        auth_manager = self._build_auth(settings)
        callback_server = self._build_callback(settings)
        browser_manager = self._build_browser(settings)

        ctx = PluginContext(
            config=settings,
            http=http,
            dns=dns,
            net=net,
            rate=rate,
            wordlists=wordlists_mgr,
            providers=provider_pool,
            auth=auth_manager,
            browser=browser_manager,
            callback=callback_server,
            differ=differ,
            payloads=payload_engine,
            waf_bypass=waf_engine,
            exploit_chain=exploit_chain_engine,
            dynamic_wordlist=dynamic_wordlist_gen,
        )
        if self._on_finding:
            ctx.emit = self._on_finding
        if self._wordlists:
            ctx.state["wordlists"] = self._wordlists

        return registry, ctx

    def _build_auth(self, settings: Settings):
        """Initialize auth manager if credentials are configured."""
        if not (settings.auth.enabled or self._credentials or self._bearer_tokens):
            return None

        from basilisk.core.auth import AuthManager, FormLoginStrategy
        auth_manager = AuthManager()
        if settings.auth.username:
            auth_manager.add_strategy(FormLoginStrategy(
                username=settings.auth.username,
                password=settings.auth.password,
                login_url=settings.auth.login_url,
            ))
        if settings.auth.extra_cookies:
            auth_manager.set_extra_cookies(settings.auth.extra_cookies)
        if settings.auth.bearer_token:
            for t in self._targets:
                auth_manager.set_bearer(t, settings.auth.bearer_token)
        for _host, (user, pwd) in self._credentials.items():
            auth_manager.add_strategy(FormLoginStrategy(
                username=user, password=pwd,
            ))
        for host, token in self._bearer_tokens.items():
            auth_manager.set_bearer(host, token)
        if settings.auth.session_file:
            auth_manager.load(Path(settings.auth.session_file))
        return auth_manager

    @staticmethod
    async def _probe_target_scheme(ctx: PluginContext, host: str) -> str:
        """Quick probe to determine if host uses HTTPS or HTTP."""
        if ctx.http is None:
            return "http"
        for scheme in ("https", "http"):
            try:
                await asyncio.wait_for(
                    ctx.http.head(f"{scheme}://{host}/"), timeout=5.0,
                )
                return scheme
            except Exception:
                continue
        return "http"

    @staticmethod
    def _build_callback(settings: Settings):
        """Initialize callback server if enabled."""
        if not settings.callback.enabled:
            return None
        from basilisk.core.callback import CallbackServer
        return CallbackServer(
            http_port=settings.callback.http_port,
            dns_port=settings.callback.dns_port,
            callback_domain=settings.callback.domain,
        )

    @staticmethod
    def _build_browser(settings: Settings):
        """Initialize headless browser if enabled."""
        if not settings.browser.enabled:
            return None
        from basilisk.utils.browser import BrowserManager
        return BrowserManager(
            max_pages=settings.browser.max_pages,
            timeout=settings.browser.timeout,
            user_agent=settings.http.user_agent,
        )

    async def _open_cache(self, project_db: Any) -> Any:
        """Open result cache. Returns None if caching is disabled."""
        if self._no_cache:
            return None

        from basilisk.storage.cache import ResultCache

        if project_db:
            # For project audits, use the project DB as cache
            return await ResultCache.from_db(project_db)

        # For non-project audits, use global cache
        return await ResultCache.open_global()

    def _build_pipeline(
        self,
        registry: PluginRegistry,
        ctx: PluginContext,
        settings: Settings,
        completed_pairs: set[tuple[str, str]],
        cache: Any = None,
    ) -> Pipeline:
        """Build the execution pipeline with progress tracking."""
        executor = AsyncExecutor(max_concurrency=settings.scan.max_concurrency)
        progress_cb = self._on_progress or _noop_progress

        if self._live_report_path:
            from basilisk.reporting.live_html import LiveHtmlRenderer
            live = LiveHtmlRenderer(self._live_report_path)
            original_cb = progress_cb
            def progress_cb(state):  # noqa: E306
                original_cb(state)
                live.update(state)

        # Build cache TTL overrides
        cache_ttl: dict[str, float] = {}
        if self._cache_ttl_hours > 0:
            for phase in ("recon", "scanning", "analysis", "pentesting",
                          "exploitation", "post_exploit", "privesc", "lateral",
                          "crypto", "forensics"):
                cache_ttl[phase] = self._cache_ttl_hours

        return Pipeline(
            registry, executor, ctx,
            on_progress=progress_cb,
            completed_pairs=completed_pairs,
            cache=cache,
            cache_ttl=cache_ttl if cache_ttl else None,
            force_phases=set(self._force_phases) if self._force_phases else None,
        )

    async def _execute(
        self,
        pipeline: Pipeline,
        scope: TargetScope,
        ctx: PluginContext,
        db: Any,
        run_id: int | None,
        settings: Settings,
        cache: Any = None,
    ) -> PipelineState:
        """Run the pipeline with proper startup/shutdown of engines."""
        phases = self._phases or [
            "recon", "scanning", "analysis", "pentesting",
            "exploitation", "post_exploit", "privesc", "lateral",
            "crypto", "forensics",
        ]

        try:
            if ctx.callback:
                await ctx.callback.start()
            if ctx.browser:
                await ctx.browser.start()

            state = await pipeline.run(
                scope, self._plugins, phases,
                exclude_patterns=self._exclude_patterns or None,
            )
            if ctx.db and run_id:
                await ctx.db.finish_run(run_id)

            if ctx.auth and settings.auth.session_file:
                ctx.auth.save(Path(settings.auth.session_file))

            return state
        finally:
            if ctx.http:
                await ctx.http.close()
            if ctx.callback:
                await ctx.callback.stop()
            if ctx.browser:
                await ctx.browser.stop()
            # Close global cache DB (but not project DB used as cache)
            if cache and not db:
                with contextlib.suppress(Exception):
                    await cache.close()
            if db:
                from basilisk.storage.db import close_db
                await close_db(db)

    async def _setup_project_db(
        self,
        ctx: PluginContext,
        scope: TargetScope,
    ) -> tuple[Any, int, set[tuple[str, str]]]:
        """Open project DB, detect resume, return (db, run_id, completed)."""
        from basilisk.storage.db import open_db
        from basilisk.storage.repo import ResultRepository

        project = self._project
        assert project is not None  # noqa: S101

        db = await open_db(project.db_path)
        repo = ResultRepository(db)
        ctx.db = repo

        # Get or create project record in DB
        proj_row = await repo.get_project_by_name(project.name)
        if proj_row:
            project_db_id = proj_row["id"]
        else:
            project_db_id = await repo.create_project(
                project.name, str(project.path)
            )

        # Check for incomplete run (resume)
        completed_pairs: set[tuple[str, str]] = set()
        incomplete = await repo.get_incomplete_run(project_db_id)

        if incomplete:
            run_id = incomplete["id"]
            completed_pairs = await repo.get_completed_pairs(run_id)
            # Reconstruct expanded scope from DB
            db_domains = await repo.get_run_domains(project_db_id)
            for d in db_domains:
                if d["parent"]:
                    scope.add(
                        Target.subdomain(d["host"], parent=d["parent"])
                    )
                elif d["host"] not in {t.host for t in scope}:
                    scope.add(Target.domain(d["host"]))
            if completed_pairs:
                logger.info(
                    "Resuming run %d: %d pairs already completed",
                    run_id, len(completed_pairs),
                )
        else:
            run_id = await repo.create_run(
                project_id=project_db_id,
                plugins=self._plugins or [],
                target_count=len(self._targets),
            )

        ctx.state["project_id"] = project_db_id
        ctx.state["run_id"] = run_id
        return db, run_id, completed_pairs

    @staticmethod
    async def run_plugin(
        plugin_name: str,
        targets: list[str],
        config: Settings | None = None,
    ) -> list:
        """Run a single plugin against targets."""
        settings = config or Settings.load()
        registry = PluginRegistry()
        registry.discover()

        plugin_cls = registry.get(plugin_name)
        if not plugin_cls:
            msg = f"Plugin '{plugin_name}' not found"
            raise ValueError(msg)

        http = AsyncHttpClient(
            timeout=settings.http.timeout,
            user_agent=settings.http.user_agent,
        )
        dns = DnsClient(nameservers=settings.dns.nameservers)
        net = NetUtils(timeout=settings.scan.port_timeout)
        rate = RateLimiter(
            rate=settings.rate_limit.requests_per_second,
            burst=settings.rate_limit.burst,
        )
        wordlists_mgr = WordlistManager()

        ctx = PluginContext(
            config=settings,
            http=http,
            dns=dns,
            net=net,
            rate=rate,
            wordlists=wordlists_mgr,
        )

        plugin = plugin_cls()
        await plugin.setup(ctx)

        executor = AsyncExecutor()
        target_objs = [Target.domain(t) for t in targets]
        try:
            return await executor.run_batch(plugin, target_objs, ctx)
        finally:
            await plugin.teardown()
            await http.close()

    def _resolve_config(self) -> Settings:
        if isinstance(self._config, Settings):
            return self._config
        if isinstance(self._config, str):
            return Settings.load(self._config)
        return Settings.load()
