"""Audit facade — elegant fluent API (Laravel-style)."""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from basilisk.config import Settings
from basilisk.core.executor import AsyncExecutor, PluginContext
from basilisk.core.pipeline import OnProgressCallback, Pipeline, PipelineState, _noop_progress
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

    def plugins(self, *names: str) -> Audit:
        self._plugins = list(names)
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

    def report(self, formats: list[str] | str | None = None) -> Audit:
        if formats:
            self._formats = [formats] if isinstance(formats, str) else formats
        return self

    async def run(self) -> PipelineState:
        """Execute the configured audit pipeline."""
        settings = self._resolve_config()

        # Build scope
        scope = TargetScope()
        for t in self._targets:
            scope.add(Target.domain(t))

        # Override ports if specified
        if self._ports:
            settings.scan.default_ports = self._ports

        # Setup context
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

        # Initialize new engines
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

        auth_manager = None
        if settings.auth.enabled or self._credentials or self._bearer_tokens:
            from basilisk.core.auth import AuthManager, FormLoginStrategy
            auth_manager = AuthManager()
            # Add form login strategy with global or per-host credentials
            if settings.auth.username:
                auth_manager.add_strategy(FormLoginStrategy(
                    username=settings.auth.username,
                    password=settings.auth.password,
                    login_url=settings.auth.login_url,
                ))
            if settings.auth.bearer_token:
                for t in self._targets:
                    auth_manager.set_bearer(t, settings.auth.bearer_token)
            for _host, (user, pwd) in self._credentials.items():
                auth_manager.add_strategy(FormLoginStrategy(
                    username=user, password=pwd,
                ))
            for host, token in self._bearer_tokens.items():
                auth_manager.set_bearer(host, token)
            # Load persisted sessions if available
            if settings.auth.session_file:
                auth_manager.load(Path(settings.auth.session_file))

        callback_server = None
        if settings.callback.enabled:
            from basilisk.core.callback import CallbackServer
            callback_server = CallbackServer(
                http_port=settings.callback.http_port,
                dns_port=settings.callback.dns_port,
                callback_domain=settings.callback.domain,
            )

        browser_manager = None
        if settings.browser.enabled:
            from basilisk.utils.browser import BrowserManager
            browser_manager = BrowserManager(
                max_pages=settings.browser.max_pages,
                timeout=settings.browser.timeout,
                user_agent=settings.http.user_agent,
            )

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

        # Project DB setup (with resume support)
        db = None
        run_id = None
        completed_pairs: set[tuple[str, str]] = set()

        if self._project:
            db, run_id, completed_pairs = await self._setup_project_db(
                ctx, scope
            )

        executor = AsyncExecutor(max_concurrency=settings.scan.max_concurrency)
        progress_cb = self._on_progress or _noop_progress

        # Wrap progress callback with live report if configured
        if self._live_report_path:
            from basilisk.reporting.live_html import LiveHtmlRenderer
            live = LiveHtmlRenderer(self._live_report_path)
            original_cb = progress_cb
            def progress_cb(state):  # noqa: E306
                original_cb(state)
                live.update(state)

        pipeline = Pipeline(
            registry, executor, ctx,
            on_progress=progress_cb,
            completed_pairs=completed_pairs,
        )

        phases = self._phases or ["recon", "scanning", "analysis", "pentesting"]

        try:
            # Start optional engines
            if callback_server:
                await callback_server.start()
            if browser_manager:
                await browser_manager.start()

            state = await pipeline.run(scope, self._plugins, phases)
            if ctx.db and run_id:
                await ctx.db.finish_run(run_id)

            # Save auth sessions for future runs
            if auth_manager and settings.auth.session_file:
                auth_manager.save(Path(settings.auth.session_file))

            return state
        finally:
            await http.close()
            if callback_server:
                await callback_server.stop()
            if browser_manager:
                await browser_manager.stop()
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

        ctx = PluginContext(
            config=settings,
            http=http,
            dns=dns,
            net=net,
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
