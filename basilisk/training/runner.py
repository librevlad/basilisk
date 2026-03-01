"""Training runner — orchestrates autonomous engine in validation mode."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from basilisk.training.planner_wrapper import TrainingPlanner
from basilisk.training.scorer_wrapper import TrainingScorer
from basilisk.training.validator import FindingTracker, ValidationReport

if TYPE_CHECKING:
    from basilisk.config import Settings
    from basilisk.core.executor import PluginContext
    from basilisk.training.profile import TrainingProfile

logger = logging.getLogger(__name__)


class TrainingRunner:
    """Run autonomous engine in training validation mode."""

    def __init__(
        self,
        profile: TrainingProfile,
        target_override: str | None = None,
        manage_docker: bool = True,
        project_root: Path | None = None,
    ) -> None:
        self.profile = profile
        self.target = target_override or profile.target
        self.manage_docker = manage_docker
        self.project_root = project_root

    async def run(
        self,
        config: Settings | None = None,
        bus: Any | None = None,
        tracker: FindingTracker | None = None,
    ) -> ValidationReport:
        """Execute training run and return validation report."""
        docker_cfg = self.profile.docker
        docker_mgr = None

        if docker_cfg.compose_file and self.manage_docker:
            from basilisk.training.docker import DockerComposeManager

            docker_mgr = DockerComposeManager()
            if docker_mgr.available:
                await docker_mgr.up(docker_cfg.compose_file, self.project_root)
                await docker_mgr.wait_ready(docker_cfg.ready_url, docker_cfg.ready_timeout)
            else:
                logger.warning("Docker not available, skipping container management")
                docker_mgr = None

        try:
            return await self._run_engine(config, bus=bus, tracker=tracker)
        finally:
            if docker_mgr:
                await docker_mgr.down(docker_cfg.compose_file, self.project_root)

    async def _run_engine(
        self,
        config: Settings | None = None,
        bus: Any | None = None,
        tracker: FindingTracker | None = None,
    ) -> ValidationReport:
        """Core engine execution (separated for Docker lifecycle wrapping)."""
        from basilisk.capabilities.mapping import build_capabilities
        from basilisk.config import Settings
        from basilisk.core.executor import AsyncExecutor, PluginContext
        from basilisk.core.registry import PluginRegistry
        from basilisk.events.bus import EventBus, EventType
        from basilisk.knowledge.graph import KnowledgeGraph
        from basilisk.memory.history import History
        from basilisk.models.target import Target, TargetScope
        from basilisk.orchestrator.executor import OrchestratorExecutor
        from basilisk.orchestrator.loop import AutonomousLoop
        from basilisk.orchestrator.planner import Planner
        from basilisk.orchestrator.safety import SafetyLimits
        from basilisk.orchestrator.selector import Selector
        from basilisk.scoring.scorer import Scorer
        from basilisk.utils.dns import DnsClient
        from basilisk.utils.http import AsyncHttpClient
        from basilisk.utils.net import NetUtils
        from basilisk.utils.rate_limiter import RateLimiter
        from basilisk.utils.wordlists import WordlistManager

        settings = config or Settings.load()

        # Build infrastructure directly
        registry = PluginRegistry()
        registry.discover()

        http = AsyncHttpClient(
            timeout=settings.http.timeout,
            max_connections=settings.http.max_connections,
            max_per_host=settings.http.max_connections_per_host,
            user_agent=settings.http.user_agent,
            verify_ssl=settings.http.verify_ssl,
        )
        dns = DnsClient(nameservers=settings.dns.nameservers, timeout=settings.dns.timeout)
        net = NetUtils(timeout=settings.scan.port_timeout)
        rate = RateLimiter(
            rate=settings.rate_limit.requests_per_second, burst=settings.rate_limit.burst,
        )
        wordlists_mgr = WordlistManager()

        from basilisk.core.providers import ProviderPool

        provider_pool = ProviderPool(registry)

        ctx = PluginContext(
            config=settings, http=http, dns=dns, net=net, rate=rate,
            wordlists=wordlists_mgr, providers=provider_pool,
        )

        # Build target scope
        from basilisk.orchestrator.selector import _is_ip_or_local

        scope = TargetScope()
        target_str = self.target
        if _is_ip_or_local(target_str):
            scope.add(Target.ip(target_str))
        else:
            scope.add(Target.domain(target_str))

        graph = KnowledgeGraph()
        tracker = tracker or FindingTracker(self.profile)
        planner = Planner()
        capabilities = build_capabilities(registry)
        selector = Selector(capabilities)
        history = History()
        scorer = Scorer(graph, history=history)

        # Wrap planner and scorer for training mode
        training_planner = TrainingPlanner(planner, tracker, self.profile)
        training_scorer = TrainingScorer(scorer, tracker, self.profile)

        core_executor = AsyncExecutor(max_concurrency=settings.scan.max_concurrency)
        orch_executor = OrchestratorExecutor(registry, core_executor, ctx)
        bus = bus or EventBus()
        safety = SafetyLimits(
            max_steps=self.profile.max_steps,
            max_duration_seconds=7200.0,
            batch_size=5,
        )

        loop = AutonomousLoop(
            graph=graph,
            planner=training_planner,
            selector=selector,
            scorer=training_scorer,
            executor=orch_executor,
            bus=bus,
            safety=safety,
            history=history,
            exploration_rate=0.0,
            goal_engine=None,
        )

        # Track verifications via event bus
        bus.subscribe(EventType.FINDING_VERIFIED, lambda e: tracker.check_verification(
            e.data["entity_id"], step=0,
        ))

        try:
            # Probe HTTP scheme
            http_scheme: dict[str, str | None] = {}
            for target in scope:
                scheme = await self._probe_target_scheme(ctx, target.host)
                http_scheme[target.host] = scheme
            ctx.state["http_scheme"] = http_scheme

            # Training auth: run setup URL + form login if configured
            auth_cfg = self.profile.auth
            if (auth_cfg.username or auth_cfg.login_url) and ctx.http:
                import re as _re

                for target in scope:
                    host_key = target.host
                    scheme = http_scheme.get(host_key, "http") or "http"
                    base = f"{scheme}://{host_key}"

                    # Generate unique run_id for {uuid} placeholder replacement
                    import uuid as _uuid_mod

                    run_id = _uuid_mod.uuid4().hex[:8]

                    # Setup step (e.g. DVWA database reset, VamPi /createdb)
                    if auth_cfg.setup_url:
                        setup_url = f"{base}{auth_cfg.setup_url}"
                        try:
                            if auth_cfg.setup_data:
                                # POST with data + CSRF token extraction
                                get_url = (
                                    f"{base}{auth_cfg.setup_get_url}"
                                    if auth_cfg.setup_get_url
                                    else setup_url
                                )
                                setup_page = await ctx.http.get(get_url)
                                setup_html = await setup_page.text()
                                setup_data = {
                                    k: v.replace("{uuid}", run_id)
                                    if isinstance(v, str) else v
                                    for k, v in auth_cfg.setup_data.items()
                                }
                                # Generic CSRF token extraction from hidden inputs
                                for m in _re.finditer(
                                    r'<input[^>]+type=["\']hidden["\'][^>]*'
                                    r'name=["\']([^"\']*(?:csrf|token)[^"\']*)["\']'
                                    r'[^>]*value=["\']([^"\']*)["\']',
                                    setup_html,
                                    _re.IGNORECASE,
                                ):
                                    setup_data[m.group(1)] = m.group(2)
                                for m in _re.finditer(
                                    r'<input[^>]+type=["\']hidden["\'][^>]*'
                                    r'value=["\']([^"\']*)["\']'
                                    r'[^>]*name=["\']([^"\']*(?:csrf|token)[^"\']*)["\']',
                                    setup_html,
                                    _re.IGNORECASE,
                                ):
                                    setup_data[m.group(2)] = m.group(1)
                                # Also extract from meta tags (Spring Security)
                                csrf_meta = _re.search(
                                    r'<meta\s+name=["\']_csrf["\']'
                                    r'\s+content=["\']([^"\']+)["\']',
                                    setup_html,
                                    _re.IGNORECASE,
                                )
                                if csrf_meta:
                                    setup_data["_csrf"] = csrf_meta.group(1)
                                await ctx.http.post(setup_url, data=setup_data)
                                logger.info("Training setup POST to %s", setup_url)
                            else:
                                # Simple GET (e.g. VamPi /createdb)
                                await ctx.http.get(setup_url)
                                logger.info("Training setup GET to %s", setup_url)
                        except Exception:
                            logger.warning("Training setup failed: %s", setup_url)

                    if auth_cfg.auth_type == "json_api":
                        # JSON API auth (REST apps like VamPi)
                        await self._json_api_auth(ctx, auth_cfg, base, host_key)
                    else:
                        # Form login — with CSRF token extraction
                        login_url = (
                            f"{base}{auth_cfg.login_url}" if auth_cfg.login_url else ""
                        )
                        if login_url:
                            try:
                                login_page = await ctx.http.get(login_url)
                                login_html = await login_page.text()
                                csrf_tokens: dict[str, str] = {}
                                for m in _re.finditer(
                                    r'<input[^>]+type=["\']hidden["\'][^>]*'
                                    r'name=["\']([^"\']*(?:csrf|token)[^"\']*)["\']'
                                    r'[^>]*value=["\']([^"\']*)["\']',
                                    login_html,
                                    _re.IGNORECASE,
                                ):
                                    csrf_tokens[m.group(1)] = m.group(2)
                                for m in _re.finditer(
                                    r'<input[^>]+type=["\']hidden["\'][^>]*'
                                    r'value=["\']([^"\']*)["\']'
                                    r'[^>]*name=["\']([^"\']*(?:csrf|token)[^"\']*)["\']',
                                    login_html,
                                    _re.IGNORECASE,
                                ):
                                    csrf_tokens[m.group(2)] = m.group(1)
                                if auth_cfg.login_fields:
                                    login_data: dict[str, str] = {
                                        k: v.replace("{uuid}", run_id)
                                        if isinstance(v, str) else v
                                        for k, v in auth_cfg.login_fields.items()
                                    }
                                else:
                                    login_data: dict[str, str] = {
                                        "username": auth_cfg.username,
                                        "password": auth_cfg.password,
                                        "Login": "Login",
                                    }
                                login_data.update(csrf_tokens)

                                resp = await ctx.http.post(login_url, data=login_data)
                                login_body = await resp.text()
                                body_lower = login_body.lower()
                                resp_url = str(getattr(resp, "url", ""))
                                # Redirect-based login (Spring Security):
                                # after following redirect, check if final URL left login page
                                redirected_away = (
                                    resp_url
                                    and "/login" not in resp_url.lower().split("?")[0]
                                )
                                login_ok = (
                                    "logout" in body_lower
                                    or "sign out" in body_lower
                                    or "welcome" in body_lower
                                    or "dashboard" in body_lower
                                    or redirected_away
                                )
                                # Override: explicit error indicators in body
                                if login_ok and (
                                    "invalid" in body_lower
                                    or "bad credentials" in body_lower
                                    or "login failed" in body_lower
                                ):
                                    login_ok = False
                                logger.info(
                                    "Training auth login to %s: status=%s ok=%s",
                                    login_url, getattr(resp, "status", "?"), login_ok,
                                )
                            except Exception:
                                logger.warning(
                                    "Training auth login failed: %s", login_url,
                                )

                    # Extra cookies (e.g. DVWA security=low)
                    if auth_cfg.extra_cookies:
                        await ctx.http.set_cookies(base, auth_cfg.extra_cookies)
                        logger.info("Set extra cookies for %s: %s",
                                    host_key, list(auth_cfg.extra_cookies.keys()))

            # Inject scan_paths from profile into graph
            if self.profile.scan_paths:
                from datetime import UTC, datetime

                from basilisk.knowledge.entities import Entity, EntityType
                from basilisk.knowledge.relations import Relation, RelationType

                now = datetime.now(UTC)
                for target in scope:
                    host_key = target.host
                    scheme = http_scheme.get(host_key, "http") or "http"
                    host_id = Entity.make_id(EntityType.HOST, host=host_key)
                    for sp in self.profile.scan_paths:
                        if not sp.startswith("/"):
                            sp = f"/{sp}"
                        path_part = sp.split("?")[0]
                        ep = Entity(
                            id=Entity.make_id(EntityType.ENDPOINT, host=host_key, path=path_part),
                            type=EntityType.ENDPOINT,
                            data={
                                "host": host_key, "path": path_part,
                                "has_params": True,
                                "scan_path": True,
                            },
                            first_seen=now, last_seen=now,
                        )
                        graph.add_entity(ep)
                        graph.add_relation(Relation(
                            source_id=host_id, target_id=ep.id,
                            type=RelationType.HAS_ENDPOINT,
                        ))
                    # Also populate ctx.state["crawled_urls"] so form_analyzer
                    # and pentesting plugins (via collect_injection_points) see them.
                    crawled = ctx.state.setdefault("crawled_urls", {})
                    host_urls = crawled.setdefault(host_key, [])
                    for sp in self.profile.scan_paths:
                        if not sp.startswith("/"):
                            sp = f"/{sp}"
                        full_url = f"{scheme}://{host_key}{sp}"
                        if full_url not in host_urls:
                            host_urls.append(full_url)

                    logger.info(
                        "Injected %d scan_paths for %s", len(self.profile.scan_paths), host_key,
                    )

            # Bootstrap target ports from profile
            if self.profile.target_ports:
                from datetime import UTC, datetime

                from basilisk.knowledge.entities import Entity, EntityType
                from basilisk.knowledge.relations import Relation, RelationType

                now = datetime.now(UTC)
                for target in scope:
                    host_id = Entity.make_id(EntityType.HOST, host=target.host)
                    for port in self.profile.target_ports:
                        svc = Entity(
                            id=Entity.make_id(
                                EntityType.SERVICE,
                                host=target.host,
                                port=str(port),
                                protocol="tcp",
                            ),
                            type=EntityType.SERVICE,
                            data={
                                "host": target.host,
                                "port": port,
                                "protocol": "tcp",
                                "service": "http",
                            },
                            first_seen=now,
                            last_seen=now,
                        )
                        graph.add_entity(svc)
                        graph.add_relation(Relation(
                            source_id=host_id,
                            target_id=svc.id,
                            type=RelationType.EXPOSES,
                        ))

            result = await loop.run(list(scope))

            # Final tracker sync from graph
            for finding in result.graph.findings():
                tracker.check_discovery(finding, step=result.steps)
            for tf in tracker.tracked:
                if tf.discovered and not tf.verified:
                    entity = result.graph.get(tf.matched_entity_id)
                    if entity and entity.data.get("verified"):
                        tracker.check_verification(tf.matched_entity_id, step=result.steps)

            return self._build_report(result, tracker)
        finally:
            if ctx.http:
                await ctx.http.close()

    @staticmethod
    async def _json_api_auth(
        ctx: PluginContext,
        auth_cfg: Any,
        base: str,
        host_key: str,
    ) -> None:
        """JSON API auth: optional register, then login, extract JWT token."""
        import json as _json
        import uuid as _uuid

        # Generate a unique run_id for {uuid} placeholder replacement
        run_id = _uuid.uuid4().hex[:8]

        # Registration (optional)
        if auth_cfg.register_url:
            reg_url = f"{base}{auth_cfg.register_url}"
            reg_data = dict(auth_cfg.register_data) if auth_cfg.register_data else {
                "username": auth_cfg.username,
                "password": auth_cfg.password,
            }
            reg_data = {
                k: v.replace("{uuid}", run_id) if isinstance(v, str) else v
                for k, v in reg_data.items()
            }
            try:
                resp = await ctx.http.post(reg_url, json=reg_data)
                status = getattr(resp, "status", "?")
                logger.info("JSON API register %s: status=%s", reg_url, status)
            except Exception:
                logger.warning("JSON API register failed: %s", reg_url)

        # Login
        login_url = f"{base}{auth_cfg.login_url}" if auth_cfg.login_url else ""
        if not login_url:
            return

        try:
            if auth_cfg.login_fields:
                login_payload = dict(auth_cfg.login_fields)
            else:
                login_payload = {
                    "username": auth_cfg.username,
                    "password": auth_cfg.password,
                }
            # Replace {uuid} placeholders with same run_id used for registration
            login_payload = {
                k: v.replace("{uuid}", run_id) if isinstance(v, str) else v
                for k, v in login_payload.items()
            }
            resp = await ctx.http.post(login_url, json=login_payload)
            body = await resp.text()
            status = getattr(resp, "status", "?")

            # Extract token from JSON response
            token = ""
            if auth_cfg.token_path:
                try:
                    data = _json.loads(body)
                    # Support dotted paths like "data.token"
                    for part in auth_cfg.token_path.split("."):
                        data = data[part]
                    token = str(data)
                except (KeyError, TypeError, _json.JSONDecodeError):
                    logger.warning(
                        "Could not extract token at path '%s' from response",
                        auth_cfg.token_path,
                    )

            if token:
                # Store in ctx.state for plugins (jwt_attack, etc.)
                ctx.state["auth_token"] = token
                ctx.state["jwt_token"] = token
                # Set default header on HTTP client
                header_name = auth_cfg.token_header or "Authorization"
                header_value = f"{auth_cfg.token_prefix}{token}"
                await ctx.http.set_default_header(header_name, header_value)
                logger.info(
                    "JSON API login to %s: status=%s token=%s...%s ok=True",
                    login_url, status, token[:10], token[-6:],
                )
            else:
                logger.info(
                    "JSON API login to %s: status=%s ok=False (no token)",
                    login_url, status,
                )
        except Exception:
            logger.warning("JSON API login failed: %s", login_url)

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

    def _build_report(self, result: Any, tracker: FindingTracker) -> ValidationReport:
        """Build final validation report from loop result and tracker state."""
        findings_detail = []
        for tf in tracker.tracked:
            findings_detail.append({
                "expected_title": tf.expected.title,
                "expected_severity": tf.expected.severity,
                "category": tf.expected.category,
                "discovered": tf.discovered,
                "verified": tf.verified,
                "discovery_step": tf.discovery_step,
                "verification_step": tf.verification_step,
                "matched_title": tf.matched_title,
            })

        return ValidationReport(
            profile_name=self.profile.name,
            target=self.target,
            total_expected=len(tracker.tracked),
            discovered=sum(1 for tf in tracker.tracked if tf.discovered),
            verified=sum(1 for tf in tracker.tracked if tf.verified),
            coverage=tracker.coverage,
            verification_rate=tracker.verification_rate,
            steps_taken=result.steps,
            findings_detail=findings_detail,
            passed=tracker.coverage >= self.profile.required_coverage,
        )
