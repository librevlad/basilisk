#!/usr/bin/env python3
"""Bulk Git Exposure Scanner — find exposed .git repos across thousands of domains.

Uses the Basilisk framework to:
1. Load domains from a text/CSV file
2. Discover subdomains for each domain (crt.sh, HackerTarget, RapidDNS, etc.)
3. Run the git_exposure plugin against every host (domain + subdomains)
4. Stream results to a JSONL file with resume support

Usage:
    python examples/git/git_exposure_scan.py domains.txt -o results.jsonl
    python examples/git/git_exposure_scan.py domains.csv -o results.jsonl -c 10 --rate 30
    python examples/git/git_exposure_scan.py domains.txt --skip-subdomains
    python examples/git/git_exposure_scan.py domains.txt --no-resume
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import io
import itertools
import json
import logging
import os
import signal
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

# Add project root to path so we can import basilisk
_project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_project_root))

from basilisk.config import Settings  # noqa: E402
from basilisk.core.executor import AsyncExecutor, PluginContext  # noqa: E402
from basilisk.core.providers import ProviderPool  # noqa: E402
from basilisk.core.registry import PluginRegistry  # noqa: E402
from basilisk.models.result import PluginResult, Severity  # noqa: E402
from basilisk.models.target import Target  # noqa: E402
from basilisk.utils.dns import DnsClient  # noqa: E402
from basilisk.utils.http import AsyncHttpClient  # noqa: E402
from basilisk.utils.net import NetUtils  # noqa: E402
from basilisk.utils.rate_limiter import RateLimiter  # noqa: E402
from basilisk.utils.wordlists import WordlistManager  # noqa: E402

logger = logging.getLogger("git_exposure_scan")

# ---------------------------------------------------------------------------
# Input file parsing
# ---------------------------------------------------------------------------

def load_domains(path: str) -> list[str]:
    """Load domains from a text or CSV file, deduplicated in order."""
    file_path = Path(path)
    if not file_path.exists():
        logger.error("Input file not found: %s", path)
        sys.exit(1)

    raw = file_path.read_text(encoding="utf-8", errors="replace")
    lines = raw.strip().splitlines()
    if not lines:
        logger.error("Input file is empty: %s", path)
        sys.exit(1)

    # Detect CSV: first line contains commas
    if "," in lines[0]:
        return _parse_csv(lines)
    return _parse_text(lines)


def _parse_csv(lines: list[str]) -> list[str]:
    """Parse CSV — find domain column by header or fall back to position."""
    reader = csv.reader(io.StringIO("\n".join(lines)))
    rows = list(reader)
    if not rows:
        return []

    # Check if first row is a header
    header = [h.strip().strip('"').lower() for h in rows[0]]
    domain_col = None

    for i, h in enumerate(header):
        if h in ("domain", "host", "hostname", "url"):
            domain_col = i
            break

    if domain_col is not None:
        data_rows = rows[1:]
    else:
        # No header — assume domain is in second column (rank, domain, score)
        # unless there's only one column
        data_rows = rows
        domain_col = 1 if len(rows[0]) >= 2 else 0

    seen: set[str] = set()
    result: list[str] = []
    for row in data_rows:
        if len(row) <= domain_col:
            continue
        domain = row[domain_col].strip().strip('"').lower()
        if domain and domain not in seen:
            seen.add(domain)
            result.append(domain)
    return result


def _parse_text(lines: list[str]) -> list[str]:
    """Parse text file — one domain per line."""
    seen: set[str] = set()
    result: list[str] = []
    for line in lines:
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        if line not in seen:
            seen.add(line)
            result.append(line)
    return result


# ---------------------------------------------------------------------------
# State management (resume support)
# ---------------------------------------------------------------------------

class ScanState:
    """Persistent scan state for resume support."""

    def __init__(self, state_path: str, input_file: str, total_domains: int):
        self.path = state_path
        self.input_file = input_file
        self.total_domains = total_domains
        self.completed_domains: set[str] = set()
        self.domain_subdomains: dict[str, list[str]] = {}
        self.checked_hosts: set[str] = set()
        self._save_counter = 0

    @classmethod
    def load(cls, state_path: str, input_file: str, total_domains: int) -> ScanState:
        """Load existing state or create a new one."""
        state = cls(state_path, input_file, total_domains)
        if not Path(state_path).exists():
            return state

        try:
            with open(state_path, encoding="utf-8") as f:
                data = json.load(f)

            if data.get("version") != 1:
                logger.warning("State file version mismatch, starting fresh")
                return state
            if data.get("input_file") != input_file:
                logger.warning("State file is for a different input, starting fresh")
                return state

            state.completed_domains = set(data.get("completed_domains", []))
            state.domain_subdomains = data.get("domain_subdomains", {})
            state.checked_hosts = set(data.get("checked_hosts", []))

            logger.info(
                "Resumed state: %d/%d domains completed, %d hosts checked",
                len(state.completed_domains), total_domains, len(state.checked_hosts),
            )
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning("Corrupt state file, starting fresh: %s", e)

        return state

    def save(self) -> None:
        """Atomically write state to disk."""
        data = {
            "version": 1,
            "input_file": self.input_file,
            "total_domains": self.total_domains,
            "completed_domains": sorted(self.completed_domains),
            "domain_subdomains": self.domain_subdomains,
            "checked_hosts": sorted(self.checked_hosts),
        }
        # Atomic write: temp file + rename
        dir_path = os.path.dirname(self.path) or "."
        try:
            fd, tmp = tempfile.mkstemp(dir=dir_path, suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)
            os.replace(tmp, self.path)
        except OSError as e:
            logger.warning("Failed to save state: %s", e)

    def mark_host_checked(self, host: str) -> None:
        """Mark a host as checked, save periodically."""
        self.checked_hosts.add(host)
        self._save_counter += 1
        if self._save_counter % 20 == 0:
            self.save()

    def mark_domain_complete(self, domain: str, subdomains: list[str]) -> None:
        """Mark a domain as fully processed."""
        self.completed_domains.add(domain)
        self.domain_subdomains[domain] = subdomains
        self.save()


# ---------------------------------------------------------------------------
# JSONL output writer
# ---------------------------------------------------------------------------

class JsonlWriter:
    """Append-only JSONL writer with flush-per-host."""

    def __init__(self, path: str):
        self.path = path
        self._file = open(path, "a", encoding="utf-8")  # noqa: SIM115

    def write_finding(
        self,
        domain: str,
        host: str,
        result: PluginResult,
    ) -> None:
        """Write findings from a PluginResult as JSONL lines."""
        timestamp = datetime.now(UTC).isoformat()

        has_significant = any(f.severity >= Severity.LOW for f in result.findings)

        if has_significant:
            for finding in result.findings:
                if finding.severity < Severity.LOW:
                    continue
                exposed_files = [
                    e["path"] for e in result.data.get("exposed_files", [])
                ]
                record = {
                    "domain": domain,
                    "host": host,
                    "severity": finding.severity.label,
                    "title": finding.title,
                    "description": finding.description,
                    "evidence": finding.evidence,
                    "exposed_files": exposed_files,
                    "timestamp": timestamp,
                }
                self._file.write(json.dumps(record, ensure_ascii=False) + "\n")
        else:
            record = {
                "domain": domain,
                "host": host,
                "severity": "INFO",
                "title": "No sensitive files exposed",
                "description": "",
                "evidence": "",
                "exposed_files": [],
                "timestamp": timestamp,
            }
            self._file.write(json.dumps(record, ensure_ascii=False) + "\n")

        self._file.flush()

    def close(self) -> None:
        self._file.close()


# ---------------------------------------------------------------------------
# Rich progress display
# ---------------------------------------------------------------------------

def _make_progress():
    """Create Rich progress bar (or a no-op fallback)."""
    try:
        from rich.console import Console
        from rich.progress import (
            BarColumn,
            MofNCompleteColumn,
            Progress,
            SpinnerColumn,
            TextColumn,
            TimeElapsedColumn,
        )
        console = Console(stderr=True)
        return Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]Scanning domains"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
        )
    except ImportError:
        return None


def _log_finding_rich(severity: str, host: str, title: str) -> None:
    """Print colored finding to stderr."""
    try:
        from rich.console import Console
        colors = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "green",
        }
        Console(stderr=True).print(
            f"  [{colors.get(severity, 'blue')}][{severity}][/] {host}: {title}"
        )
    except ImportError:
        print(f"  [{severity}] {host}: {title}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Queue-based scanning: producer-consumer with priority
# ---------------------------------------------------------------------------

# Queue item: (priority, seq, domain, host)
# priority 0 = subdomain (high, checked first), priority 1 = root domain
# Within priority 0: negative seq → newest subdomains at the top (LIFO)
# Within priority 1: positive seq → input order preserved (FIFO)
QueueItem = tuple[int, int, str, str]

# Sentinel that compares greater than any real item
_STOP: QueueItem = (999, 0, "", "")


class DomainTracker:
    """Track per-domain completion across async workers."""

    def __init__(self) -> None:
        self._queued: dict[str, int] = {}     # domain → pending host count
        self._discovery_done: set[str] = set()
        self._subdomains: dict[str, list[str]] = {}

    def queue_host(self, domain: str) -> None:
        self._queued[domain] = self._queued.get(domain, 0) + 1

    def add_subdomain(self, domain: str, sub: str) -> None:
        self._subdomains.setdefault(domain, []).append(sub)

    def mark_discovery_done(self, domain: str) -> bool:
        """Returns True if domain is already fully complete (nothing was queued)."""
        self._discovery_done.add(domain)
        return self._queued.get(domain, 0) == 0

    def host_done(self, domain: str) -> bool:
        """Decrement pending count. Returns True when domain is fully complete."""
        self._queued[domain] -= 1
        return domain in self._discovery_done and self._queued[domain] == 0

    def get_subdomains(self, domain: str) -> list[str]:
        return self._subdomains.get(domain, [])


async def feed_domain(
    domain: str,
    registry: PluginRegistry,
    ctx: PluginContext,
    git_queue: asyncio.PriorityQueue,
    seq: itertools.count,
    tracker: DomainTracker,
    state: ScanState,
    skip_subdomains: bool,
    max_subdomains: int,
    shutdown_event: asyncio.Event,
    on_domain_done: asyncio.Queue,
) -> None:
    """Discover subdomains and stream hosts into the git-check queue."""
    if shutdown_event.is_set():
        return

    # Queue root domain (priority=1, FIFO order)
    if domain not in state.checked_hosts:
        tracker.queue_host(domain)
        await git_queue.put((1, next(seq), domain, domain))

    if skip_subdomains:
        if tracker.mark_discovery_done(domain):
            state.mark_domain_complete(domain, [])
            await on_domain_done.put(domain)
        return

    # Use cached subdomains from a previous interrupted run
    if domain in state.domain_subdomains:
        cached = state.domain_subdomains[domain]
        logger.debug("Using cached %d subdomains for %s", len(cached), domain)
        for sub in cached:
            tracker.add_subdomain(domain, sub)
            if sub not in state.checked_hosts:
                tracker.queue_host(domain)
                await git_queue.put((0, -next(seq), domain, sub))
        if tracker.mark_discovery_done(domain):
            state.mark_domain_complete(domain, cached)
            await on_domain_done.put(domain)
        return

    # Stream subdomains from providers as each one finishes
    providers = registry.by_provides("subdomains")
    providers = [
        p for p in providers
        if p.meta.default_enabled and p.meta.name != "subdomain_bruteforce"
    ]

    if not providers:
        state.domain_subdomains[domain] = []
        if tracker.mark_discovery_done(domain):
            state.mark_domain_complete(domain, [])
            await on_domain_done.put(domain)
        return

    target = Target.domain(domain)
    executor = AsyncExecutor(max_concurrency=len(providers))
    seen_subs: set[str] = set()

    async def _run_provider(provider_cls):
        plugin = provider_cls()
        try:
            await plugin.setup(ctx)
            result = await executor.run_one(plugin, target, ctx)
            subs: list[str] = []
            if result.ok:
                for sub in result.data.get("subdomains", []):
                    host = sub.lower() if isinstance(sub, str) else sub.get("host", "").lower()
                    if host and host != domain:
                        subs.append(host)
            await plugin.teardown()
            return subs
        except Exception as e:
            logger.debug(
                "Provider %s failed for %s: %s", provider_cls.meta.name, domain, e,
            )
            return []

    tasks = [_run_provider(p) for p in providers]
    for coro in asyncio.as_completed(tasks):
        if shutdown_event.is_set():
            break
        try:
            new_subs = await coro
        except Exception:
            continue

        for sub in new_subs:
            if len(seen_subs) >= max_subdomains:
                break
            if sub in seen_subs:
                continue
            seen_subs.add(sub)
            tracker.add_subdomain(domain, sub)
            if sub not in state.checked_hosts:
                tracker.queue_host(domain)
                # priority=0, negative seq → newest first
                await git_queue.put((0, -next(seq), domain, sub))

    all_subs = sorted(seen_subs)
    state.domain_subdomains[domain] = all_subs
    if all_subs:
        logger.info("Found %d subdomains for %s", len(all_subs), domain)

    if tracker.mark_discovery_done(domain):
        state.mark_domain_complete(domain, all_subs)
        await on_domain_done.put(domain)


async def git_worker(
    git_queue: asyncio.PriorityQueue,
    git_plugin,
    ctx: PluginContext,
    tracker: DomainTracker,
    state: ScanState,
    writer: JsonlWriter,
    shutdown_event: asyncio.Event,
    stats: dict[str, int],
    on_domain_done: asyncio.Queue,
) -> None:
    """Pull hosts from the priority queue and run git_exposure checks."""
    single_executor = AsyncExecutor(max_concurrency=1)

    while True:
        item: QueueItem = await git_queue.get()
        _prio, _seq, domain, host = item

        if domain == "":  # sentinel
            git_queue.task_done()
            break

        if shutdown_event.is_set():
            git_queue.task_done()
            continue

        # Build target
        target = (
            Target.domain(host) if host == domain
            else Target.subdomain(host, parent=domain)
        )

        try:
            result = await single_executor.run_one(git_plugin, target, ctx)
            writer.write_finding(domain, host, result)
            for finding in result.findings:
                if finding.severity >= Severity.LOW:
                    stats["findings"] += 1
                    _log_finding_rich(finding.severity.label, host, finding.title)
        except Exception as e:
            logger.debug("Error scanning %s: %s", host, e)

        state.mark_host_checked(host)

        # Check if this domain is now fully complete
        if tracker.host_done(domain):
            subs = tracker.get_subdomains(domain)
            state.mark_domain_complete(domain, subs)
            await on_domain_done.put(domain)

        git_queue.task_done()


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

async def init_context(
    settings: Settings,
    rate_rps: float,
) -> tuple[PluginRegistry, PluginContext, AsyncHttpClient]:
    """Initialize framework components: registry, context, HTTP client."""
    registry = PluginRegistry()
    count = registry.discover()
    logger.info("Discovered %d plugins", count)

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
    rate = RateLimiter(rate=rate_rps, burst=max(10, int(rate_rps // 3)))
    wordlists = WordlistManager()
    provider_pool = ProviderPool(registry)

    ctx = PluginContext(
        config=settings,
        http=http,
        dns=dns,
        net=net,
        rate=rate,
        wordlists=wordlists,
        providers=provider_pool,
    )

    return registry, ctx, http


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def async_main(args: argparse.Namespace) -> None:
    """Main async entry point."""
    # Load domains
    domains = load_domains(args.input_file)
    logger.info("Loaded %d domains from %s", len(domains), args.input_file)

    # State management
    state_path = args.output + ".state.json"
    if args.no_resume and Path(state_path).exists():
        os.remove(state_path)
        logger.info("Removed old state file (--no-resume)")

    state = ScanState.load(state_path, args.input_file, len(domains))

    # Filter already completed domains
    pending = [d for d in domains if d not in state.completed_domains]
    if len(pending) < len(domains):
        logger.info(
            "Resuming: %d/%d domains already completed, %d remaining",
            len(domains) - len(pending), len(domains), len(pending),
        )

    if not pending:
        logger.info("All domains already processed. Use --no-resume to restart.")
        return

    # Init framework
    settings = Settings.load(args.config) if args.config else Settings.load()
    registry, ctx, http = await init_context(settings, args.rate)

    # Prepare git_exposure plugin
    git_cls = registry.get("git_exposure")
    if not git_cls:
        logger.error("git_exposure plugin not found. Check plugin discovery.")
        await http.close()
        sys.exit(1)

    git_plugin = git_cls()
    await git_plugin.setup(ctx)

    # JSONL writer
    writer = JsonlWriter(args.output)

    # Graceful shutdown
    shutdown_event = asyncio.Event()
    _ctrl_c_count = [0]

    def _signal_handler(signum, frame):
        _ctrl_c_count[0] += 1
        if _ctrl_c_count[0] == 1:
            logger.warning("Ctrl+C received — draining queue, saving state...")
            shutdown_event.set()
        else:
            raise KeyboardInterrupt

    signal.signal(signal.SIGINT, _signal_handler)

    # Priority queue + shared state
    git_queue: asyncio.PriorityQueue[QueueItem] = asyncio.PriorityQueue()
    seq = itertools.count()
    tracker = DomainTracker()
    stats: dict[str, int] = {"findings": 0}
    on_domain_done: asyncio.Queue[str] = asyncio.Queue()

    # Number of git-check workers: enough to saturate the rate limiter
    num_workers = max(args.concurrency * 4, 20)

    progress = _make_progress()

    try:
        # --- launch workers ---
        workers = [
            asyncio.create_task(
                git_worker(
                    git_queue, git_plugin, ctx, tracker,
                    state, writer, shutdown_event, stats, on_domain_done,
                )
            )
            for _ in range(num_workers)
        ]

        # --- launch domain feeders (semaphore-gated, input order) ---
        domain_sem = asyncio.Semaphore(args.concurrency)

        async def _feed_one(d: str) -> None:
            async with domain_sem:
                await feed_domain(
                    d, registry, ctx, git_queue, seq, tracker,
                    state, args.skip_subdomains, args.max_subdomains,
                    shutdown_event, on_domain_done,
                )

        feeders = [asyncio.create_task(_feed_one(d)) for d in pending]

        # --- progress tracking (driven by on_domain_done events) ---
        if progress:
            with progress:
                task_id = progress.add_task("scan", total=len(pending))
                completed = 0
                while completed < len(pending) and not shutdown_event.is_set():
                    try:
                        await asyncio.wait_for(on_domain_done.get(), timeout=0.5)
                        completed += 1
                        progress.advance(task_id)
                    except TimeoutError:
                        continue
        else:
            completed = 0
            while completed < len(pending) and not shutdown_event.is_set():
                try:
                    await asyncio.wait_for(on_domain_done.get(), timeout=0.5)
                    completed += 1
                    print(
                        f"\r  Progress: {completed}/{len(pending)} domains",
                        end="", file=sys.stderr, flush=True,
                    )
                except TimeoutError:
                    continue
            print(file=sys.stderr)

        # --- wait for feeders to finish ---
        await asyncio.gather(*feeders, return_exceptions=True)

        # --- drain remaining queue items ---
        await git_queue.join()

        # --- stop workers ---
        for _ in workers:
            await git_queue.put(_STOP)
        await asyncio.gather(*workers, return_exceptions=True)

    finally:
        state.save()
        writer.close()
        await git_plugin.teardown()
        await http.close()

    # Summary
    print(
        f"\nDone. Processed {len(state.completed_domains)}/{len(domains)} domains, "
        f"{len(state.checked_hosts)} hosts checked, "
        f"{stats['findings']} findings.",
        file=sys.stderr,
    )
    print(f"Results: {args.output}", file=sys.stderr)
    if len(state.completed_domains) < len(domains):
        print(
            f"State saved: {state_path} — re-run to resume.",
            file=sys.stderr,
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Bulk Git Exposure Scanner — powered by Basilisk framework",
    )
    parser.add_argument(
        "input_file",
        help="File with domains (text: one per line, or CSV with Domain column)",
    )
    parser.add_argument(
        "-o", "--output",
        default="git_exposure_results.jsonl",
        help="Output JSONL file (default: git_exposure_results.jsonl)",
    )
    parser.add_argument(
        "-c", "--concurrency",
        type=int, default=5,
        help="Max parallel domains (default: 5)",
    )
    parser.add_argument(
        "--skip-subdomains",
        action="store_true",
        help="Skip subdomain discovery, only scan root domains",
    )
    parser.add_argument(
        "--max-subdomains",
        type=int, default=200,
        help="Max subdomains per domain (default: 200)",
    )
    parser.add_argument(
        "--rate",
        type=float, default=50.0,
        help="Global requests per second (default: 50)",
    )
    parser.add_argument(
        "--config",
        help="Path to Basilisk YAML config file",
    )
    parser.add_argument(
        "--no-resume",
        action="store_true",
        help="Ignore state file, start from scratch",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # Logging setup
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )
    # Suppress noisy loggers
    logging.getLogger("aiohttp").setLevel(logging.WARNING)
    logging.getLogger("basilisk.quality").setLevel(logging.WARNING)

    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
