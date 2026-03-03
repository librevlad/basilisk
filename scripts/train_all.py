"""Run training for all 20 container profiles and verify report generation.

Usage:
    .venv/Scripts/python.exe scripts/train_all.py [--max-steps N] [--profile NAME]
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import time
from pathlib import Path

# Ensure project root is on sys.path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PROFILES_DIR = ROOT / "training" / "profiles"

logger = logging.getLogger("train_all")


async def run_one_profile(
    profile_path: Path,
    max_steps: int,
) -> dict:
    """Run training for a single profile, return result dict."""
    from basilisk.config import Settings
    from basilisk.events.bus import EventBus
    from basilisk.reporting import ReportWriter
    from basilisk.training.profile import TrainingProfile
    from basilisk.training.runner import TrainingRunner
    from basilisk.training.validator import FindingTracker

    tp = TrainingProfile.load(profile_path)
    tp.max_steps = max_steps

    settings = Settings.load()
    bus = EventBus()
    proj_root = PROFILES_DIR.parent.parent

    runner = TrainingRunner(
        tp,
        target_override=None,
        manage_docker=True,
        project_root=proj_root,
    )
    tracker = FindingTracker(tp)
    writer = ReportWriter(bus, target=tp.target, max_steps=tp.max_steps, mode="train")

    t0 = time.monotonic()
    report_dir = await writer.start()
    try:
        report = await runner.run(config=settings, bus=bus, tracker=tracker)
    except Exception as exc:
        elapsed = time.monotonic() - t0
        return {
            "profile": tp.name,
            "status": "ERROR",
            "error": str(exc),
            "elapsed": elapsed,
            "report_dir": str(report_dir),
            "report_exists": (report_dir / "report.html").exists(),
        }
    else:
        await writer.finalize_training(report, tracker)
        elapsed = time.monotonic() - t0

        html_path = report_dir / "report.html"
        json_path = report_dir / "report.json"
        html_exists = html_path.exists()
        html_size = html_path.stat().st_size if html_exists else 0
        json_exists = json_path.exists()

        # Quick sanity: HTML should contain training section
        has_training = False
        has_container = False
        if html_exists:
            content = html_path.read_text(encoding="utf-8")
            has_training = 'id="training"' in content
            has_container = "Container runs as root" in content

        return {
            "profile": tp.name,
            "status": "PASSED" if report.passed else "FAILED",
            "coverage": f"{report.coverage:.0%}",
            "verified": f"{report.verification_rate:.0%}",
            "discovered": report.discovered,
            "total_expected": report.total_expected,
            "steps": report.steps_taken,
            "elapsed": elapsed,
            "report_dir": str(report_dir),
            "report_exists": html_exists,
            "report_size_kb": html_size // 1024,
            "json_exists": json_exists,
            "has_training_section": has_training,
            "has_container_finding": has_container,
        }


async def main(max_steps: int, profile_filter: str | None) -> int:
    """Run all profiles sequentially."""
    profiles = sorted(PROFILES_DIR.glob("*.yaml"), key=lambda p: p.stem)
    if profile_filter:
        profiles = [p for p in profiles if profile_filter in p.stem]
    if not profiles:
        logger.error("No profiles found matching filter: %s", profile_filter)
        return 1

    logger.info("=" * 70)
    logger.info("TRAINING ALL %d CONTAINERS (max_steps=%d)", len(profiles), max_steps)
    logger.info("=" * 70)

    results: list[dict] = []
    total_t0 = time.monotonic()

    for i, ppath in enumerate(profiles, 1):
        name = ppath.stem
        logger.info("")
        logger.info("[%d/%d] Starting: %s", i, len(profiles), name)
        logger.info("-" * 50)

        result = await run_one_profile(ppath, max_steps)
        results.append(result)

        status = result.get("status", "?")
        elapsed = result.get("elapsed", 0)
        report_ok = result.get("report_exists", False)
        logger.info(
            "[%d/%d] %s: %s | report=%s | %.1fs",
            i, len(profiles), name, status,
            "OK" if report_ok else "MISSING", elapsed,
        )
        if result.get("error"):
            logger.error("  Error: %s", result["error"])

    total_elapsed = time.monotonic() - total_t0

    # Summary
    logger.info("")
    logger.info("=" * 70)
    logger.info("SUMMARY")
    logger.info("=" * 70)
    logger.info("%-20s %-8s %-8s %-5s %-6s %-8s %-5s %-5s",
                "Profile", "Status", "Covg", "Disc", "Time", "Report", "Train", "Cont")
    logger.info("-" * 70)

    ok_count = 0
    report_count = 0
    training_section_count = 0
    container_finding_count = 0

    for r in results:
        name = r["profile"]
        status = r.get("status", "?")
        covg = r.get("coverage", "-")
        disc = str(r.get("discovered", "-"))
        elapsed_s = f"{r.get('elapsed', 0):.0f}s"
        report_ok = "OK" if r.get("report_exists") else "MISS"
        has_train = "Y" if r.get("has_training_section") else "N"
        has_cont = "Y" if r.get("has_container_finding") else "N"

        logger.info("%-20s %-8s %-8s %-5s %-6s %-8s %-5s %-5s",
                     name, status, covg, disc, elapsed_s, report_ok, has_train, has_cont)

        if status in ("PASSED", "FAILED"):
            ok_count += 1
        if r.get("report_exists"):
            report_count += 1
        if r.get("has_training_section"):
            training_section_count += 1
        if r.get("has_container_finding"):
            container_finding_count += 1

    logger.info("-" * 70)
    logger.info("Total: %d profiles, %d ran OK, %d reports generated",
                len(results), ok_count, report_count)
    logger.info("Training sections: %d/%d, Container findings: %d/%d",
                training_section_count, len(results),
                container_finding_count, len(results))
    logger.info("Total time: %.0fs", total_elapsed)

    if report_count < len(results):
        logger.error("FAIL: Not all profiles generated reports!")
        return 1
    logger.info("ALL %d PROFILES GENERATED REPORTS", len(results))
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run training for all profiles")
    parser.add_argument("--max-steps", type=int, default=10,
                        help="Max steps per profile (default: 10)")
    parser.add_argument("--profile", type=str, default=None,
                        help="Filter to run only matching profile(s)")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )
    # Suppress noisy loggers
    logging.getLogger("basilisk").setLevel(logging.WARNING)
    logging.getLogger("aiohttp").setLevel(logging.WARNING)

    rc = asyncio.run(main(args.max_steps, args.profile))
    sys.exit(rc)
