#!/usr/bin/env python3
"""Batch training runner — runs all 20 training profiles sequentially.

Usage:
    .venv/Scripts/python.exe run_batch_training.py [--max-steps N]

Expects containers already running (docker-compose.training.yml up -d).
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
from pathlib import Path

# Force UTF-8 output on Windows
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Add project to path
sys.path.insert(0, str(Path(__file__).parent))

PROFILES_DIR = Path(__file__).parent / "training_profiles"

# Order: easiest first (from last benchmark), hardest last
PROFILE_ORDER = [
    "xvwa",         # 95.2%
    "wackopicko",   # 93.8%
    "dsvw",         # 90.9%
    "dvwa",         # 87.5%
    "bwapp",        # 87.5%
    "vampi",        # 87.5%
    "hackazon",     # 85.7%
    "mutillidae",   # 83.3%
    "juice_shop",   # 82.8%
    "vapi",         # 80.0%
    "gruyere",      # 69.2%
    "nodegoat",     # 66.7%
    "dvga",         # 66.7%
    "badstore",     # 63.2%
    "altoro_mutual",# 56.2%
    "crapi",        # 33.3%
    "webgoat",      # 23.1%
    "railsgoat",    # 22.2%
    "pixi",         # 0% last time
    "dvws",         # NEW: WebSocket vulnerabilities
]


async def run_single(profile_name: str, max_steps: int | None = None) -> dict:
    """Run a single training profile and return results."""
    from basilisk.config import Settings
    from basilisk.training.profile import TrainingProfile
    from basilisk.training.runner import TrainingRunner

    profile_path = PROFILES_DIR / f"{profile_name}.yaml"
    if not profile_path.exists():
        return {"name": profile_name, "error": f"Profile not found: {profile_path}"}

    tp = TrainingProfile.load(profile_path)
    if max_steps is not None:
        tp.max_steps = max_steps

    settings = Settings.load()
    runner = TrainingRunner(
        tp,
        manage_docker=False,  # Containers already running
        project_root=Path(__file__).parent,
    )

    start = time.time()
    try:
        report = await runner.run(config=settings)
        elapsed = time.time() - start
        return {
            "name": report.profile_name,
            "target": report.target,
            "coverage": report.coverage,
            "discovered": report.discovered,
            "total": report.total_expected,
            "verified": report.verified,
            "verification_rate": report.verification_rate,
            "steps": report.steps_taken,
            "elapsed": elapsed,
            "passed": report.passed,
            "findings": report.findings_detail,
        }
    except Exception as e:
        elapsed = time.time() - start
        return {
            "name": profile_name,
            "error": str(e),
            "elapsed": elapsed,
        }


async def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--max-steps", type=int, default=None)
    parser.add_argument("--profiles", nargs="*", default=None,
                        help="Specific profiles to run (default: all)")
    args = parser.parse_args()

    profiles = args.profiles or PROFILE_ORDER

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    # Suppress noisy loggers
    logging.getLogger("aiohttp").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)

    results = []
    total_start = time.time()

    print(f"\n{'='*80}")
    print(f"  BASILISK BATCH TRAINING — {len(profiles)} profiles")
    print(f"{'='*80}\n")

    for i, name in enumerate(profiles, 1):
        print(f"\n{'─'*60}")
        print(f"  [{i}/{len(profiles)}] Training: {name}")
        print(f"{'─'*60}")

        result = await run_single(name, args.max_steps)
        results.append(result)

        if "error" in result:
            print(f"  ERROR: {result['error']} ({result.get('elapsed', 0):.1f}s)")
        else:
            print(
                f"  Coverage: {result['coverage']*100:.1f}% "
                f"({result['discovered']}/{result['total']}) "
                f"| Verified: {result['verified']} ({result['verification_rate']*100:.1f}%) "
                f"| Steps: {result['steps']} "
                f"| Time: {result['elapsed']:.1f}s"
            )

    total_elapsed = time.time() - total_start

    # Summary table
    print(f"\n\n{'='*80}")
    print(f"  SUMMARY — Batch Training Results")
    print(f"{'='*80}")
    print(f"{'Name':<20} {'Coverage':>10} {'Disc':>6} {'Total':>6} {'Verif':>6} {'Steps':>6} {'Time':>8}")
    print(f"{'─'*20} {'─'*10} {'─'*6} {'─'*6} {'─'*6} {'─'*6} {'─'*8}")

    total_disc = 0
    total_exp = 0
    total_verif = 0

    for r in sorted(results, key=lambda x: x.get("coverage", -1), reverse=True):
        if "error" in r:
            print(f"{r['name']:<20} {'ERROR':>10}  {r['error'][:40]}")
        else:
            cov = f"{r['coverage']*100:.1f}%"
            disc = r["discovered"]
            total = r["total"]
            verif = r["verified"]
            steps = r["steps"]
            elapsed = f"{r['elapsed']:.0f}s"
            total_disc += disc
            total_exp += total
            total_verif += verif
            print(f"{r['name']:<20} {cov:>10} {disc:>6} {total:>6} {verif:>6} {steps:>6} {elapsed:>8}")

    avg_cov = total_disc / total_exp * 100 if total_exp else 0
    print(f"{'─'*20} {'─'*10} {'─'*6} {'─'*6} {'─'*6} {'─'*6} {'─'*8}")
    print(f"{'TOTAL':<20} {avg_cov:>9.1f}% {total_disc:>6} {total_exp:>6} {total_verif:>6} {'':>6} {total_elapsed:>7.0f}s")
    print()

    # Write results to file
    import json
    results_file = Path(__file__).parent / "training_results.json"
    with open(results_file, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"Results saved to {results_file}")


if __name__ == "__main__":
    asyncio.run(main())
