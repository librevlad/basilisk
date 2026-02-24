"""Example: run a full autonomous audit on target domains.

Usage:
    python examples/full_audit.py
"""

import asyncio
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)

from basilisk import Basilisk


async def main():
    targets = ["example.com"]

    print(f"\nAuditing: {', '.join(targets)}")
    print("=" * 60)

    result = await Basilisk(*targets, max_steps=50).run()

    print("\n" + "=" * 60)
    print(f"AUDIT COMPLETE: {len(result.findings)} findings")
    print(f"Steps: {result.steps}")
    print(f"Duration: {result.duration:.1f}s")
    print(f"Reason: {result.termination_reason}")

    if result.graph_data:
        print(
            f"Graph: {result.graph_data.get('entity_count', 0)} entities, "
            f"{result.graph_data.get('relation_count', 0)} relations"
        )

    # Severity breakdown
    sev_counts: dict[str, int] = {}
    for f in result.findings:
        sev = f.severity.name if hasattr(f.severity, "name") else str(f.severity)
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    if sev_counts:
        print("\nSeverity breakdown:")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev_counts.get(sev):
                print(f"  {sev}: {sev_counts[sev]}")

    return result


if __name__ == "__main__":
    asyncio.run(main())
