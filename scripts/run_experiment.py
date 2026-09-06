#!/usr/bin/env python3
"""Run a complete experiment suite.

Usage:
  python scripts/run_experiment.py --config ours_full --target open5gs --hours 24
  python scripts/run_experiment.py --all-configs --all-targets --runs 3
"""

import argparse
import asyncio
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import FiveGCImpl
from src.experiments.runner import ExperimentRunner, EXPERIMENT_CONFIGS
from src.experiments.analysis import ResultAnalyzer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("experiment")


async def main():
    parser = argparse.ArgumentParser(description="5G Fuzzing Experiment Runner")
    parser.add_argument("--config", choices=list(EXPERIMENT_CONFIGS.keys()),
                       help="Single configuration to run")
    parser.add_argument("--all-configs", action="store_true",
                       help="Run all configurations")
    parser.add_argument("--target", choices=[t.value for t in FiveGCImpl],
                       help="Single target 5GC")
    parser.add_argument("--all-targets", action="store_true",
                       help="Run against all targets")
    parser.add_argument("--runs", type=int, default=3,
                       help="Runs per configuration (default: 3)")
    parser.add_argument("--hours", type=int, default=24,
                       help="Hours per run (default: 24)")
    parser.add_argument("--output", type=str, default="./results",
                       help="Output directory")
    parser.add_argument("--live", action="store_true",
                       help="Run against live 5GC deployments (Docker required)")
    parser.add_argument("--analyze-only", type=str,
                       help="Only analyze existing results in directory")
    args = parser.parse_args()

    if args.analyze_only:
        analyzer = ResultAnalyzer()
        analyzer.load_from_dir(Path(args.analyze_only))
        report = analyzer.generate_report()
        import json
        print(json.dumps(report, indent=2, default=str))
        return

    configs = [args.config] if args.config else (
        list(EXPERIMENT_CONFIGS.keys()) if args.all_configs else ["ours_full"]
    )
    targets = (
        [FiveGCImpl(args.target)] if args.target
        else list(FiveGCImpl) if args.all_targets
        else [FiveGCImpl.OPEN5GS]
    )

    runner = ExperimentRunner(
        output_dir=Path(args.output),
        runs_per_config=args.runs,
        hours_per_run=args.hours,
        live_mode=args.live,
    )

    logger.info(f"Configs: {configs}")
    logger.info(f"Targets: {[t.value for t in targets]}")
    logger.info(f"Runs per config: {args.runs}")
    logger.info(f"Hours per run: {args.hours}")

    results = await runner.run_all(configs=configs, targets=targets)

    # Run analysis
    analyzer = ResultAnalyzer(results=results)
    report = analyzer.generate_report()

    print("\n" + "=" * 60)
    print("EXPERIMENT COMPLETE")
    print("=" * 60)
    print(f"Total runs: {report['overview']['total_experiment_runs']}")
    print(f"Total crashes found: {report['overview']['total_crashes_found']}")
    print(f"Total unique crashes: {report['overview']['total_unique_crashes']}")

    print("\nHypothesis Tests:")
    for h_name, h_result in report["hypothesis_tests"].items():
        if h_result.get("status") == "insufficient_data":
            print(f"  {h_name}: INSUFFICIENT DATA")
        else:
            sig = "✓ SIGNIFICANT" if h_result.get("significant") else "✗ not significant"
            print(f"  {h_name}: {sig} (p={h_result.get('p_value', 'N/A'):.4f}, "
                  f"d={h_result.get('cohens_d', 'N/A'):.3f})")


if __name__ == "__main__":
    asyncio.run(main())
