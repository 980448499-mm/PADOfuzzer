#!/usr/bin/env python3
"""Automated ablation experiment runner.

Maps our v2 live fuzzers to the 5 experimental configurations:
  ours_full      — FSM=ON,  cross_protocol=ON,  all 10 mutations
  ours_no_fsm    — FSM=OFF, cross_protocol=ON,  all 10 mutations
  ours_no_cross  — FSM=ON,  cross_protocol=OFF, 9 mutations
  aflnet_like    — FSM=OFF, cross_protocol=OFF, 1 mutation (empty_values)
  random         — FSM=OFF, cross_protocol=OFF, random only

Usage:
  # Full ablation: 5 configs × 3 targets × 1 run = 15 experiments
  python scripts/run_experiments.py --hours 1 --runs 1

  # Quick test: 2 configs × 1 target
  python scripts/run_experiments.py --hours 0.1 --targets oai --configs ours_full,random

Generates:
  results/experiments/<target>/<config>_run<N>.json
  results/experiments/comparison_report.json
"""

import argparse, asyncio, json, os, sys, time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# ─── Configuration matrix ──────────────────────────────────────

EXPERIMENT_MATRIX = {
    "ours_full": {
        "description": "Full system: FSM + cross-protocol + 10 mutations",
        "fsm": True,
        "cross_protocol": True,
        "mutations": "all",
    },
    "ours_no_fsm": {
        "description": "Ablation: no FSM guidance",
        "fsm": False,
        "cross_protocol": True,
        "mutations": "all",
    },
    "ours_no_cross_protocol": {
        "description": "Ablation: no cross-protocol mutation",
        "fsm": True,
        "cross_protocol": False,
        "mutations": "all",
    },
    "aflnet_like": {
        "description": "AFLNet baseline: single mutation, no FSM",
        "fsm": False,
        "cross_protocol": False,
        "mutations": "single",
    },
    "random": {
        "description": "Lower bound: random mutation, no feedback",
        "fsm": False,
        "cross_protocol": False,
        "mutations": "single",
    },
}

TARGET_CONFIG = {
    "oai": {
        "script": "live_fuzz_oai.py",
        "containers": ["oai-nrf", "oai-udm", "oai-udr", "oai-ausf", "mysql"],
    },
    "free5gc": {
        "script": "live_fuzz_free5gc.py",
        "containers": [
            "fuzzing-free5gc-nrf", "fuzzing-free5gc-amf", "fuzzing-free5gc-smf",
            "fuzzing-free5gc-ausf", "fuzzing-free5gc-udm", "fuzzing-free5gc-udr",
            "fuzzing-free5gc-pcf", "fuzzing-free5gc-nssf",
        ],
    },
    "open5gs": {
        "script": "live_fuzz_open5gs.py",
        "containers": [
            "fuzzing-open5gs-nrf", "fuzzing-open5gs-amf", "fuzzing-open5gs-smf",
            "fuzzing-open5gs-ausf", "fuzzing-open5gs-udm", "fuzzing-open5gs-udr",
            "fuzzing-open5gs-pcf", "fuzzing-open5gs-nssf", "fuzzing-open5gs-scp",
        ],
    },
}


def build_fuzzer_cmd(target: str, config_name: str, hours: float,
                      output_dir: Path) -> List[str]:
    """Build the CLI command for a given target and experiment config."""
    t = TARGET_CONFIG[target]
    c = EXPERIMENT_MATRIX[config_name]

    cmd = [
        sys.executable,
        str(Path(__file__).resolve().parent / t["script"]),
        "--hours", str(hours),
        "--output", str(output_dir),
    ]
    if not c["fsm"]:
        cmd.append("--no-fsm")
    if not c["cross_protocol"]:
        cmd.append("--no-cross-protocol")

    return cmd


async def run_single_experiment(target: str, config_name: str,
                                 hours: float, run_id: int,
                                 output_dir: Path) -> Dict[str, Any]:
    """Run a single experiment and return the result."""
    config_out = output_dir / target / config_name
    config_out.mkdir(parents=True, exist_ok=True)

    cmd = build_fuzzer_cmd(target, config_name, hours, config_out)
    c = EXPERIMENT_MATRIX[config_name]

    print(f"\n{'='*60}")
    print(f"[{datetime.now():%H:%M:%S}] {target}/{config_name} run={run_id}")
    print(f"  FSM={c['fsm']} cross_protocol={c['cross_protocol']}")
    print(f"  {' '.join(cmd)}")
    print(f"{'='*60}")

    start = time.time()
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    elapsed = time.time() - start

    # Parse the JSON report file
    report = None
    for f in sorted(config_out.glob("fuzz_report_*.json"),
                     key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            report = json.loads(f.read_text())
            break
        except (json.JSONDecodeError, IOError):
            pass

    if report is None:
        print(f"  WARNING: No report found. stdout snippet: {stdout[-500:].decode()}")
        return {
            "target": target, "config": config_name, "run_id": run_id,
            "status": "failed", "duration": elapsed,
        }

    campaign = report.get("campaign", {})
    crashes = report.get("crashes", {})
    coverage = report.get("coverage", {})
    strategy = report.get("strategy_effectiveness", {})
    fsm_data = report.get("fsm", {})

    result = {
        "target": target,
        "config": config_name,
        "run_id": run_id,
        "status": "completed",
        "duration": elapsed,
        "requests": campaign.get("requests_sent", 0),
        "request_rate": campaign.get("request_rate", 0),
        "total_crashes": crashes.get("total", 0),
        "crash_by_severity": crashes.get("by_severity", {}),
        "unique_responses": coverage.get("total_unique_responses", 0),
        "coverage_growth_rate": coverage.get("growth_rate", 0),
        "plateau_detected": coverage.get("plateau_detected", False),
        "fsm_states": fsm_data.get("discovered_states", 0),
        "top_strategy": strategy["ranking"][0]["strategy"] if strategy.get("ranking") else "N/A",
        "top_strategy_score": strategy["ranking"][0]["score"] if strategy.get("ranking") else 0,
        "crash_details": crashes.get("details", []),
    }

    # Save per-run result
    result_path = config_out / f"experiment_run{run_id}.json"
    result_path.write_text(json.dumps(result, indent=2, default=str))

    print(f"  Result: {result['requests']} reqs, {result['total_crashes']} crashes, "
          f"{result['unique_responses']} unique responses, "
          f"FSM={result['fsm_states']} states, {elapsed:.0f}s")

    return result


async def run_all_experiments(targets: List[str], configs: List[str],
                               hours: float, runs: int,
                               output_dir: Path) -> List[Dict]:
    """Run the full experiment matrix."""
    total = len(targets) * len(configs) * runs
    results: List[Dict] = []
    count = 0

    print(f"\n{'#'*60}")
    print(f"Experiment Suite: {len(targets)} targets × {len(configs)} configs × {runs} runs = {total} total")
    print(f"Hours per run: {hours}h")
    print(f"Output: {output_dir}")
    print(f"{'#'*60}")

    for run_id in range(1, runs + 1):
        for target in targets:
            for config_name in configs:
                count += 1
                print(f"\n[{count}/{total}]", end=" ")
                result = await run_single_experiment(
                    target, config_name, hours, run_id, output_dir)
                results.append(result)

    return results


def generate_comparison_report(results: List[Dict],
                                output_dir: Path) -> Dict[str, Any]:
    """Generate statistical comparison report."""
    from scipy import stats as scipy_stats

    # Group by config
    grouped: Dict[str, List[Dict]] = defaultdict(list)
    for r in results:
        if r["status"] == "completed":
            grouped[r["config"]].append(r)

    # Per-config summary
    config_summaries = {}
    for config_name, group in grouped.items():
        crashes_list = [r["total_crashes"] for r in group]
        responses_list = [r["unique_responses"] for r in group]
        requests_list = [r["requests"] for r in group]

        config_summaries[config_name] = {
            "runs": len(group),
            "total_crashes_mean": float(np.mean(crashes_list)),
            "total_crashes_std": float(np.std(crashes_list)),
            "unique_responses_mean": float(np.mean(responses_list)),
            "unique_responses_std": float(np.std(responses_list)),
            "requests_mean": float(np.mean(requests_list)),
            "targets": list(set(r["target"] for r in group)),
        }

    # Hypothesis tests (if enough data)
    hypothesis_tests = {}
    ours = grouped.get("ours_full", [])
    aflnet = grouped.get("aflnet_like", [])
    random_cfg = grouped.get("random", [])

    # H1: ours_full > aflnet_like for unique responses
    if len(ours) >= 3 and len(aflnet) >= 3:
        ours_resp = [r["unique_responses"] for r in ours]
        afl_resp = [r["unique_responses"] for r in aflnet]
        stat, p = scipy_stats.mannwhitneyu(ours_resp, afl_resp, alternative="greater")
        d = (np.mean(ours_resp) - np.mean(afl_resp)) / max(
            np.sqrt((np.var(ours_resp) + np.var(afl_resp)) / 2), 0.01)
        hypothesis_tests["H1_fsm_vs_aflnet"] = {
            "hypothesis": "H1: FSM-guided > AFLNet-like for unique responses",
            "ours_mean": float(np.mean(ours_resp)),
            "aflnet_mean": float(np.mean(afl_resp)),
            "p_value": float(p),
            "significant": bool(p < 0.05),
            "cohens_d": float(d),
        }

    # H2: ours_full > random (upper bound vs lower bound)
    if len(ours) >= 3 and len(random_cfg) >= 3:
        ours_c = [r["total_crashes"] for r in ours]
        rnd_c = [r["total_crashes"] for r in random_cfg]
        stat, p = scipy_stats.mannwhitneyu(ours_c, rnd_c, alternative="greater")
        hypothesis_tests["H2_ours_vs_random"] = {
            "hypothesis": "H2: Full system > Random for crash discovery",
            "ours_mean": float(np.mean(ours_c)),
            "random_mean": float(np.mean(rnd_c)),
            "p_value": float(p),
            "significant": bool(p < 0.05),
        }

    report = {
        "experiment_suite": {
            "total_runs": len(results),
            "completed_runs": sum(1 for r in results if r["status"] == "completed"),
            "failed_runs": sum(1 for r in results if r["status"] != "completed"),
            "generated_at": datetime.now().isoformat(),
        },
        "config_comparison": config_summaries,
        "hypothesis_tests": hypothesis_tests,
        "per_target": {},
    }

    # Per-target breakdown
    for target in set(r["target"] for r in results if r["status"] == "completed"):
        target_results = [r for r in results if r["target"] == target]
        by_config = defaultdict(list)
        for r in target_results:
            by_config[r["config"]].append(r["unique_responses"])

        best_cfg = max(by_config, key=lambda c: np.mean(by_config[c]))
        report["per_target"][target] = {
            "configs_tested": list(by_config.keys()),
            "best_config": best_cfg,
            "best_unique_responses": float(np.mean(by_config[best_cfg])),
        }

    # Save
    report_path = output_dir / "comparison_report.json"
    report_path.write_text(json.dumps(report, indent=2, default=str))
    print(f"\nComparison report: {report_path}")

    return report


def print_comparison_table(report: Dict[str, Any]):
    """Print a formatted comparison table."""
    comp = report.get("config_comparison", {})
    if not comp:
        return

    print(f"\n{'='*80}")
    print("EXPERIMENT COMPARISON")
    print(f"{'='*80}")
    print(f"{'Config':<25s} {'Runs':>5s} {'Crashes±Std':>15s} {'Responses±Std':>18s} {'Requests':>10s}")
    print(f"{'-'*25} {'-'*5} {'-'*15} {'-'*18} {'-'*10}")

    for config_name, summary in comp.items():
        print(f"{config_name:<25s} {summary['runs']:>5d} "
              f"{summary['total_crashes_mean']:>6.1f}±{summary['total_crashes_std']:>4.1f}  "
              f"{summary['unique_responses_mean']:>8.1f}±{summary['unique_responses_std']:>5.1f}  "
              f"{summary['requests_mean']:>8.0f}")

    print(f"\n{'='*60}")
    print("HYPOTHESIS TESTS")
    print(f"{'='*60}")
    for name, test in report.get("hypothesis_tests", {}).items():
        sig = "SIGNIFICANT" if test["significant"] else "not sig."
        print(f"  {name}: p={test['p_value']:.4f} ({sig}), d={test.get('cohens_d', 0):.2f}")


async def main():
    parser = argparse.ArgumentParser(
        description="Automated Ablation Experiment Runner")
    parser.add_argument("--hours", type=float, default=0.5,
                        help="Hours per run (default: 0.5)")
    parser.add_argument("--runs", type=int, default=1,
                        help="Number of runs per config (default: 1)")
    parser.add_argument("--targets", type=str, default="oai,free5gc,open5gs",
                        help="Comma-separated targets (default: all)")
    parser.add_argument("--configs", type=str,
                        default="ours_full,ours_no_fsm,ours_no_cross_protocol,aflnet_like,random",
                        help="Comma-separated configs (default: all 5)")
    parser.add_argument("--output", type=str, default="./results/experiments",
                        help="Output directory")
    args = parser.parse_args()

    targets = [t.strip() for t in args.targets.split(",")]
    configs = [c.strip() for c in args.configs.split(",")]
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Validate targets
    for t in targets:
        if t not in TARGET_CONFIG:
            print(f"Unknown target: {t}. Valid: {list(TARGET_CONFIG.keys())}")
            return

    # Validate configs
    for c in configs:
        if c not in EXPERIMENT_MATRIX:
            print(f"Unknown config: {c}. Valid: {list(EXPERIMENT_MATRIX.keys())}")
            return

    results = await run_all_experiments(targets, configs, args.hours,
                                         args.runs, output_dir)

    report = generate_comparison_report(results, output_dir)
    print_comparison_table(report)


if __name__ == "__main__":
    asyncio.run(main())
