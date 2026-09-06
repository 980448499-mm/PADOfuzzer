#!/usr/bin/env python3
"""End-to-end: deploy 5GC, run fuzzing campaign, collect results.

Workflow:
  1. Build/pull 5GC Docker images
  2. Deploy target 5GC (docker-compose up)
  3. Wait for health check
  4. Run benign scenarios → learn FSMs
  5. Run fuzzing campaign (configurable hours)
  6. Triage crashes, generate report
  7. Tear down 5GC

Usage:
  # Deploy Open5GS, run 1-hour fuzzing campaign
  python scripts/deploy_and_fuzz.py --target open5gs --hours 1

  # Just deploy and health-check (no fuzzing)
  python scripts/deploy_and_fuzz.py --target open5gs --deploy-only

  # Use mock 5GC (no Docker needed, for development)
  python scripts/deploy_and_fuzz.py --mock

  # Run full experiment suite (all configs, 24h each)
  python scripts/deploy_and_fuzz.py --target open5gs --full-suite
"""

import argparse
import asyncio
import json
import logging
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import FiveGCImpl, ProtocolType
from src.deployment.orchestrator import DeploymentManager
from src.experiments.runner import (
    ExperimentRunner, ExperimentConfig, ExperimentResult,
    EXPERIMENT_CONFIGS,
)
from src.experiments.analysis import ResultAnalyzer
from src.fsm_learner.training import FSMTrainer, TrainingConfig
from src.stimulus.scenarios.registration import make_registration_scenario
from src.stimulus.scenarios.pdu_session import make_pdu_session_scenario

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("deploy_and_fuzz")


@dataclass
class CampaignResults:
    target: str
    deployment_ok: bool
    training_ok: bool
    fuzzing_results: list
    total_crashes: int
    total_unique_crashes: int
    report: dict


async def deploy_5gc(deploy_mgr: DeploymentManager, target: FiveGCImpl) -> bool:
    """Deploy the 5GC and wait for health check."""
    logger.info(f"Deploying {target.value} 5GC...")
    deployment = await deploy_mgr.deploy(impl_type=target)
    if not deployment or deployment.status.value != "healthy":
        logger.error("Deployment failed")
        return False

    logger.info(f"Deployed {len(deployment.endpoints)} NFs")
    for ep in deployment.endpoints:
        logger.info(f"  {ep.nf_type}: {ep.ip_address}:{ep.sbi_port}")

    logger.info("Health check passed")
    return True


async def train_fsms() -> bool:
    """Learn FSM models from benign scenarios."""
    logger.info("Training FSM models...")
    trainer = FSMTrainer()
    scenarios = [
        make_registration_scenario(n_runs=10),
        make_pdu_session_scenario(n_runs=10),
    ]
    fsms = trainer.run_training_pipeline(scenarios=scenarios)
    logger.info(f"Trained {len(fsms)} FSM models")
    return True


async def run_fuzzing_campaign(
    target: FiveGCImpl,
    hours: int,
    configs: Optional[list] = None,
    mock: bool = False,
) -> CampaignResults:
    """Run the fuzzing campaign."""
    if configs is None:
        configs = ["ours_full", "aflnet_like", "random"]

    runner = ExperimentRunner(
        output_dir=Path("./results"),
        runs_per_config=1,
        hours_per_run=hours,
    )

    logger.info(f"Fuzzing: {len(configs)} configs, {hours}h each, target={target.value}")

    if mock:
        # Use mock send function
        from src.fuzzing_engine.core import FuzzingEngine

        # Override to use mock transport
        logger.info("Using mock 5GC (no real containers)")
        results = await runner.run_all(
            configs=configs,
            targets=[target],
            protocols=[ProtocolType.NAS, ProtocolType.NGAP],
        )
    else:
        results = await runner.run_all(
            configs=configs,
            targets=[target],
            protocols=[ProtocolType.NAS, ProtocolType.NGAP, ProtocolType.PFCP],
        )

    # Analyze
    analyzer = ResultAnalyzer(results=results)
    report = analyzer.generate_report()

    return CampaignResults(
        target=target.value,
        deployment_ok=not mock,
        training_ok=not mock,
        fuzzing_results=[{
            "config": r.config_name,
            "iterations": r.total_iterations,
            "unique_crashes": r.unique_crashes,
            "edges_covered": r.edges_covered,
        } for r in results],
        total_crashes=report["overview"]["total_crashes_found"],
        total_unique_crashes=report["overview"]["total_unique_crashes"],
        report=report,
    )


async def main():
    parser = argparse.ArgumentParser(
        description="5G Fuzzing: Deploy + Fuzz + Analyze"
    )
    parser.add_argument("--target", choices=[t.value for t in FiveGCImpl],
                       default="open5gs", help="Target 5GC implementation")
    parser.add_argument("--hours", type=float, default=1,
                       help="Hours per fuzzing run (decimal OK, e.g. 0.01)")
    parser.add_argument("--deploy-only", action="store_true",
                       help="Only deploy and health-check")
    parser.add_argument("--mock", action="store_true",
                       help="Use mock 5GC (no Docker)")
    parser.add_argument("--full-suite", action="store_true",
                       help="Run all 5 configs (long)")
    parser.add_argument("--output", type=str, default="./results",
                       help="Results output directory")
    args = parser.parse_args()

    target = FiveGCImpl(args.target)

    print("\n" + "=" * 60)
    print("5G FUZZING CAMPAIGN")
    print("=" * 60)
    print(f"Target: {target.value}")
    print(f"Mock mode: {args.mock}")
    print(f"Hours per run: {args.hours}")
    print(f"Full suite: {args.full_suite}")
    print("=" * 60 + "\n")

    if args.mock:
        # Mock mode: run fuzzing without Docker
        configs = list(EXPERIMENT_CONFIGS.keys()) if args.full_suite else ["ours_full", "aflnet_like"]
        results = await run_fuzzing_campaign(target, args.hours, configs, mock=True)

        print("\n" + "=" * 60)
        print("RESULTS (Mock Mode)")
        print("=" * 60)
        print(f"Total iterations: {results.fuzzing_results}")
        print(f"Total crashes: {results.total_crashes}")
        print(f"Unique crashes: {results.total_unique_crashes}")

        # Save results
        output_dir = Path(args.output)
        output_dir.mkdir(parents=True, exist_ok=True)
        with open(output_dir / "campaign_results.json", "w") as f:
            json.dump(results.report, f, indent=2, default=str)
        logger.info(f"Results saved to {output_dir}/campaign_results.json")

        return

    # Real mode: deploy 5GC, then fuzz
    deploy_dir = Path(__file__).resolve().parent.parent / "src" / "deployment"
    deploy_mgr = DeploymentManager(compose_dir=deploy_dir)

    deployment = None
    try:
        # Step 1: Deploy
        logger.info("=== STEP 1: Deploy 5GC ===")
        deployment = await deploy_mgr.deploy(impl_type=target)
        if not deployment or deployment.status.value != "healthy":
            logger.error("Deployment failed, aborting")
            return
        logger.info(f"Deployed {len(deployment.endpoints)} NFs")

        if args.deploy_only:
            logger.info("Deploy-only mode. 5GC is running.")
            print(f"\nTo tear down: docker compose -f src/deployment/{args.target}/docker-compose.yml -p fuzzing-{args.target} down -v --remove-orphans")
            deployment = None  # Prevent teardown in finally block
            return

        # Step 2: Train FSMs
        logger.info("=== STEP 2: Train FSM models ===")
        await train_fsms()

        # Step 3: Run fuzzing
        logger.info("=== STEP 3: Fuzzing campaign ===")
        configs = list(EXPERIMENT_CONFIGS.keys()) if args.full_suite else ["ours_full", "aflnet_like"]
        results = await run_fuzzing_campaign(target, args.hours, configs, mock=False)

        # Step 4: Display results
        print("\n" + "=" * 60)
        print("CAMPAIGN RESULTS")
        print("=" * 60)
        for r in results.fuzzing_results:
            print(f"  {r['config']}: {r['iterations']} iters, "
                  f"{r['unique_crashes']} unique crashes, "
                  f"{r['edges_covered']} edges")
        print(f"\nTotal crashes: {results.total_crashes}")
        print(f"Unique crashes: {results.total_unique_crashes}")

        # Hypothesis tests
        print("\nHypothesis Tests:")
        for h_name, h_result in results.report["hypothesis_tests"].items():
            if h_result.get("status") == "insufficient_data":
                print(f"  {h_name}: INSUFFICIENT DATA (need more runs)")
            else:
                sig = "SIGNIFICANT" if h_result.get("significant") else "not sig."
                print(f"  {h_name}: {sig} p={h_result.get('p_value', 'N/A'):.4f}")

        # Save results
        output_dir = Path(args.output)
        output_dir.mkdir(parents=True, exist_ok=True)
        with open(output_dir / "campaign_results.json", "w") as f:
            json.dump(results.report, f, indent=2, default=str)

    finally:
        # Step 5: Tear down
        logger.info("=== TEARDOWN ===")
        if deployment:
            await deploy_mgr.destroy(deployment)
        logger.info("5GC torn down")


if __name__ == "__main__":
    asyncio.run(main())
