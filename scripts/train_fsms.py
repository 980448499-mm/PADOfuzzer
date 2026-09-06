#!/usr/bin/env python3
"""Train FSM models from benign scenarios and save to disk.

Usage:
  python scripts/train_fsms.py --output models/
  python scripts/train_fsms.py --target open5gs --output models/
"""

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import FiveGCImpl
from src.fsm_learner.training import FSMTrainer, TrainingConfig
from src.stimulus.scenarios.registration import make_registration_scenario
from src.stimulus.scenarios.pdu_session import (
    make_pdu_session_scenario,
    make_pfcp_session_scenario,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("train")


def main():
    parser = argparse.ArgumentParser(description="5G FSM Training")
    parser.add_argument("--target", choices=[t.value for t in FiveGCImpl],
                       default="open5gs", help="Target 5GC implementation")
    parser.add_argument("--output", type=str, default="./models",
                       help="Output directory for FSM models")
    parser.add_argument("--min-traces", type=int, default=20,
                       help="Minimum traces per procedure")
    args = parser.parse_args()

    target = FiveGCImpl(args.target)
    config = TrainingConfig(
        target=target,
        min_traces_per_procedure=args.min_traces,
        output_dir=Path(args.output),
    )

    trainer = FSMTrainer(config=config)

    scenarios = [
        make_registration_scenario(n_runs=args.min_traces),
        make_pdu_session_scenario(n_runs=args.min_traces),
        make_pfcp_session_scenario(n_runs=args.min_traces),
    ]

    logger.info(f"Training FSMs for target: {target.value}")
    logger.info(f"Scenarios: {len(scenarios)}")

    fsms = trainer.run_training_pipeline(scenarios=scenarios)

    for target_name, proc_fsms in fsms.items():
        logger.info(f"Target: {target_name}")
        for proc, fsm in proc_fsms.items():
            logger.info(f"  {proc}: {len(fsm.states)} states, "
                       f"{sum(len(s.outgoing) for s in fsm.states.values())} transitions")

    # Print Mermaid diagrams for review
    for target_name, proc_fsms in fsms.items():
        for proc, fsm in proc_fsms.items():
            print(f"\n{'='*60}")
            print(f"FSM: {target_name}/{proc}")
            print(f"{'='*60}")
            print(fsm.to_mermaid())


if __name__ == "__main__":
    main()
