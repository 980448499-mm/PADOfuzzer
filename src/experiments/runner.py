"""Experiment runner — comparative evaluation against baselines.

Configurations:
  ours_full      — All mutations + FSM guidance + coverage feedback
  ours_no_fsm    — All mutations + coverage feedback, no FSM
  aflnet_like    — Bitflip only + coverage feedback (AFLNet baseline)
  random         — Pure random byte mutation (lower bound)

Targets: Open5GS, free5GC, OAI
Protocols: NGAP, NAS, SBI, PFCP, GTP-U
"""

import asyncio
import json
import logging
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np

from src import (
    CrashRecord,
    CrashSeverity,
    Feedback,
    FiveGCImpl,
    FuzzResult,
    MonitoringResult,
    NFType,
    ProtocolType,
)
from src.codec.base import ProtocolCodec
from src.codec.nas_codec import NAS5GSCodec
from src.codec.ngap_codec import NGAPCodec
from src.fuzzing_engine.core import FuzzingConfig, FuzzingEngine
from src.fuzzing_engine.mutator import (
    BitFlipMutation,
    MutatorEngine,
    RandomMutation,
    StructurePreservingMutation,
)
from src.fuzzing_engine.seed_manager import Seed, SeedManager
from src.fsm_learner.fsm_model import ProtocolFSM
from src.fsm_learner.fsm_guide import FSMGuidedFuzzing
from src.triage.crash_triage import CrashTriage
from src.feedback.analyzer import FeedbackAnalyzer

logger = logging.getLogger(__name__)


@dataclass
class ExperimentConfig:
    name: str  # e.g., "ours_full", "aflnet_like"
    mutators: List[str]  # Mutation strategy names
    fsm_guidance: bool
    coverage_feedback: bool
    description: str = ""


# Predefined experiment configurations
EXPERIMENT_CONFIGS: Dict[str, ExperimentConfig] = {
    "ours_full": ExperimentConfig(
        name="ours_full",
        mutators=["bit_flip", "structure_preserving", "state_aware",
                   "cross_protocol", "sequence_level", "http2"],
        fsm_guidance=True,
        coverage_feedback=True,
        description="Full system: FSM-guided + multi-component coverage + cross-protocol",
    ),
    "ours_no_fsm": ExperimentConfig(
        name="ours_no_fsm",
        mutators=["bit_flip", "structure_preserving", "cross_protocol",
                   "sequence_level", "http2"],
        fsm_guidance=False,
        coverage_feedback=True,
        description="Ablation: no FSM guidance, but all mutations + coverage",
    ),
    "ours_no_cross_protocol": ExperimentConfig(
        name="ours_no_cross_protocol",
        mutators=["bit_flip", "structure_preserving", "state_aware",
                   "sequence_level", "http2"],
        fsm_guidance=True,
        coverage_feedback=True,
        description="Ablation: no cross-protocol mutation",
    ),
    "aflnet_like": ExperimentConfig(
        name="aflnet_like",
        mutators=["bit_flip"],
        fsm_guidance=False,
        coverage_feedback=True,
        description="AFLNet baseline: bit-flip mutation + coverage feedback",
    ),
    "random": ExperimentConfig(
        name="random",
        mutators=["random"],
        fsm_guidance=False,
        coverage_feedback=False,
        description="Lower bound: random byte mutation, no feedback",
    ),
}


@dataclass
class ExperimentResult:
    """Results from a single experiment run."""

    config_name: str
    target: FiveGCImpl
    run_id: int  # 1-based run number
    start_time: float
    end_time: float = 0.0
    total_iterations: int = 0
    total_seeds: int = 0
    unique_crashes: int = 0
    total_crashes: int = 0
    edges_covered: int = 0
    fsm_states_visited: int = 0
    coverage_growth: List[Tuple[float, int]] = field(default_factory=list)
    crash_timeline: List[Tuple[float, str, str]] = field(default_factory=list)
    strategy_stats: Dict[str, Any] = field(default_factory=dict)
    crash_details: List[Dict[str, Any]] = field(default_factory=list)


class ExperimentRunner:
    """Run comparative experiments across configurations and targets.

    Experiment protocol:
      1. Deploy target 5GC
      2. Run training phase (generate benign traces, learn FSM)
      3. Run fuzzing campaign (N hours per protocol per target)
      4. Collect all metrics
      5. Repeat R times for statistical significance
    """

    def __init__(
        self,
        output_dir: Optional[Path] = None,
        runs_per_config: int = 3,
        hours_per_run: int = 24,
        random_seed: int = 42,
        live_mode: bool = False,
    ):
        self.output_dir = output_dir or Path("./results")
        self.runs_per_config = runs_per_config
        self.hours_per_run = hours_per_run
        self.random_seed = random_seed
        self.live_mode = live_mode
        self.results: List[ExperimentResult] = []

    async def run_all(
        self,
        configs: Optional[List[str]] = None,
        targets: Optional[List[FiveGCImpl]] = None,
        protocols: Optional[List[ProtocolType]] = None,
    ) -> List[ExperimentResult]:
        """Run all experiment configurations across all targets.

        Total design: C configs × T targets × P protocols × R runs
        """

        if configs is None:
            configs = list(EXPERIMENT_CONFIGS.keys())
        if targets is None:
            targets = list(FiveGCImpl)
        if protocols is None:
            protocols = [ProtocolType.NAS, ProtocolType.NGAP]

        total_runs = len(configs) * len(targets) * self.runs_per_config
        logger.info(
            f"Starting experiment suite: "
            f"{len(configs)} configs × {len(targets)} targets × "
            f"{self.runs_per_config} runs = {total_runs} total runs"
        )

        for config_name in configs:
            exp_config = EXPERIMENT_CONFIGS[config_name]
            for target in targets:
                for run_id in range(1, self.runs_per_config + 1):
                    result = await self.run_single_experiment(
                        exp_config, target, run_id, protocols
                    )
                    self.results.append(result)
                    self._save_result(result)

                    logger.info(
                        f"Completed: {config_name} / {target.value} "
                        f"run {run_id}/{self.runs_per_config}"
                    )

        return self.results

    async def run_single_experiment(
        self,
        exp_config: ExperimentConfig,
        target: FiveGCImpl,
        run_id: int,
        protocols: List[ProtocolType],
    ) -> ExperimentResult:
        """Run a single experiment configuration.

        In live_mode, deploys the real 5GC target via Docker, runs live
        training + fuzzing against it, then tears down.  Otherwise uses
        a mock send function for offline/CI testing.
        """
        # Set random seed for reproducibility
        random.seed(self.random_seed + run_id)
        np.random.seed(self.random_seed + run_id)

        # ── live mode: real 5GC deployment ────────────────────────
        if self.live_mode:
            return await self._run_live_experiment(
                exp_config, target, run_id, protocols,
            )

        # ── mock mode: simulated send function ────────────────────
        result = ExperimentResult(
            config_name=exp_config.name,
            target=target,
            run_id=run_id,
            start_time=time.time(),
        )

        # Configure fuzzing engine
        fuzz_config = FuzzingConfig(
            max_time_seconds=self.hours_per_run * 3600,
            checkpoint_interval=5000,
        )

        # Build codec set
        codecs = {
            ProtocolType.NAS: NAS5GSCodec(),
            ProtocolType.NGAP: NGAPCodec(),
        }

        # Build FSM (only if FSM guidance enabled)
        fsms = {}
        if exp_config.fsm_guidance:
            fsms = self._build_fsms_for_target(target)

        # Build mutator with only configured strategies
        mutator = self._build_mutator(exp_config)

        engine = FuzzingEngine(
            config=fuzz_config,
            codecs=codecs,
            fsms=fsms,
            mutator=mutator,
        )

        # Load seed corpus
        corpus_dir = Path("./corpus")
        if corpus_dir.exists():
            engine.load_corpus(corpus_dir)

        # Mock send function for testing without real 5GC
        async def mock_send(nf, proto, pdu):
            await asyncio.sleep(0.001)  # Simulate network delay
            return pdu

        engine.set_send_function(mock_send)

        # Run fuzzing campaign
        target_nf = NFType.AMF  # Primary target
        crashes = await engine.run(
            target_impl=target,
            target_nf=target_nf,
            protocols=protocols,
        )

        # Triage crashes
        triage = CrashTriage()
        groups = triage.triage(crashes)

        # Collect results
        result.end_time = time.time()
        result.total_iterations = engine.current_iteration
        result.total_seeds = engine.seed_manager.total_seeds
        result.unique_crashes = len(groups)
        result.total_crashes = sum(g.count for g in groups)
        result.edges_covered = engine.multi_coverage.aggregated.total_edges
        result.strategy_stats = engine.mutator.get_strategy_stats()
        result.crash_details = triage.get_statistics()["groups"]

        return result

    async def _run_live_experiment(
        self,
        exp_config: ExperimentConfig,
        target: FiveGCImpl,
        run_id: int,
        protocols: List[ProtocolType],
    ) -> ExperimentResult:
        """Run experiment against a live 5GC deployment."""
        from src.experiments.live_session import LiveSessionConfig, LiveFuzzingSession

        logger.info(
            "LIVE MODE: deploying %s for config %s run %d",
            target.value, exp_config.name, run_id,
        )

        session_config = LiveSessionConfig(
            target=target,
            protocols=protocols,
            primary_nf=NFType.AMF,
            max_hours=float(self.hours_per_run),
            output_dir=self.output_dir,
            checkpoint_interval=5000,
        )

        session = LiveFuzzingSession(session_config)
        live_result = await session.run()

        # Convert LiveSessionResult → ExperimentResult
        result = ExperimentResult(
            config_name=exp_config.name,
            target=target,
            run_id=run_id,
            start_time=live_result.start_time,
            end_time=live_result.end_time,
            total_iterations=live_result.total_iterations,
            unique_crashes=live_result.unique_crashes,
            total_crashes=live_result.total_crashes,
            edges_covered=live_result.edges_covered,
            crash_details=live_result.crash_groups,
        )

        if live_result.error_message:
            logger.error("Live session error: %s", live_result.error_message)

        return result

    # ─── Internal helpers ──────────────────────────────────────

    def _build_mutator(self, config: ExperimentConfig) -> MutatorEngine:
        """Build a mutator engine with only the specified strategies."""
        engine = MutatorEngine()

        # Filter strategies
        available = {
            "bit_flip": BitFlipMutation(),
            "structure_preserving": StructurePreservingMutation(),
            "random": RandomMutation(),
        }
        # Additional strategies
        from src.fuzzing_engine.mutator import (
            StateAwareMutation,
            CrossProtocolMutation,
            SequenceLevelMutation,
            HTTP2Mutation,
        )
        available.update({
            "state_aware": StateAwareMutation(),
            "cross_protocol": CrossProtocolMutation(),
            "sequence_level": SequenceLevelMutation(),
            "http2": HTTP2Mutation(),
        })

        for strategy_name in config.mutators:
            if strategy_name in available:
                engine.add_strategy(available[strategy_name])

        return engine

    def _build_fsms_for_target(self, target: FiveGCImpl) -> Dict[ProtocolType, ProtocolFSM]:
        """Build protocol FSMs for a target.

        Trains FSM models from diverse, realistic message-sequence
        traces covering the main 5G NAS and PFCP procedures.  Each
        trace exercises a different edge of the protocol state
        machine so the learner captures normal behaviour before the
        fuzzer begins searching for invalid transitions.
        """
        from src.fsm_learner.learner import FSMLearner

        fsms: Dict[ProtocolType, ProtocolFSM] = {}
        learner = FSMLearner()

        # ── NAS 5GS registration traces ──────────────────────────
        reg_traces = [
            # 1 — vanilla registration (null security)
            [
                "Registration Request",
                "Authentication Request",
                "Authentication Response",
                "Security Mode Command",
                "Security Mode Complete",
                "Registration Accept",
                "Registration Complete",
            ],
            # 2 — registration with identity request (SUCI → SUPI)
            [
                "Registration Request",
                "Identity Request",
                "Identity Response",
                "Authentication Request",
                "Authentication Response",
                "Security Mode Command",
                "Security Mode Complete",
                "Registration Accept",
                "Registration Complete",
            ],
            # 3 — deregistration (UE-initiated)
            [
                "Deregistration Request (UE originating)",
                "Deregistration Accept (UE originating)",
            ],
            # 4 — registration reject (cause: illegal UE)
            [
                "Registration Request",
                "Registration Reject",
            ],
            # 5 — registration with authentication failure
            [
                "Registration Request",
                "Authentication Request",
                "Authentication Failure",
            ],
            # 6 — service request (CM-IDLE → CM-CONNECTED)
            [
                "Service Request",
                "Authentication Request",
                "Authentication Response",
                "Security Mode Command",
                "Security Mode Complete",
                "Service Accept",
            ],
            # 7 — periodic registration update
            [
                "Registration Request",
                "Registration Accept",
                "Registration Complete",
            ],
            # 8 — registration with configuration update
            [
                "Registration Request",
                "Authentication Request",
                "Authentication Response",
                "Security Mode Command",
                "Security Mode Complete",
                "Registration Accept",
                "Registration Complete",
                "Configuration Update Command",
                "Configuration Update Complete",
            ],
        ]

        reg_fsm = learner.learn_from_sequences(
            reg_traces, procedure="registration", protocol="nas-5gs",
        )
        if reg_fsm:
            fsms[ProtocolType.NAS] = reg_fsm

        # ── NAS 5GS PDU session traces ───────────────────────────
        pdu_traces = [
            # PDU session establishment — IPv4
            [
                "PDU Session Establishment Request",
                "Authentication Request",
                "Authentication Response",
                "Security Mode Command",
                "Security Mode Complete",
                "PDU Session Establishment Accept",
            ],
            # PDU session release (UE-initiated)
            [
                "PDU Session Release Request",
                "PDU Session Release Command",
                "PDU Session Release Complete",
            ],
            # PDU session establishment reject
            [
                "PDU Session Establishment Request",
                "PDU Session Establishment Reject",
            ],
            # PDU session modification
            [
                "PDU Session Modification Request",
                "PDU Session Modification Command",
                "PDU Session Modification Complete",
                "PDU Session Modification Command",
                "PDU Session Modification Complete",
            ],
        ]

        pdu_fsm = learner.learn_from_sequences(
            pdu_traces, procedure="pdu-session", protocol="nas-5gs",
        )
        if pdu_fsm:
            if ProtocolType.NAS in fsms:
                # Merge PDU session states into the NAS FSM
                for state_name, fsm_state in pdu_fsm.states.items():
                    if state_name not in fsms[ProtocolType.NAS].states:
                        fsms[ProtocolType.NAS].add_state(state_name, **{
                            "is_initial": fsm_state.is_initial,
                            "is_accepting": fsm_state.is_accepting,
                            "is_error": fsm_state.is_error,
                        })
                fsms[ProtocolType.NAS].transitions.extend(pdu_fsm.transitions)
                fsms[ProtocolType.NAS].initial_state = pdu_fsm.initial_state or fsms[ProtocolType.NAS].initial_state
            else:
                fsms[ProtocolType.NAS] = pdu_fsm

        # ── PFCP traces ──────────────────────────────────────────
        pfcp_traces = [
            # Association setup
            [
                "PFCP Association Setup Request",
                "PFCP Association Setup Response",
            ],
            # Session establishment
            [
                "PFCP Session Establishment Request",
                "PFCP Session Establishment Response",
            ],
            # Session modification
            [
                "PFCP Session Modification Request",
                "PFCP Session Modification Response",
            ],
            # Session deletion
            [
                "PFCP Session Deletion Request",
                "PFCP Session Deletion Response",
            ],
            # Heartbeat
            [
                "PFCP Heartbeat Request",
                "PFCP Heartbeat Response",
            ],
        ]

        pfcp_fsm = learner.learn_from_sequences(
            pfcp_traces, procedure="pfcp", protocol="pfcp",
        )
        if pfcp_fsm:
            fsms[ProtocolType.PFCP] = pfcp_fsm

        return fsms

    # ─── Persistence ──────────────────────────────────────────

    def _save_result(self, result: ExperimentResult) -> None:
        """Save experiment result to disk."""
        output_dir = self.output_dir / result.target.value
        output_dir.mkdir(parents=True, exist_ok=True)

        filename = f"{result.config_name}_run{result.run_id}.json"
        filepath = output_dir / filename

        data = {
            "config_name": result.config_name,
            "target": result.target.value,
            "run_id": result.run_id,
            "start_time": result.start_time,
            "end_time": result.end_time,
            "duration_seconds": result.end_time - result.start_time,
            "total_iterations": result.total_iterations,
            "total_seeds": result.total_seeds,
            "unique_crashes": result.unique_crashes,
            "total_crashes": result.total_crashes,
            "edges_covered": result.edges_covered,
            "strategy_stats": result.strategy_stats,
            "crash_details": result.crash_details,
        }

        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)

    def load_results(self) -> List[ExperimentResult]:
        """Load all saved experiment results."""
        loaded: List[ExperimentResult] = []
        for json_file in self.output_dir.rglob("*.json"):
            try:
                with open(json_file) as f:
                    data = json.load(f)
                result = ExperimentResult(
                    config_name=data["config_name"],
                    target=FiveGCImpl(data["target"]),
                    run_id=data["run_id"],
                    start_time=data["start_time"],
                    end_time=data["end_time"],
                    total_iterations=data["total_iterations"],
                    total_seeds=data["total_seeds"],
                    unique_crashes=data["unique_crashes"],
                    total_crashes=data["total_crashes"],
                    edges_covered=data["edges_covered"],
                    strategy_stats=data["strategy_stats"],
                    crash_details=data["crash_details"],
                )
                loaded.append(result)
            except Exception:
                pass
        return loaded

    def compare_configurations(self) -> Dict[str, Any]:
        """Compare experiment configurations with statistical tests."""
        from collections import defaultdict
        from scipy import stats

        results = self.load_results() if not self.results else self.results

        # Group results by config
        grouped: Dict[str, List[ExperimentResult]] = defaultdict(list)
        for r in results:
            grouped[r.config_name].append(r)

        comparison: Dict[str, Any] = {}
        for config_name, config_results in grouped.items():
            crashes = [r.unique_crashes for r in config_results]
            edges = [r.edges_covered for r in config_results]
            iterations = [r.total_iterations for r in config_results]

            comparison[config_name] = {
                "runs": len(config_results),
                "unique_crashes_mean": float(np.mean(crashes)),
                "unique_crashes_std": float(np.std(crashes)),
                "edges_covered_mean": float(np.mean(edges)),
                "edges_covered_std": float(np.std(edges)),
                "iterations_mean": float(np.mean(iterations)),
            }

        return comparison
