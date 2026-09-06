"""Core fuzzing engine with state machine guidance and coverage feedback.

Main fuzz loop:
  1. Select seed from corpus (energy scheduling)
  2. Determine current protocol state (from FSM tracker)
  3. Select mutation strategy based on state and coverage
  4. Apply mutations to generate test case
  5. Encode via protocol codec
  6. Send to appropriate 5GC NF
  7. Monitor for crashes, errors, coverage changes
  8. Process feedback
  9. Update seed queue with new coverage info
"""

import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import UUID, uuid4

from src import (
    CrashRecord,
    CrashSeverity,
    Feedback,
    FiveGCImpl,
    FuzzResult,
    MonitoringResult,
    MutationCategory,
    NFType,
    ProtocolType,
)
from src.codec.base import ParsedMessage, ProtocolCodec
from src.codec.nas_codec import NAS5GSCodec
from src.codec.ngap_codec import NGAPCodec
from src.fuzzing_engine.coverage.bitmap import CoverageBitmap, MultiComponentCoverage
from src.fuzzing_engine.power_scheduler import SeedEnergy
from src.fuzzing_engine.seed_manager import Seed, SeedManager
from src.fuzzing_engine.mutator import MutatorEngine
from src.fsm_learner.fsm_model import ProtocolFSM
from src.fsm_learner.fsm_guide import FSMGuidedFuzzing, AttackPlan
from src.monitor.component_monitor import ComponentMonitor

logger = logging.getLogger(__name__)


@dataclass
class FuzzingConfig:
    max_iterations: int = 1000000
    max_time_seconds: int = 86400  # 24 hours
    checkpoint_interval: int = 1000
    save_crashes: bool = True
    min_seed_energy: float = 0.1
    exploration_prob: float = 0.05
    timeout_per_iteration: float = 5.0  # seconds


class FuzzingEngine:
    """Core fuzzing loop orchestrating seeds, mutations, codec, injection, and feedback."""

    def __init__(
        self,
        config: Optional[FuzzingConfig] = None,
        codecs: Optional[Dict[ProtocolType, ProtocolCodec]] = None,
        fsms: Optional[Dict[ProtocolType, ProtocolFSM]] = None,
        mutator: Optional[MutatorEngine] = None,
        monitor: Optional[Any] = None,  # ComponentMonitor when deployed
    ):
        self.config = config or FuzzingConfig()
        self.codecs = codecs or self._default_codecs()
        self.fsms = fsms or {}
        self.mutator = mutator or MutatorEngine()
        self.seed_manager = SeedManager()
        self.multi_coverage = MultiComponentCoverage()
        self.crash_registry: Dict[str, List[CrashRecord]] = {}
        self.current_iteration = 0
        self.start_time = time.time()
        self._stop_flag = False
        self._send_fn: Optional[callable] = None  # Injected by caller
        self._monitor = monitor  # ComponentMonitor (optional)

    @staticmethod
    def _default_codecs() -> Dict[ProtocolType, ProtocolCodec]:
        return {
            ProtocolType.NAS: NAS5GSCodec(),
            ProtocolType.NGAP: NGAPCodec(),
        }

    # ─── Public API ───────────────────────────────────────────

    def set_send_function(self, send_fn: callable) -> None:
        """Inject the function used to send fuzzed PDUs to the target."""
        self._send_fn = send_fn

    def load_corpus(self, corpus_dir: Path) -> int:
        """Load seed corpus from directory."""
        count = 0
        for proto_dir in corpus_dir.iterdir():
            if proto_dir.is_dir():
                try:
                    proto = ProtocolType(proto_dir.name)
                except ValueError:
                    continue
                for seed_file in proto_dir.iterdir():
                    try:
                        raw = seed_file.read_bytes()
                        seed = Seed(
                            protocol=proto,
                            raw_pdu=raw,
                            generation=0,
                        )
                        if self.seed_manager.add_seed(seed):
                            count += 1
                    except Exception:
                        pass
        logger.info(f"Loaded {count} seeds from {corpus_dir}")
        return count

    def stop(self) -> None:
        self._stop_flag = True

    def should_stop(self) -> bool:
        if self._stop_flag:
            return True
        if self.current_iteration >= self.config.max_iterations:
            return True
        if (time.time() - self.start_time) > self.config.max_time_seconds:
            return True
        return False

    # ─── Main fuzz loop ───────────────────────────────────────

    async def run(
        self,
        target_impl: FiveGCImpl,
        target_nf: NFType,
        protocols: Optional[List[ProtocolType]] = None,
    ) -> List[FuzzResult]:
        """Run the main fuzzing campaign.

        Args:
            target_impl: 5GC implementation under test
            target_nf: Network Function under test
            protocols: Protocols to fuzz (default: all available)

        Returns:
            List of unique crash results
        """
        if protocols is None:
            protocols = list(self.codecs.keys())

        crash_results: List[FuzzResult] = []
        self.start_time = time.time()

        logger.info(
            f"Starting fuzzing campaign: target={target_impl.value} "
            f"nf={target_nf.value} protocols={[p.value for p in protocols]}"
        )

        while not self.should_stop():
            for protocol in protocols:
                if self.should_stop():
                    break
                try:
                    result = await self._fuzz_iteration(
                        target_impl, target_nf, protocol
                    )
                    if result.crash:
                        crash_results.append(result)
                        self._record_crash(result.crash)

                    self.current_iteration += 1

                    if self.current_iteration % self.config.checkpoint_interval == 0:
                        self._checkpoint()

                except Exception as e:
                    logger.error(f"Fuzz iteration error: {e}")

        logger.info(
            f"Fuzzing complete: {self.current_iteration} iterations, "
            f"{len(crash_results)} crashes in "
            f"{time.time() - self.start_time:.1f}s"
        )
        return crash_results

    async def _fuzz_iteration(
        self,
        target_impl: FiveGCImpl,
        target_nf: NFType,
        protocol: ProtocolType,
    ) -> FuzzResult:
        """Execute a single fuzzing iteration."""
        iteration_id = uuid4()

        # 1. Select seed
        seed = self.seed_manager.select_next()
        if seed is None:
            return FuzzResult(iteration_id=iteration_id)

        # 2. Determine FSM state and build attack plan
        fsm_guide = None
        attack_plan = None
        target_state = "unknown"

        if protocol in self.fsms:
            fsm_guide = FSMGuidedFuzzing(self.fsms[protocol])
            target_state = fsm_guide.select_target_state()
            attack_plan = fsm_guide.build_attack_plan(target_state)

        # 3. Select and apply mutation strategy
        strategy, fuzzed_pdu = self.mutator.mutate(
            seed=seed,
            protocol=protocol,
            codec=self.codecs.get(protocol),
            current_state=target_state,
            coverage_stagnation=self._check_coverage_stagnation(),
        )

        # 4. Send fuzzed PDU to target
        messages_sent = [fuzzed_pdu]
        crash = None
        monitoring = None

        if self._send_fn:
            try:
                raw_response = await asyncio.wait_for(
                    self._send_fn(target_nf, protocol, fuzzed_pdu),
                    timeout=self.config.timeout_per_iteration,
                )
                monitoring = await self._collect_monitoring(target_impl, target_nf, raw_response)
                crash = self._detect_crash(monitoring, seed, fuzzed_pdu)
            except asyncio.TimeoutError:
                crash = CrashRecord(
                    target_impl=target_impl,
                    target_nf=target_nf,
                    protocol=protocol,
                    seed_id=seed.id,
                    input_pdu=fuzzed_pdu,
                    crash_signal="timeout",
                    severity=CrashSeverity.LOW,
                )

        # 5. Process feedback
        feedback = Feedback(
            mutation_strategy=strategy.__class__.__name__ if strategy else "unknown",
            timestamp=time.time(),
        )
        if monitoring and monitoring.new_edges:
            feedback.coverage_novelty = len(monitoring.new_edges) / 100.0
            feedback.new_edges_count = len(monitoring.new_edges)
            feedback.state_reached = monitoring.nf_states.get(target_nf.value, "unknown")
            feedback.crash = crash

        self._apply_feedback(seed, feedback, monitoring)

        return FuzzResult(
            iteration_id=iteration_id,
            target_impl=target_impl,
            target_nf=target_nf,
            protocol=protocol,
            seed_id=seed.id,
            strategy_name=strategy.__class__.__name__ if strategy else "unknown",
            messages_sent=[],
            monitoring=monitoring,
            crash=crash,
        )

    # ─── Monitoring and crash detection ───────────────────────

    async def _collect_monitoring(
        self,
        target_impl: FiveGCImpl,
        target_nf: NFType,
        raw_response: Any,
    ) -> MonitoringResult:
        """Collect monitoring data after a fuzz iteration.

        When a ComponentMonitor is attached (real deployment), pulls
        live container logs, NF health state, and coverage edges.
        Otherwise falls back to a minimal response record so the
        fuzzer can still operate in mock/offline mode.
        """
        from src import LogEntry

        logs: List[LogEntry] = []
        new_edges: Set[int] = set()
        nf_states: Dict[str, str] = {}

        if self._monitor is not None:
            try:
                # Harvest recent logs via LogHarvester
                harvester = getattr(self._monitor, "log_harvester", None)
                if harvester is not None:
                    harvested = await asyncio.wait_for(
                        harvester.collect(tail_lines=50),
                        timeout=3.0,
                    )
                    if harvested:
                        logs.extend(harvested)

                # Detect crashes + collect per-NF state
                detector = getattr(self._monitor, "crash_detector", None)
                if detector is not None:
                    crashes = detector.detect(logs)
                    # Also check container health
                    health_crashes = detector.detect_from_container_health()
                    for crash in crashes + health_crashes:
                        self._record_crash(crash)
                nf_states = ComponentMonitor._infer_nf_states(logs)

                # Collect coverage edges
                coverage_collector = getattr(
                    self._monitor, "coverage_collector", None,
                )
                if coverage_collector is not None:
                    cov_bitmap = await asyncio.wait_for(
                        coverage_collector.collect(),
                        timeout=10.0,
                    )
                    if cov_bitmap is not None and cov_bitmap.total_edges > 0:
                        new_edges = self.multi_coverage.get_overall_new_edges(
                            cov_bitmap,
                        )
                        self.multi_coverage.add_nf_coverage(
                            target_nf.value, cov_bitmap,
                        )
            except asyncio.TimeoutError:
                logger.debug("Monitoring collection timed out")
            except Exception as exc:
                logger.debug("Monitoring collection error: %s", exc)

        # Always include at least one record so callers don't choke
        if not logs:
            logs.append(LogEntry(
                timestamp=time.time(),
                nf_type=target_nf,
                level="INFO",
                message="Fuzz iteration response",
            ))
        if not nf_states:
            nf_states[target_nf.value] = "unknown"

        return MonitoringResult(
            logs=logs,
            new_edges=new_edges,
            nf_states=nf_states,
        )

    def _detect_crash(
        self,
        monitoring: Optional[MonitoringResult],
        seed: Seed,
        fuzzed_pdu: bytes,
    ) -> Optional[CrashRecord]:
        """Detect crashes from monitoring data."""
        if monitoring is None:
            return None

        crash_signals = {
            "SIGSEGV": CrashSeverity.CRITICAL,
            "SIGABRT": CrashSeverity.CRITICAL,
            "SIGBUS": CrashSeverity.HIGH,
            "SIGFPE": CrashSeverity.HIGH,
            "Assertion failed": CrashSeverity.MEDIUM,
            "ERROR": CrashSeverity.LOW,
        }

        for log_entry in monitoring.logs:
            for signal, severity in crash_signals.items():
                if signal.lower() in log_entry.message.lower():
                    return CrashRecord(
                        target_impl=None,
                        target_nf=log_entry.nf_type,
                        protocol=seed.protocol,
                        seed_id=seed.id,
                        input_pdu=fuzzed_pdu,
                        crash_signal=signal,
                        severity=severity,
                    )

        return None

    def _record_crash(self, crash: CrashRecord) -> None:
        """Register a crash for deduplication and reporting."""
        key = f"{crash.target_nf}_{crash.crash_signal}"
        if key not in self.crash_registry:
            self.crash_registry[key] = []
        self.crash_registry[key].append(crash)

    # ─── Feedback processing ──────────────────────────────────

    def _apply_feedback(
        self,
        seed: Seed,
        feedback: Feedback,
        monitoring: Optional[MonitoringResult],
    ) -> None:
        """Apply feedback to update seed energy and coverage tracking."""
        new_edges = monitoring.new_edges if monitoring else set()
        state = feedback.state_reached or "unknown"
        crashed = feedback.crash is not None

        self.seed_manager.update_energy(seed, new_edges, state, crashed)

    def _check_coverage_stagnation(self) -> bool:
        """Check if coverage has stagnated (no new edges in last N iterations)."""
        # Simplified: return False unless all NFs have very few new edges
        return bool(self.multi_coverage.get_stagnant_nfs())

    # ─── Checkpoint ──────────────────────────────────────────

    def _checkpoint(self) -> None:
        """Save fuzzing state for resumption."""
        elapsed = time.time() - self.start_time
        throughput = self.current_iteration / max(elapsed, 1)
        logger.info(
            f"Checkpoint: {self.current_iteration} iters, "
            f"{len(self.crash_registry)} unique crashes, "
            f"{throughput:.1f} iter/s, "
            f"{elapsed:.0f}s elapsed"
        )

    # ─── Statistics ──────────────────────────────────────────

    @property
    def stats(self) -> Dict[str, Any]:
        elapsed = max(time.time() - self.start_time, 0.01)
        return {
            "total_iterations": self.current_iteration,
            "total_seeds": self.seed_manager.total_seeds,
            "unique_crashes": len(self.crash_registry),
            "elapsed_seconds": elapsed,
            "iterations_per_second": self.current_iteration / elapsed,
            "edges_covered": self.multi_coverage.aggregated.total_edges,
        }
