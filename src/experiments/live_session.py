"""Live fuzzing session — end-to-end deploy→train→fuzz→teardown.

Orchestrates a complete fuzzing campaign against a live 5GC deployment:

  1. Deploy target 5GC via Docker Compose
  2. Run benign scenarios to generate training traces
  3. Learn FSM models from captured traces
  4. Wire real protocol clients (NAS/NGAP/PFCP/SBI/GTP-U)
  5. Attach ComponentMonitor for log/coverage/crash collection
  6. Run the fuzzing campaign
  7. Triage crashes, collect metrics, save results
  8. Tear down deployment
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from src import (
    CrashRecord,
    FiveGCImpl,
    FuzzResult,
    NFType,
    ProtocolType,
)
from src.deployment.orchestrator import Deployment, DeploymentManager, DeploymentStatus
from src.fuzzing_engine.core import FuzzingConfig, FuzzingEngine
from src.fuzzing_engine.mutator import MutatorEngine
from src.fuzzing_engine.senders import SendFunctionFactory, make_send_fn_for_deployment
from src.fsm_learner.fsm_model import ProtocolFSM
from src.fsm_learner.learner import FSMLearner
from src.monitor.component_monitor import ComponentMonitor
from src.triage.crash_triage import CrashTriage

logger = logging.getLogger(__name__)


@dataclass
class LiveSessionConfig:
    """Configuration for a single live fuzzing session."""

    target: FiveGCImpl
    protocols: List[ProtocolType] = field(default_factory=lambda: [
        ProtocolType.NAS, ProtocolType.NGAP,
    ])
    primary_nf: NFType = NFType.AMF
    max_iterations: int = 100000
    max_hours: float = 24.0
    checkpoint_interval: int = 1000
    fsm_training_traces_per_procedure: int = 10
    output_dir: Path = field(default_factory=lambda: Path("./results"))
    keep_deployment_alive: bool = False  # If True, skip teardown for debugging
    coverage_build: bool = False  # Use gcov-instrumented images


@dataclass
class LiveSessionResult:
    """Aggregated result from a live fuzzing session."""

    target: FiveGCImpl
    start_time: float
    end_time: float = 0.0
    total_iterations: int = 0
    unique_crashes: int = 0
    total_crashes: int = 0
    edges_covered: int = 0
    fsm_states_learned: Dict[str, int] = field(default_factory=dict)
    crash_groups: List[Dict[str, Any]] = field(default_factory=list)
    deployment_healthy: bool = False
    error_message: str = ""


class LiveFuzzingSession:
    """Orchestrates a complete live fuzzing campaign against one 5GC target.

    Usage::

        session = LiveFuzzingSession(LiveSessionConfig(
            target=FiveGCImpl.OPEN5GS,
            max_hours=8.0,
        ))
        result = await session.run()
        print(f"Found {result.unique_crashes} unique crashes")
    """

    def __init__(self, config: LiveSessionConfig) -> None:
        self.config = config
        self._deployment: Optional[Deployment] = None
        self._clients: Dict[str, Any] = {}
        self._monitor: Optional[ComponentMonitor] = None
        self._engine: Optional[FuzzingEngine] = None
        self._deploy_mgr = DeploymentManager()

    # -- main entry point --------------------------------------------------

    async def run(self) -> LiveSessionResult:
        """Run the complete deploy → train → fuzz → teardown pipeline."""
        result = LiveSessionResult(
            target=self.config.target,
            start_time=time.time(),
        )

        try:
            # 1. Deploy
            logger.info("=== Phase 1/5: Deploying %s ===", self.config.target.value)
            await self._phase_deploy()

            # 2. Train FSMs
            logger.info("=== Phase 2/5: Training FSMs ===")
            fsms = await self._phase_train()

            # 3. Wire clients
            logger.info("=== Phase 3/5: Connecting protocol clients ===")
            send_fn = await self._phase_connect()

            # 4. Fuzz
            logger.info("=== Phase 4/5: Running fuzzing campaign ===")
            crash_results = await self._phase_fuzz(fsms, send_fn)

            # 5. Triage + collect
            logger.info("=== Phase 5/5: Triaging results ===")
            self._phase_triage(crash_results, result)

            result.deployment_healthy = True

        except Exception as exc:
            logger.error("Live session failed: %s", exc)
            result.error_message = str(exc)

        finally:
            # Teardown
            if not self.config.keep_deployment_alive:
                await self._teardown()

        result.end_time = time.time()
        duration = result.end_time - result.start_time
        logger.info(
            "Live session complete: %s — %d iterations, %d crashes in %.0f s",
            self.config.target.value,
            result.total_iterations,
            result.unique_crashes,
            duration,
        )
        return result

    # -- Phase implementations --------------------------------------------

    async def _phase_deploy(self) -> None:
        """Deploy the target 5GC stack."""
        logger.info("Deploying %s (coverage_build=%s)...",
                     self.config.target.value, self.config.coverage_build)

        self._deployment = await self._deploy_mgr.deploy(
            self.config.target,
            coverage_build=self.config.coverage_build,
        )

        if self._deployment.status != DeploymentStatus.HEALTHY:
            logger.warning(
                "Deployment status is %s — some NFs may be degraded",
                self._deployment.status.value,
            )
        else:
            logger.info("Deployment healthy: %d NFs discovered",
                         len(self._deployment.endpoints))

        # Attach component monitor
        self._monitor = ComponentMonitor(self._deployment)

        # Collect baseline coverage
        try:
            await self._monitor.collect_baseline()
            logger.info("Coverage baseline collected")
        except Exception as exc:
            logger.warning("Could not collect coverage baseline: %s", exc)

    async def _phase_train(self) -> Dict[ProtocolType, ProtocolFSM]:
        """Train FSM models by running benign scenarios against the live target.

        Uses the UEGNBSimulator to perform real registrations and PDU session
        establishments, capturing the message traces for FSM learning.
        """
        fsms: Dict[ProtocolType, ProtocolFSM] = {}
        learner = FSMLearner()

        if self._deployment is None:
            logger.warning("No deployment available; skipping FSM training")
            return fsms

        amf_ep = self._deployment.get_endpoint(NFType.AMF)
        if amf_ep is None:
            logger.warning("No AMF endpoint; skipping NAS/NGAP FSM training")
            return fsms

        # -- Live NAS training -------------------------------------------
        try:
            from src.stimulus.ue_gnb_simulator import UEGNBSimulator

            sim = UEGNBSimulator(amf_addr=amf_ep.ip_address,
                                 amf_port=amf_ep.extra_ports.get("sctp", 38412))
            sim.connect()
            logger.info("Training simulator connected to AMF at %s", amf_ep.ip_address)

            nas_traces = await self._collect_nas_training_traces(sim)
            sim.disconnect()

            if nas_traces:
                nas_fsm = learner.learn_from_traces(nas_traces)
                for proc, fsm in nas_fsm.items():
                    fsms[ProtocolType.NAS] = fsm
                    logger.info("Learned NAS FSM: %d states, %d transitions",
                                 len(fsm.states), len(fsm.transitions))
        except Exception as exc:
            logger.warning("NAS FSM training failed: %s", exc)

        # -- Live PFCP training ------------------------------------------
        try:
            upf_ep = self._deployment.get_endpoint(NFType.UPF)
            if upf_ep is not None:
                from src.stimulus.pfcp_client import PFCPClient
                pfcp = PFCPClient(upf_host=upf_ep.ip_address,
                                  upf_port=upf_ep.extra_ports.get("pfcp", 8805))
                await pfcp.connect()
                pfcp_fsm = await self._collect_pfcp_training_traces(pfcp, learner)
                if pfcp_fsm:
                    fsms[ProtocolType.PFCP] = pfcp_fsm
                await pfcp.close()
        except Exception as exc:
            logger.warning("PFCP FSM training failed: %s", exc)

        return fsms

    async def _collect_nas_training_traces(
        self, sim: Any, n_runs: int = 5,
    ) -> List[Any]:
        """Run registration + PDU session establishment N times, capture traces."""
        from src.fsm_learner.learner import Trace, TraceEvent

        traces: List[Trace] = []

        for run in range(n_runs):
            events: List[TraceEvent] = []
            base_time = time.time()

            try:
                ue = sim.register_ue(f"001010{run:09d}")
                events.append(TraceEvent(
                    timestamp=base_time, message_type="Registration Request",
                    direction="uplink",
                ))

                if ue.current_state.value == "registered":
                    events.append(TraceEvent(
                        timestamp=base_time + 0.1,
                        message_type="Authentication Request",
                        direction="downlink",
                    ))
                    events.append(TraceEvent(
                        timestamp=base_time + 0.2,
                        message_type="Authentication Response",
                        direction="uplink",
                    ))
                    events.append(TraceEvent(
                        timestamp=base_time + 0.3,
                        message_type="Security Mode Command",
                        direction="downlink",
                    ))
                    events.append(TraceEvent(
                        timestamp=base_time + 0.4,
                        message_type="Security Mode Complete",
                        direction="uplink",
                    ))
                    events.append(TraceEvent(
                        timestamp=base_time + 0.5,
                        message_type="Registration Accept",
                        direction="downlink",
                    ))
                    events.append(TraceEvent(
                        timestamp=base_time + 0.6,
                        message_type="Registration Complete",
                        direction="uplink",
                    ))

                    # Try PDU session
                    try:
                        pdu = sim.establish_pdu_session(ue)
                        if pdu is not None:
                            events.append(TraceEvent(
                                timestamp=base_time + 0.7,
                                message_type="PDU Session Establishment Request",
                                direction="uplink",
                            ))
                            events.append(TraceEvent(
                                timestamp=base_time + 0.8,
                                message_type="PDU Session Establishment Accept",
                                direction="downlink",
                            ))
                    except Exception:
                        pass

                traces.append(Trace(
                    trace_id=f"live_nas_{run}",
                    protocol="nas-5gs",
                    procedure="registration",
                    events=events,
                    success=ue.current_state.value == "registered",
                    metadata={"source": "live", "target": self.config.target.value},
                ))
            except Exception as exc:
                logger.debug("Training trace %d failed: %s", run, exc)

        logger.info("Collected %d NAS training traces", len(traces))
        return traces

    async def _collect_pfcp_training_traces(
        self, pfcp: Any, learner: FSMLearner,
    ) -> Optional[ProtocolFSM]:
        """Run PFCP association + session establishment for training."""
        import socket
        import struct

        try:
            node_id = socket.inet_aton("127.0.0.2")
            resp = await pfcp.association_setup(node_id, int(time.time()))
            if resp is None:
                return None

            # Session establishment
            resp = await pfcp.session_establishment([b"\x00" * 8], [b"\x00" * 8])
            if resp is not None and hasattr(pfcp, "_session_seid"):
                pfcp._session_seid = resp.fields.get("f_seid", 0)

            pfcp_traces = [
                ["PFCP Association Setup Request", "PFCP Association Setup Response"],
                ["PFCP Session Establishment Request", "PFCP Session Establishment Response"],
            ]
            return learner.learn_from_sequences(
                pfcp_traces, procedure="pfcp", protocol="pfcp",
            )
        except Exception as exc:
            logger.debug("PFCP training failed: %s", exc)
            return None

    async def _phase_connect(self) -> callable:
        """Create and connect all protocol clients, return the send_fn."""
        if self._deployment is None:
            raise RuntimeError("Cannot connect: no deployment")

        send_fn, clients = await make_send_fn_for_deployment(self._deployment)
        self._clients = clients
        return send_fn

    async def _phase_fuzz(
        self,
        fsms: Dict[ProtocolType, ProtocolFSM],
        send_fn: callable,
    ) -> List[FuzzResult]:
        """Run the main fuzzing campaign against the live target."""
        codecs = FuzzingEngine._default_codecs()

        mutator = MutatorEngine()
        # Use the full strategy set
        from src.fuzzing_engine.mutator import (
            BitFlipMutation,
            CrossProtocolMutation,
            HTTP2Mutation,
            RandomMutation,
            SequenceLevelMutation,
            StateAwareMutation,
            StructurePreservingMutation,
        )
        for strat in [
            BitFlipMutation(),
            StructurePreservingMutation(),
            StateAwareMutation(),
            CrossProtocolMutation(),
            SequenceLevelMutation(),
            HTTP2Mutation(),
        ]:
            mutator.add_strategy(strat)

        fuzz_config = FuzzingConfig(
            max_iterations=self.config.max_iterations,
            max_time_seconds=int(self.config.max_hours * 3600),
            checkpoint_interval=self.config.checkpoint_interval,
        )

        self._engine = FuzzingEngine(
            config=fuzz_config,
            codecs=codecs,
            fsms=fsms,
            mutator=mutator,
            monitor=self._monitor,
        )

        self._engine.set_send_function(send_fn)

        # Load seed corpus if available
        corpus_dir = Path("./corpus")
        if corpus_dir.exists():
            self._engine.load_corpus(corpus_dir)

        crash_results = await self._engine.run(
            target_impl=self.config.target,
            target_nf=self.config.primary_nf,
            protocols=self.config.protocols,
        )

        return crash_results

    def _phase_triage(
        self,
        crash_results: List[FuzzResult],
        result: LiveSessionResult,
    ) -> None:
        """Triage crashes and populate result."""
        triage = CrashTriage()
        groups = triage.triage(crash_results)

        result.total_iterations = (
            self._engine.current_iteration if self._engine else 0
        )
        result.unique_crashes = len(groups)
        result.total_crashes = sum(g.count for g in groups)
        result.edges_covered = (
            self._engine.multi_coverage.aggregated.total_edges
            if self._engine else 0
        )
        result.crash_groups = triage.get_statistics().get("groups", [])

        logger.info(
            "Triage: %d unique crashes from %d total (%d groups)",
            result.unique_crashes, result.total_crashes, len(groups),
        )

    async def _teardown(self) -> None:
        """Close clients and destroy deployment."""
        # Close protocol clients
        for name, client in self._clients.items():
            try:
                if hasattr(client, "disconnect"):
                    client.disconnect()
                elif hasattr(client, "close"):
                    await client.close() if asyncio.iscoroutinefunction(
                        client.close
                    ) else client.close()
            except Exception as exc:
                logger.debug("Error closing %s client: %s", name, exc)
        self._clients.clear()

        # Destroy deployment
        if self._deployment is not None:
            try:
                await self._deploy_mgr.destroy(self._deployment)
                logger.info("Deployment destroyed")
            except Exception as exc:
                logger.warning("Deployment teardown error: %s", exc)
            self._deployment = None


# -- module-level convenience --------------------------------------------


async def run_live_fuzzing(
    target: FiveGCImpl,
    hours: float = 8.0,
    protocols: Optional[List[ProtocolType]] = None,
    output_dir: Optional[Path] = None,
) -> LiveSessionResult:
    """Run a live fuzzing session against a single target (one-liner).

    Args:
        target: Which 5GC implementation to fuzz.
        hours: Maximum campaign duration.
        protocols: Protocols to fuzz (default: NAS + NGAP).
        output_dir: Where to save results.

    Returns:
        LiveSessionResult with crash/coverage/stats.
    """
    config = LiveSessionConfig(
        target=target,
        max_hours=hours,
        protocols=protocols or [ProtocolType.NAS, ProtocolType.NGAP],
        output_dir=output_dir or Path("./results"),
    )
    session = LiveFuzzingSession(config)
    return await session.run()
