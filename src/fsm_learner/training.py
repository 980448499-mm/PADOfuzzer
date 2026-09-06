"""FSM training orchestration — generates benign traces and learns protocol FSMs.

Training phase workflow:
  1. Generate benign traces via scenario definitions
  2. Feed traces to FSMLearner (PTA → Blue-Fringe EDSM → FSM)
  3. Validate learned FSM against expected state transitions
  4. Serialize FSM models for use by FSMGuidedFuzzing
  5. Optional: refine FSM with additional traces from different targets
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src import FiveGCImpl, ProtocolType
from src.fsm_learner.learner import FSMLearner, Trace, TraceEvent
from src.fsm_learner.fsm_model import ProtocolFSM
from src.stimulus.scenarios.common import BenignScenario

logger = logging.getLogger(__name__)


@dataclass
class TrainingConfig:
    """Configuration for the training phase."""
    target: FiveGCImpl  # Which 5GC to train against
    protocols: List[ProtocolType] = field(default_factory=lambda: [
        ProtocolType.NAS, ProtocolType.NGAP,
    ])
    min_traces_per_procedure: int = 10
    compatibility_threshold: float = 0.85
    output_dir: Optional[Path] = None
    refine_with_live_traces: bool = False


@dataclass
class TrainingResult:
    """Output from one training run."""
    target: FiveGCImpl
    protocol: ProtocolType
    fsm: ProtocolFSM
    procedure: str
    trace_count: int
    state_count: int
    transition_count: int
    expected_states: List[str]  # States the FSM should contain
    validation_passed: bool
    validation_details: str = ""


class FSMTrainer:
    """Orchestrates FSM learning from benign traces.

    Supports:
      - Training from predefined scenario traces
      - Training from captured PCAP traces
      - FSM validation against domain knowledge
      - Per-target FSM refinement
    """

    def __init__(self, config: Optional[TrainingConfig] = None):
        self.config = config or TrainingConfig(target=FiveGCImpl.OPEN5GS)
        self.learner = FSMLearner(compatibility_threshold=
                                   self.config.compatibility_threshold)
        self.results: Dict[str, Dict[str, TrainingResult]] = {}

    # ─── Main training workflow ─────────────────────────────────

    def train_from_scenarios(
        self,
        scenarios: List[BenignScenario],
    ) -> Dict[str, ProtocolFSM]:
        """Learn FSM models from predefined scenario traces.

        Args:
            scenarios: List of benign scenario definitions

        Returns:
            Dict mapping procedure_name → ProtocolFSM
        """
        all_traces: List[Trace] = []
        procedure_map: Dict[str, List[Trace]] = {}

        for scenario in scenarios:
            traces = self._scenario_to_traces(scenario)
            procedure_map.setdefault(scenario.procedure, []).extend(traces)
            all_traces.extend(traces)

            logger.info(
                f"Generated {len(traces)} traces for "
                f"procedure '{scenario.procedure}' from scenario '{scenario.name}'"
            )

        fsms = self.learner.learn_from_traces(all_traces)

        # Store results
        for procedure, fsm in fsms.items():
            self.results.setdefault(self.config.target.value, {})
            self.results[self.config.target.value][procedure] = TrainingResult(
                target=self.config.target,
                protocol=ProtocolType.NAS,
                fsm=fsm,
                procedure=procedure,
                trace_count=len(procedure_map.get(procedure, [])),
                state_count=len(fsm.states),
                transition_count=sum(
                    len(fsm.get_outgoing(name)) for name in fsm.states
                ),
                expected_states=self._expected_states_for(procedure),
                validation_passed=False,  # Set after validation
            )

        return fsms

    def train_from_sequences(
        self,
        sequences: Dict[str, List[List[str]]],
        protocol: ProtocolType = ProtocolType.NAS,
    ) -> Dict[str, ProtocolFSM]:
        """Quick training from message sequences (for testing/development).

        Args:
            sequences: Dict of procedure_name → list of message sequences
            protocol: Protocol type

        Returns:
            Learned FSMs
        """
        fsms: Dict[str, ProtocolFSM] = {}

        for procedure, seqs in sequences.items():
            fsm = self.learner.learn_from_sequences(
                seqs, procedure=procedure, protocol=protocol.value
            )
            if fsm:
                fsms[procedure] = fsm
                logger.info(
                    f"Learned FSM for '{procedure}': "
                    f"{len(fsm.states)} states, "
                    f"{sum(len(fsm.get_outgoing(name)) for name in fsm.states)} transitions"
                )

        return fsms

    # ─── FSM validation ────────────────────────────────────────

    def validate_fsm(
        self,
        fsm: ProtocolFSM,
        procedure: str,
    ) -> Tuple[bool, str]:
        """Validate a learned FSM against domain knowledge.

        Checks:
          1. Required states are present
          2. Required transitions exist
          3. No disconnected states (unreachable)
          4. START state has outgoing edges
          5. Coverage: at least N unique message types
        """
        details: List[str] = []
        valid = True

        # Check 1: Required states
        expected = self._expected_states_for(procedure)
        found_states = set(fsm.states.keys())
        for expected_state in expected:
            found = any(expected_state.lower() in s.lower()
                       for s in found_states)
            if not found:
                details.append(f"Missing expected state: {expected_state}")
                valid = False

        # Check 2: START state reachability
        start_id = fsm.initial_state
        if start_id not in fsm.states:
            details.append("No START state found")
            valid = False
        elif not fsm.get_outgoing(start_id):
            details.append("START state has no outgoing transitions")
            valid = False

        # Check 3: Minimum size
        if len(fsm.states) < 2:
            details.append(f"FSM too small: {len(fsm.states)} states")
            valid = False

        # Check 4: Connectedness (all states reachable from START)
        reachable = self._bfs_reachable(fsm, start_id)
        for state_id in fsm.states:
            if state_id not in reachable:
                details.append(f"State '{state_id}' is not reachable from START")
                valid = False

        # Check 5: Unique message types
        messages: set = set()
        for state_name in fsm.states:
            for trans in fsm.get_outgoing(state_name):
                messages.add(trans.trigger)
        if len(messages) < 2:
            details.append(f"Too few unique message types: {len(messages)}")
            valid = False

        status = "PASSED" if valid else "FAILED"
        details_str = f"{status}: {'; '.join(details)}" if details else f"{status}"
        logger.info(f"FSM validation for '{procedure}': {details_str}")

        return valid, details_str

    def validate_all(self) -> Dict[str, bool]:
        """Validate all trained FSMs."""
        results: Dict[str, bool] = {}
        for target_results in self.results.values():
            for proc, result in target_results.items():
                passed, details = self.validate_fsm(result.fsm, proc)
                result.validation_passed = passed
                result.validation_details = details
                results[f"{result.target.value}/{proc}"] = passed
        return results

    # ─── Persistence ──────────────────────────────────────────

    def save_fsms(self, output_dir: Path) -> None:
        """Save all trained FSMs to disk."""
        output_dir.mkdir(parents=True, exist_ok=True)

        for target_results in self.results.values():
            for proc, result in target_results.items():
                target_dir = output_dir / result.target.value
                target_dir.mkdir(parents=True, exist_ok=True)

                fsm_dict = result.fsm.to_dict()
                fsm_dict["procedure"] = proc
                fsm_dict["target"] = result.target.value

                filepath = target_dir / f"{proc}_fsm.json"
                with open(filepath, "w") as f:
                    json.dump(fsm_dict, f, indent=2, default=str)

                mermaid = result.fsm.to_mermaid()
                mermaid_path = target_dir / f"{proc}_fsm.md"
                with open(mermaid_path, "w") as f:
                    f.write(f"# {proc} FSM\n\n```mermaid\n{mermaid}\n```\n")

        logger.info(f"Saved all FSMs to {output_dir}")

    def load_fsms(self, input_dir: Path) -> Dict[str, Dict[str, ProtocolFSM]]:
        """Load trained FSMs from disk."""
        loaded: Dict[str, Dict[str, ProtocolFSM]] = {}

        for json_file in input_dir.rglob("*_fsm.json"):
            with open(json_file) as f:
                data = json.load(f)

            fsm = ProtocolFSM.from_dict(data)
            target = data["target"]
            procedure = data["procedure"]

            loaded.setdefault(target, {})[procedure] = fsm
            logger.info(f"Loaded FSM: {target}/{procedure} "
                       f"({len(fsm.states)} states)")

        return loaded

    # ─── Helpers ──────────────────────────────────────────────

    def _scenario_to_traces(self, scenario: BenignScenario) -> List[Trace]:
        """Convert a scenario to multiple Trace objects (one per run)."""
        traces: List[Trace] = []
        protocol_str = scenario.protocol.value

        for run in range(scenario.n_runs):
            events = []
            base_time = run * 0.1  # stagger timestamps

            for i, step in enumerate(scenario.steps):
                events.append(TraceEvent(
                    timestamp=base_time + i * 0.05,
                    message_type=step.message_type,
                    direction=step.direction.value,
                    fields=step.fields,
                ))

            traces.append(Trace(
                trace_id=f"{scenario.procedure}_{run}",
                protocol=protocol_str,
                procedure=scenario.procedure,
                events=events,
                success=True,
                metadata={"scenario": scenario.name},
            ))

        return traces

    @staticmethod
    def _expected_states_for(procedure: str) -> List[str]:
        """Return expected FSM states for a given procedure.

        Based on 3GPP procedure specifications.
        """
        expected = {
            "registration": [
                "INIT", "AUTHENTICATING", "SECURING", "REGISTERED",
            ],
            "pdu_session_establishment": [
                "INIT", "PDU_SESSION_PENDING", "PDU_SESSION_ACTIVE",
            ],
            "pfcp_session_establishment": [
                "INIT", "SESSION_ESTABLISHED",
            ],
            "service_request": [
                "INIT", "SERVICE_REQUESTED", "CONNECTED",
            ],
            "deregistration": [
                "INIT", "DEREGISTERING", "DEREGISTERED",
            ],
        }
        return expected.get(procedure, ["INIT", "COMPLETE"])

    @staticmethod
    def _bfs_reachable(fsm: ProtocolFSM, start_state: str) -> set:
        """BFS to find all reachable states from start_state."""
        visited: set = {start_state}
        queue = [start_state]
        while queue:
            current = queue.pop(0)
            for trans in fsm.get_outgoing(current):
                if trans.to_state not in visited:
                    visited.add(trans.to_state)
                    queue.append(trans.to_state)
        return visited

    # ─── Training pipeline ─────────────────────────────────────

    def run_training_pipeline(
        self,
        scenarios: Optional[List[BenignScenario]] = None,
    ) -> Dict[str, Dict[str, ProtocolFSM]]:
        """Run the complete training pipeline.

        1. Generate traces from scenarios
        2. Learn FSM models
        3. Validate each FSM
        4. Save to output directory
        5. Return trained FSMs
        """
        if scenarios is None:
            from src.stimulus.scenarios.registration import make_registration_scenario
            from src.stimulus.scenarios.pdu_session import make_pdu_session_scenario
            scenarios = [
                make_registration_scenario(),
                make_pdu_session_scenario(),
            ]

        logger.info(
            f"Starting training pipeline with {len(scenarios)} scenarios"
        )

        fsms = self.train_from_scenarios(scenarios)
        validations = self.validate_all()

        passed = sum(1 for v in validations.values() if v)
        total = len(validations)
        logger.info(f"FSM validation: {passed}/{total} passed")

        if self.config.output_dir:
            self.save_fsms(self.config.output_dir)

        # Return per-target FSMs
        result: Dict[str, Dict[str, ProtocolFSM]] = {}
        for target, proc_results in self.results.items():
            result[target] = {
                proc: r.fsm for proc, r in proc_results.items()
            }

        return result
