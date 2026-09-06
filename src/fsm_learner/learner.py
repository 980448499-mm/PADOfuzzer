"""FSM Learner: learn protocol state machines from benign traffic traces.

Combines:
  - Prefix Tree Acceptor construction from message traces
  - Blue-Fringe EDSM for state generalization
  - Log-pcap alignment for state labeling with domain knowledge
  - FSM export/import for fuzzing guidance

Input: Timestamped traces of benign protocol interaction
       (pcap + NF logs, aligned by transaction)

Output: Deterministic ProtocolFSM for each protocol procedure
"""

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from src.fsm_learner.blue_fringe import BlueFringeEDSM
from src.fsm_learner.compatibility import CompatibilityScorer
from src.fsm_learner.fsm_model import ProtocolFSM
from src.fsm_learner.prefix_tree import PrefixTreeAcceptor

logger = logging.getLogger(__name__)


@dataclass
class TraceEvent:
    """A single event in a protocol trace."""

    timestamp: float
    message_type: str  # e.g., "Registration Request"
    direction: str  # "uplink" or "downlink"
    raw_data: Optional[bytes] = None
    nf_type: Optional[str] = None  # Source NF
    session_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Trace:
    """A complete protocol interaction trace."""

    trace_id: str
    protocol: str
    procedure: str  # e.g., "registration", "pdu_session_establishment"
    events: List[TraceEvent] = field(default_factory=list)
    success: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def message_sequence(self) -> List[str]:
        return [e.message_type for e in self.events]

    @property
    def uplink_sequence(self) -> List[str]:
        return [e.message_type for e in self.events if e.direction == "uplink"]

    @property
    def downlink_sequence(self) -> List[str]:
        return [e.message_type for e in self.events if e.direction == "downlink"]


class FSMLearner:
    """Learn protocol state machines from traffic traces.

    Two-phase approach:
      Phase 1: Learn from benign traces (EDSM)
      Phase 2: Incorporate domain knowledge (3GPP spec alignment)
    """

    def __init__(self, compatibility_threshold: float = 0.85):
        self.threshold = compatibility_threshold
        self.learned_fsms: Dict[str, ProtocolFSM] = {}  # procedure_name -> FSM

    def learn_from_traces(self, traces: List[Trace]) -> Dict[str, ProtocolFSM]:
        """Learn FSMs from a set of protocol traces.

        Args:
            traces: List of benign protocol interaction traces

        Returns:
            Dict mapping procedure name to learned FSM
        """
        # Group traces by procedure
        grouped: Dict[str, List[Trace]] = defaultdict(list)
        for trace in traces:
            grouped[trace.procedure].append(trace)

        for procedure, proc_traces in grouped.items():
            fsm = self._learn_single_procedure(procedure, proc_traces)
            if fsm:
                self.learned_fsms[procedure] = fsm
                logger.info(
                    f"Learned FSM for {procedure}: "
                    f"{len(fsm.states)} states, {len(fsm.transitions)} transitions"
                )

        return self.learned_fsms

    def _learn_single_procedure(
        self, procedure: str, traces: List[Trace]
    ) -> Optional[ProtocolFSM]:
        """Learn FSM for a single procedure type.

        Steps:
          1. Extract message sequences from traces
          2. Build Prefix Tree Acceptor
          3. Run Blue-Fringe EDSM
          4. Label states with domain knowledge
          5. Return generalized FSM
        """
        if not traces:
            return None

        # Extract message sequences
        sequences = [t.message_sequence for t in traces if t.success]
        if not sequences:
            return None

        # Build PTA
        pta = PrefixTreeAcceptor()
        pta.insert_traces(sequences)
        logger.debug(
            f"PTA for {procedure}: {pta.get_total_traces()} traces, "
            f"{pta.get_total_nodes()} nodes"
        )

        # Run EDSM
        edsm = BlueFringeEDSM(compatibility_threshold=self.threshold)
        fsm = edsm.run(pta, protocol="nas-5gs", fsm_name=procedure)

        # Label states with domain knowledge
        fsm = self._label_states(fsm, procedure)

        # Build message type map
        all_msg_types: Set[str] = set()
        for trace in traces:
            for event in trace.events:
                all_msg_types.add(event.message_type)
        for i, msg in enumerate(sorted(all_msg_types)):
            fsm.message_type_map[i] = msg

        return fsm

    def _label_states(self, fsm: ProtocolFSM, procedure: str) -> ProtocolFSM:
        """Label FSM states with domain-meaningful names.

        Uses procedure-specific knowledge to map merged states
        to protocol phase labels.
        """
        # State labeling patterns per procedure type
        LABEL_PATTERNS: Dict[str, Dict[str, List[str]]] = {
            "registration": {
                "INIT": ["START", "INIT", "DEREGISTERED"],
                "DEREGISTERED": ["INIT", "S_0"],
                "AUTHENTICATING": ["Authentication Request", "Authentication Response"],
                "SECURING": ["Security Mode Command", "Security Mode Complete"],
                "REGISTERED": ["Registration Accept", "Registration Complete"],
                "REGISTRATION_FAILED": ["Registration Reject", "Authentication Reject"],
            },
            "pdu_session_establishment": {
                "INIT": ["START", "INIT"],
                "PDU_ESTABLISHING": ["PDU Session Establishment Request"],
                "PDU_ACTIVE": ["PDU Session Establishment Accept"],
                "PDU_REJECTED": ["PDU Session Establishment Reject"],
            },
        }

        patterns = LABEL_PATTERNS.get(procedure, {})
        if not patterns:
            return fsm

        for state_name, state in list(fsm.states.items()):
            outgoing = [t.trigger for t in fsm.get_outgoing(state_name)]
            incoming = [t.trigger for t in fsm.get_incoming(state_name)]
            all_related = outgoing + incoming

            for label, triggers in patterns.items():
                if any(t in all_related for t in triggers):
                    # Rename state to meaningful label
                    new_name = label
                    if new_name in fsm.states and new_name != state_name:
                        new_name = f"{label}_{state_name}"
                    fsm.states[new_name] = state
                    del fsm.states[state_name]
                    state.name = new_name

                    # Update transitions
                    for t in fsm.transitions:
                        if t.from_state == state_name:
                            t.from_state = new_name
                        if t.to_state == state_name:
                            t.to_state = new_name
                    break

        return fsm

    def learn_from_sequences(self, sequences: List[List[str]],
                             procedure: str = "unknown",
                             protocol: str = "unknown") -> Optional[ProtocolFSM]:
        """Quick FSM learning from pre-extracted message sequences.

        Useful for testing and for synthetic trace generation.
        """
        pta = PrefixTreeAcceptor()
        pta.insert_traces(sequences)

        edsm = BlueFringeEDSM(compatibility_threshold=self.threshold)
        fsm = edsm.run(pta, protocol=protocol, fsm_name=procedure)
        return fsm

    def get_fsm(self, procedure: str) -> Optional[ProtocolFSM]:
        """Get a learned FSM by procedure name."""
        return self.learned_fsms.get(procedure)

    def get_all_fsms(self) -> Dict[str, ProtocolFSM]:
        return dict(self.learned_fsms)
