"""FSM-guided fuzzing: select target states and build attack plans.

Novel algorithm: Rare State Prioritization (RSP)
  - Score states by: 1 / (visit_count + 1) * depth_bonus
  - depth_bonus = 1 + 0.1 * state_depth
  - 5% chance to select invalid (non-existent) transition
"""

import random
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from src.fsm_learner.fsm_model import ProtocolFSM, FSMTransition


@dataclass
class AttackPlan:
    """A sequence of messages designed to reach and fuzz a target state."""

    messages: List[str]  # Message type sequence to reach target
    target_state: str
    fuzz_message_index: int = -1  # Index of message to mutate (last by default)
    metadata: Dict[str, Any] = field(default_factory=dict)


class FSMGuidedFuzzing:
    """Uses learned FSM to guide fuzzing toward interesting states.

    Key insights:
      1. Rare states (visited few times) are more likely to have bugs
      2. Deep states (long path from initial) stress boundary conditions
      3. Invalid transitions (not in learned FSM) exercise error paths
    """

    def __init__(self, fsm: ProtocolFSM):
        self.fsm = fsm
        self.current_state: str = fsm.initial_state or "unknown"
        self.visited_states: Counter = Counter()
        self._invalid_transition_pool: List[str] = []

    def select_target_state(self) -> str:
        """Select target state using Rare State Prioritization (RSP).

        Novel algorithm:
          score(state) = 1 / (visit_count + 1) * (1 + 0.1 * depth)
          5% chance: select a non-existent state (invalid transition)
        """
        if random.random() < 0.05:
            return self._select_invalid_transition()

        if not self.fsm.states:
            return "unknown"

        scores: Dict[str, float] = {}
        for state_name in self.fsm.states:
            visits = self.visited_states.get(state_name, 0)
            visit_bonus = 1.0 / (visits + 1)
            depth = self.fsm.state_depth(state_name)
            depth_bonus = 1.0 + 0.1 * depth
            scores[state_name] = visit_bonus * depth_bonus

        return max(scores, key=scores.get) if scores else "unknown"

    def _select_invalid_transition(self) -> str:
        """Select a message type not valid in the current state."""
        forbidden = self.fsm.get_forbidden_messages(self.current_state)
        if forbidden:
            return f"INVALID ({random.choice(forbidden)})"
        return f"INVALID_STATE_{random.randint(0, 9999)}"

    def build_attack_plan(self, target_state: str) -> AttackPlan:
        """Build sequence of messages to reach target state.

        Returns an AttackPlan where the LAST message in the path
        is the one to be fuzzed.
        """
        if self.current_state == target_state:
            return AttackPlan(
                messages=[target_state],
                target_state=target_state,
                fuzz_message_index=0,
            )

        path = self.fsm.shortest_path(self.current_state, target_state)
        if not path:
            return AttackPlan(
                messages=[],
                target_state=target_state,
            )

        # Build message sequence from transitions
        messages: List[str] = []
        for i in range(len(path) - 1):
            from_s = path[i]
            to_s = path[i + 1]
            transition = self.fsm.get_transition(from_s, to_s)
            if transition:
                messages.append(transition.trigger)

        fuzz_index = len(messages) - 1 if messages else 0

        return AttackPlan(
            messages=messages,
            target_state=target_state,
            fuzz_message_index=max(0, fuzz_index),
        )

    def update_state(self, new_state: str) -> None:
        """Update current state and record visit."""
        self.current_state = new_state
        self.visited_states[new_state] += 1

    def get_state_coverage(self) -> float:
        """Fraction of FSM states visited at least once."""
        if not self.fsm.states:
            return 0.0
        return len(self.visited_states) / len(self.fsm.states)

    def get_rare_states(self, min_visits: int = 2) -> List[str]:
        return [s for s in self.fsm.states
                if self.visited_states.get(s, 0) < min_visits]

    def suggest_mutation_type(self, target_state: str) -> str:
        """Suggest mutation strategy based on target state characteristics.

        - Error states → structure-preserving (understand error handling)
        - Deep states → state-aware (stress boundary conditions)
        - Rare states → aggressive bitflip (exploration)
        - Invalid states → cross-protocol (parser confusion)
        """
        if "INVALID" in target_state:
            return "cross_protocol"
        if "ERROR" in target_state or "REJECT" in target_state:
            return "structure_preserving"
        depth = self.fsm.state_depth(target_state)
        visits = self.visited_states.get(target_state, 0)
        if depth > 3:
            return "state_aware"
        if visits < 3:
            return "bit_flip"
        return "structure_preserving"
