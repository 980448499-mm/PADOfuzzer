"""FSM state-guided mutation strategy.

Targets invalid state transitions by injecting messages known to be
invalid in the current protocol state.
"""

from typing import Dict, List

from .base import MutationStrategy, MutationContext
from src.fuzzing_engine.seed_manager import Seed
from .bit_flip import BitFlipMutation
from .structure_preserving import StructurePreservingMutation


class StateAwareMutation(MutationStrategy):
    """Mutations guided by FSM state — targets invalid transitions."""

    name = "state_aware"

    def __init__(self):
        self._invalid_messages: Dict[str, List[bytes]] = {}

    def register_invalid_message(self, state: str, pdu: bytes) -> None:
        """Register a PDU known to be invalid for a specific state."""
        if state not in self._invalid_messages:
            self._invalid_messages[state] = []
        self._invalid_messages[state].append(pdu)

    def mutate(self, seed: Seed, context: MutationContext) -> bytes:
        r = context.random
        state = context.current_state

        # 70%: use structure-preserving mutation from current state
        if r.random() < 0.7 and context.codec:
            return StructurePreservingMutation().mutate(seed, context)

        # 30%: try to force invalid transition
        invalid_for_state = self._invalid_messages.get(state, [])
        if invalid_for_state and r.random() < 0.5:
            return r.choice(invalid_for_state)

        # Fallback: aggressive bit flips
        return BitFlipMutation().mutate(seed, context)
