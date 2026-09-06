"""Mutation engine with dynamic strategy selection based on coverage and FSM state.

Base classes live in src.fuzzing_engine.mutations.base to avoid circular imports.
The 6 primary mutation strategies are in the src.fuzzing_engine.mutations package.
"""

import random
from typing import Any, Dict, List, Optional, Tuple

from src import ProtocolType
from src.codec.base import ProtocolCodec
from src.fuzzing_engine.seed_manager import Seed

# Import base classes from shared location
from .mutations.base import MutationContext, MutationStrategy  # noqa: E402

# Re-export strategies for backward compatibility
from .mutations import (  # noqa: E402, F401
    BitFlipMutation,
    StructurePreservingMutation,
    StateAwareMutation,
    CrossProtocolMutation,
    SequenceLevelMutation,
    HTTP2Mutation,
)


class RandomMutation(MutationStrategy):
    """Pure random byte mutation (baseline strategy)."""

    name = "random"

    def mutate(self, seed: Seed, context: MutationContext) -> bytes:
        r = context.random
        rate = r.uniform(0.01, 0.10)
        data = bytearray(seed.raw_pdu)
        num_bytes = max(1, int(len(data) * rate))
        for _ in range(num_bytes):
            if data:
                pos = r.randint(0, len(data) - 1)
                data[pos] = r.randint(0, 255)
        return bytes(data) if data else bytes([r.randint(0, 255)])


class MutatorEngine:
    """Selects and applies mutation strategies based on context.

    Strategy selection policy (novel contribution):
      - Coverage stagnation (>100 iter no new edges): Cross-Protocol or aggressive
      - Deep FSM state (e.g., PDU_SESSION_ACTIVE): State-Aware
      - New seeds (generation < 3): Bit-Flip (exploration)
      - Existing seeds: Structure-Preserving (exploitation)
      - HTTP/2 protocol: always try HTTP2 first
    """

    def __init__(self):
        self.strategies: List[MutationStrategy] = [
            BitFlipMutation(),
            StructurePreservingMutation(),
            StateAwareMutation(),
            CrossProtocolMutation(),
            SequenceLevelMutation(),
            HTTP2Mutation(),
            RandomMutation(),
        ]
        self._strategy_map = {s.name: s for s in self.strategies}
        self._strategy_stats: Dict[str, int] = {s.name: 0 for s in self.strategies}
        self._stagnation_counter = 0

    def mutate(
        self,
        seed: Seed,
        protocol: ProtocolType,
        codec: Optional[ProtocolCodec] = None,
        current_state: str = "unknown",
        coverage_stagnation: bool = False,
    ) -> Tuple[MutationStrategy, bytes]:
        """Select strategy and apply mutation.

        Returns (strategy_used, fuzzed_pdu_bytes).
        """
        context = MutationContext(
            protocol=protocol,
            current_state=current_state,
            codec=codec,
            coverage_stagnation=coverage_stagnation,
            iteration=0,
        )

        if coverage_stagnation:
            self._stagnation_counter += 1
        else:
            self._stagnation_counter = 0

        r = context.random

        # Strategy selection logic
        if protocol == ProtocolType.SBI:
            strategy = self._strategy_map["http2"]
        elif self._stagnation_counter > 100:
            strategy = r.choice([
                self._strategy_map["cross_protocol"],
                self._strategy_map["state_aware"],
            ])
        elif seed.generation < 3:
            strategy = r.choice([
                self._strategy_map["bit_flip"],
                self._strategy_map["structure_preserving"],
            ])
        else:
            # Weighted selection
            weights = {
                "bit_flip": 0.15,
                "structure_preserving": 0.30,
                "state_aware": 0.25,
                "cross_protocol": 0.10,
                "sequence_level": 0.10,
                "http2": 0.05,
                "random": 0.05,
            }
            strategy_name = r.choices(
                list(weights.keys()),
                weights=list(weights.values()),
                k=1,
            )[0]
            strategy = self._strategy_map[strategy_name]

        fuzzed_pdu = strategy.mutate(seed, context)
        self._strategy_stats[strategy.name] += 1

        return strategy, fuzzed_pdu

    def get_strategy_stats(self) -> Dict[str, int]:
        return dict(self._strategy_stats)

    def add_strategy(self, strategy: MutationStrategy) -> None:
        self.strategies.append(strategy)
        self._strategy_map[strategy.name] = strategy
        if strategy.name not in self._strategy_stats:
            self._strategy_stats[strategy.name] = 0

    def reset_stats(self) -> None:
        for k in self._strategy_stats:
            self._strategy_stats[k] = 0
