"""Base classes for mutation strategies.

Separated from mutator.py to avoid circular imports when strategies
are defined in the mutations/ package.
"""

import random
from abc import ABC, abstractmethod
from typing import Optional

from src import ProtocolType
from src.codec.base import ProtocolCodec
from src.fuzzing_engine.seed_manager import Seed


class MutationContext:
    """Context provided to mutation strategies."""

    def __init__(
        self,
        protocol: ProtocolType,
        current_state: str = "unknown",
        codec: Optional[ProtocolCodec] = None,
        coverage_stagnation: bool = False,
        iteration: int = 0,
    ):
        self.protocol = protocol
        self.current_state = current_state
        self.codec = codec
        self.coverage_stagnation = coverage_stagnation
        self.iteration = iteration
        self.random = random.Random()


class MutationStrategy(ABC):
    """Base class for all mutation strategies."""

    name: str = "base"

    @abstractmethod
    def mutate(self, seed: Seed, context: MutationContext) -> bytes:
        """Mutate a seed and return the fuzzed PDU bytes."""

    def get_weight(self, context: MutationContext) -> float:
        """Return the weight for this strategy in the given context."""
        return 1.0
