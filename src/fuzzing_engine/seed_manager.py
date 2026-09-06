"""Seed management with coverage-guided energy scheduling."""

import hashlib
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set
from uuid import UUID, uuid4

from src import ProtocolType
from src.codec.base import ParsedMessage
from src.fuzzing_engine.power_scheduler import SeedEnergy, PowerScheduler


@dataclass
class Seed:
    """A single seed in the fuzzing corpus."""

    id: UUID = field(default_factory=uuid4)
    protocol: Optional[ProtocolType] = None
    raw_pdu: bytes = b""
    parsed_message: Optional[ParsedMessage] = None
    state_context: str = "unknown"  # FSM state this seed belongs to
    coverage_bitmap: Optional[Set[int]] = None  # Edge IDs covered
    energy: float = 1.0
    parent_id: Optional[UUID] = None
    generation: int = 0
    timestamp: float = field(default_factory=time.time)
    mutation_history: List[str] = field(default_factory=list)
    crash_triggered: bool = False
    tag: str = ""

    @property
    def coverage_signature(self) -> str:
        if self.raw_pdu:
            return hashlib.sha256(self.raw_pdu).hexdigest()[:16]
        return "empty"

    @property
    def size(self) -> int:
        return len(self.raw_pdu)


class SeedManager:
    """Manages the seed corpus with energy-based scheduling.

    Inspired by AFL's queue management but extended with:
      - Coverage bitmap tracking per seed
      - FSM state context awareness
      - Energy scheduling based on coverage novelty
      - Multi-protocol seed categorization
    """

    def __init__(self, corpus_dir: Optional[Path] = None):
        self.corpus_dir = corpus_dir or Path("./corpus")
        self.queue: List[Seed] = []
        self.favored: List[Seed] = []
        self._coverage_signatures: Set[str] = set()
        self._state_seeds: Dict[str, List[Seed]] = {}
        self.power_scheduler = PowerScheduler()
        self._total_iterations = 0

    def add_seed(self, seed: Seed) -> bool:
        """Add a seed to the corpus if it provides new coverage."""
        sig = seed.coverage_signature
        if sig in self._coverage_signatures:
            return False

        self._coverage_signatures.add(sig)
        self.queue.append(seed)
        self._index_by_state(seed)
        return True

    def select_next(self) -> Optional[Seed]:
        """Select the next seed for fuzzing using AFL-style scheduling.

        Strategy:
          1. If there are unfuzzed favored seeds, pick one
          2. Otherwise, pick from queue with probability proportional to energy
          3. Occasionally (5%) pick a random seed for exploration
        """
        self._total_iterations += 1

        if not self.queue:
            return None

        # 5% exploration: random seed
        if random.random() < 0.05:
            return random.choice(self.queue)

        # Pick from favored queue first (skip every other for non-favored)
        if self.favored and self._total_iterations % 3 != 0:
            seed = self.favored[0]
            self.favored = self.favored[1:] + self.favored[:1]  # Rotate
            return seed

        # Weighted selection by energy
        total_energy = sum(s.energy for s in self.queue)
        if total_energy <= 0:
            return random.choice(self.queue)

        r = random.uniform(0, total_energy)
        cumulative = 0.0
        for seed in self.queue:
            cumulative += seed.energy
            if r <= cumulative:
                return seed

        return self.queue[-1]

    def select_for_state(self, target_state: str) -> Optional[Seed]:
        """Select a seed closest to the target FSM state."""
        state_seeds = self._state_seeds.get(target_state, [])
        if state_seeds:
            return max(state_seeds, key=lambda s: s.energy)
        # Fallback: return a random seed
        return random.choice(self.queue) if self.queue else None

    def update_energy(self, seed: Seed, new_coverage: Set[int],
                      state_reached: str = "unknown",
                      crash_found: bool = False) -> None:
        """Update a seed's energy based on feedback."""
        coverage_novelty = len(new_coverage - (seed.coverage_bitmap or set()))
        seed.energy = self.power_scheduler.compute_energy(
            SeedEnergy(
                coverage_novelty=coverage_novelty,
                state_reached=state_reached,
                crash_found=crash_found,
                generation=seed.generation,
                size=seed.size,
                is_new_state=state_reached not in self._state_seeds,
            )
        )
        if seed.coverage_bitmap is None:
            seed.coverage_bitmap = set()
        seed.coverage_bitmap |= new_coverage

        # Promote to favored if energy is high
        if seed.energy > 2.0 and seed not in self.favored:
            self.favored.append(seed)

    def get_state_coverage(self) -> Dict[str, int]:
        """Return count of seeds per FSM state."""
        return {state: len(seeds) for state, seeds in self._state_seeds.items()}

    def reset(self) -> None:
        """Reset the seed manager state."""
        self.queue.clear()
        self.favored.clear()
        self._coverage_signatures.clear()
        self._state_seeds.clear()
        self._total_iterations = 0

    def _index_by_state(self, seed: Seed) -> None:
        state = seed.state_context
        if state not in self._state_seeds:
            self._state_seeds[state] = []
        self._state_seeds[state].append(seed)

    @property
    def total_seeds(self) -> int:
        return len(self.queue)

    @property
    def total_favored(self) -> int:
        return len(self.favored)
