"""Coverage-aware seed energy scheduling.

Novel algorithm: Seeds get energy proportional to their coverage
novelty and inversely proportional to density in coverage space.
"""

import math
from dataclasses import dataclass


@dataclass
class SeedEnergy:
    coverage_novelty: int  # Number of new edges discovered by this seed
    state_reached: str  # FSM state reached
    crash_found: bool
    generation: int
    size: int  # Size of the seed in bytes
    is_new_state: bool  # Whether this seed reached a previously unseen state


class PowerScheduler:
    """Energy-based seed power scheduling.

    Algorithm:
      For each seed, compute energy based on:
      - Coverage novelty: new edges get bonus
      - State novelty: new FSM states get large bonus
      - Crash trigger: seeds that found crashes get persistent energy boost
      - Generation: newer seeds get slight exploration bonus
      - Size: smaller seeds preferred (faster to fuzz)

      Energy = base_energy * (1 + novelty_factor) * (1 + state_bonus)
               * crash_multiplier * size_factor * gen_decay

    If energy > threshold: seed is "favored" — always selected before non-favored.
    Non-favored seeds have proportional random selection.

    Also implements coverage density penalty:
      Seeds whose coverage overlaps heavily with other seeds get lower energy.
    """

    BASE_ENERGY = 1.0
    NOVELTY_WEIGHT = 0.05  # Per new edge bonus
    STATE_NOVELTY_BONUS = 2.0  # Large bonus for new states
    CRASH_MULTIPLIER = 3.0  # Persistent boost for crash-finding seeds
    MAX_ENERGY = 100.0  # Cap to prevent overflow

    def __init__(self):
        self._state_visit_counts: dict[str, int] = {}
        self._edge_seed_count: dict[int, int] = {}  # Edge → number of seeds that cover it

    def compute_energy(self, seed_info: SeedEnergy) -> float:
        """Compute energy for a seed based on feedback metrics."""
        energy = self.BASE_ENERGY

        # Coverage novelty factor
        if seed_info.coverage_novelty > 0:
            novelty_factor = 1.0 + seed_info.coverage_novelty * self.NOVELTY_WEIGHT
            energy *= novelty_factor

        # State novelty bonus
        state_count = self._state_visit_counts.get(seed_info.state_reached, 0)
        if seed_info.is_new_state:
            energy *= self.STATE_NOVELTY_BONUS
        else:
            # Rare states get more energy
            energy *= 1.0 + 1.0 / (state_count + 1)

        # Crash bonus
        if seed_info.crash_found:
            energy *= self.CRASH_MULTIPLIER

        # Size factor: smaller seeds are faster to process, so fuzz them more
        if seed_info.size > 0:
            size_factor = 1.0 + math.log2(max(1, 4096 / max(seed_info.size, 1)))
            energy *= size_factor

        # Generation decay: newer seeds get slight bonus
        gen_factor = 1.0 + 0.1 / (seed_info.generation + 1)
        energy *= gen_factor

        # Track state visits
        self._state_visit_counts[seed_info.state_reached] = state_count + 1

        return min(energy, self.MAX_ENERGY)

    def compute_edge_density_penalty(self, edge_id: int,
                                     total_seeds: int) -> float:
        """Penalty for edges covered by many seeds (density regularization)."""
        seed_count = self._edge_seed_count.get(edge_id, 0)
        if seed_count == 0 or total_seeds == 0:
            return 1.0
        density = seed_count / total_seeds
        return 1.0 - min(density, 0.9)

    def track_edge_coverage(self, edge_id: int) -> None:
        self._edge_seed_count[edge_id] = self._edge_seed_count.get(edge_id, 0) + 1

    def reset(self) -> None:
        self._state_visit_counts.clear()
        self._edge_seed_count.clear()
