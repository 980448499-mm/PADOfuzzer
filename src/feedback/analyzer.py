"""Feedback analyzer — closes the fuzzing loop.

Analyzes monitoring results to guide fuzzing strategy selection:
  1. Coverage novelty score (how many new edges)
  2. State coverage (which FSM states were reached)
  3. Strategy effectiveness (which mutations find bugs)
  4. Energy adjustment signals for seed scheduling
  5. Coverage growth curve analysis (detect stagnation)
"""

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from src import (
    CrashRecord,
    CrashSeverity,
    Feedback,
    MonitoringResult,
    NFType,
    ProtocolType,
)

logger = logging.getLogger(__name__)


@dataclass
class StrategyStats:
    """Statistics for a mutation strategy."""
    name: str
    iterations: int = 0
    new_edges_found: int = 0
    crashes_found: int = 0
    unique_crashes_found: int = 0
    states_reached: Set[str] = field(default_factory=set)
    avg_response_time: float = 0.0

    @property
    def edges_per_iteration(self) -> float:
        return self.new_edges_found / max(self.iterations, 1)

    @property
    def crash_rate(self) -> float:
        return self.crashes_found / max(self.iterations, 1)


@dataclass
class CoverageGrowthPoint:
    timestamp: float
    total_edges: int
    new_edges: int


class FeedbackAnalyzer:
    """Analyzes fuzzing feedback to guide the next iteration.

    Tracks:
      - Coverage growth over time
      - Strategy effectiveness
      - Coverage stagnation detection
    """

    def __init__(self, stagnation_threshold: int = 100):
        self.stagnation_threshold = stagnation_threshold
        self.strategy_stats: Dict[str, StrategyStats] = {}
        self.coverage_growth: List[CoverageGrowthPoint] = []
        self.iteration_count = 0
        self.last_new_edge_time = time.time()
        self._edges_history: List[int] = []

    def analyze(
        self,
        monitoring: Optional[MonitoringResult],
        crash: Optional[CrashRecord],
        strategy_name: str,
    ) -> Feedback:
        """Analyze monitoring results and produce feedback.

        Returns a Feedback object that guides:
          - Whether to switch strategy
          - Whether coverage is stagnating
          - How to update seed energy
        """
        self.iteration_count += 1

        # Track strategy stats
        if strategy_name not in self.strategy_stats:
            self.strategy_stats[strategy_name] = StrategyStats(name=strategy_name)
        stats = self.strategy_stats[strategy_name]
        stats.iterations += 1

        new_edges_count = 0
        state_reached = None

        if monitoring:
            new_edges_count = len(monitoring.new_edges)
            stats.new_edges_found += new_edges_count
            if monitoring.nf_states:
                for nf, state in monitoring.nf_states.items():
                    stats.states_reached.add(f"{nf}:{state}")
                    state_reached = state

        if crash:
            stats.crashes_found += 1
            if crash.severity in (CrashSeverity.CRITICAL, CrashSeverity.HIGH):
                stats.unique_crashes_found += 1

        # Track coverage growth
        if new_edges_count > 0:
            self.last_new_edge_time = time.time()
            self.coverage_growth.append(CoverageGrowthPoint(
                timestamp=time.time(),
                total_edges=sum(s.new_edges_found for s in self.strategy_stats.values()),
                new_edges=new_edges_count,
            ))

        self._edges_history.append(new_edges_count)
        if len(self._edges_history) > 1000:
            self._edges_history = self._edges_history[-1000:]

        return Feedback(
            coverage_novelty=self._compute_coverage_novelty(),
            state_reached=state_reached,
            crash=crash,
            mutation_strategy=strategy_name,
            new_edges_count=new_edges_count,
            timestamp=time.time(),
        )

    def is_coverage_stagnating(self) -> bool:
        """Check if coverage growth has stalled.

        Stagnation = no new edges in the last N iterations.
        When stagnating, the fuzzer should switch to more
        aggressive strategies (cross-protocol, state-aware).
        """
        if self.iteration_count < self.stagnation_threshold:
            return False
        recent_new_edges = self._edges_history[-self.stagnation_threshold:]
        return sum(recent_new_edges) == 0

    def get_best_strategy(self) -> str:
        """Return the strategy with the highest edge-per-iteration rate."""
        if not self.strategy_stats:
            return "structure_preserving"

        best = max(
            self.strategy_stats.items(),
            key=lambda x: x[1].edges_per_iteration,
        )
        return best[0]

    def get_most_crash_strategy(self) -> str:
        """Return the strategy that found the most unique crashes."""
        if not self.strategy_stats:
            return "state_aware"

        best = max(
            self.strategy_stats.items(),
            key=lambda x: x[1].unique_crashes_found,
        )
        return best[0]

    def get_recommended_strategy(self) -> str:
        """Recommend the next mutation strategy.

        Logic:
          - If coverage stagnating: cross_protocol or state_aware
          - If a strategy is finding crashes: stick with it
          - Otherwise: use the most coverage-efficient strategy
        """
        if self.is_coverage_stagnating():
            return "cross_protocol"

        best_crash = self.get_most_crash_strategy()
        crash_stats = self.strategy_stats.get(best_crash)
        if crash_stats and crash_stats.unique_crashes_found > 0:
            return best_crash

        return self.get_best_strategy()

    def get_coverage_growth_rate(self) -> float:
        """Edges per minute over the last 5 minutes."""
        if len(self.coverage_growth) < 2:
            return 0.0
        recent = [p for p in self.coverage_growth
                  if time.time() - p.timestamp < 300]
        if len(recent) < 2:
            return 0.0
        elapsed = recent[-1].timestamp - recent[0].timestamp
        new_edges = sum(p.new_edges for p in recent)
        return new_edges / max(elapsed, 1) * 60

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of all strategy statistics."""
        return {
            "total_iterations": self.iteration_count,
            "total_new_edges": sum(s.new_edges_found for s in self.strategy_stats.values()),
            "total_crashes": sum(s.crashes_found for s in self.strategy_stats.values()),
            "is_stagnating": self.is_coverage_stagnating(),
            "coverage_growth_rate_epm": self.get_coverage_growth_rate(),
            "strategies": {
                name: {
                    "iterations": s.iterations,
                    "new_edges": s.new_edges_found,
                    "edges_per_iter": f"{s.edges_per_iteration:.4f}",
                    "crashes": s.crashes_found,
                    "unique_crashes": s.unique_crashes_found,
                    "states_reached": len(s.states_reached),
                }
                for name, s in self.strategy_stats.items()
            },
        }

    def reset(self) -> None:
        """Reset analyzer state for a new campaign."""
        self.strategy_stats.clear()
        self.coverage_growth.clear()
        self.iteration_count = 0
        self.last_new_edge_time = time.time()
        self._edges_history.clear()

    def _compute_coverage_novelty(self) -> float:
        """Compute a normalized coverage novelty score."""
        if not self._edges_history:
            return 0.0
        recent = self._edges_history[-10:]
        avg_new = sum(recent) / len(recent)
        # Normalize: 1 new edge per 10 iterations = moderate novelty
        return min(1.0, avg_new / 10.0)
