"""State compatibility scoring for FSM state merging.

Scores how compatible two PTA states are for merging, based on:
  1. Future behavior similarity (same outgoing transitions)
  2. Message type distribution similarity
  3. Trace count compatibility
  4. Depth similarity (states at similar depths are more likely mergeable)
"""

import math
from collections import Counter
from typing import Dict, List

from src.fsm_learner.prefix_tree import PTANode


class CompatibilityScorer:
    """Evidence-driven compatibility scoring for Blue-Fringe merging.

    Higher score = more compatible for merging.
    Threshold controls aggressiveness of generalization.
    """

    def __init__(self, threshold: float = 0.85):
        self.threshold = threshold

    def score(self, red_state: PTANode, blue_state: PTANode) -> float:
        """Compute compatibility score between a RED (deterministic)
        and a BLUE (candidate) state.

        Returns score in [0.0, 1.0]. Higher = more compatible.
        """
        if red_state.node_id == blue_state.node_id:
            return 1.0

        scores: List[float] = []

        # 1. Future behavior similarity
        future_sim = self._future_behavior_similarity(red_state, blue_state)
        scores.append(("future_behavior", 0.35, future_sim))

        # 2. Outgoing transition similarity
        trans_sim = self._outgoing_transition_similarity(red_state, blue_state)
        scores.append(("outgoing_trans", 0.30, trans_sim))

        # 3. Trace count compatibility
        trace_sim = self._trace_count_similarity(red_state, blue_state)
        scores.append(("trace_count", 0.15, trace_sim))

        # 4. Depth similarity
        depth_sim = self._depth_similarity(red_state, blue_state)
        scores.append(("depth", 0.10, depth_sim))

        # 5. Label similarity
        label_sim = 1.0 if red_state.label == blue_state.label else 0.5
        scores.append(("label", 0.10, label_sim))

        # Weighted sum
        total = sum(factor * score for _, factor, score in scores)
        return min(1.0, max(0.0, total))

    def can_merge(self, red_state: PTANode, blue_state: PTANode) -> bool:
        """Determine if two states should be merged."""
        return self.score(red_state, blue_state) >= self.threshold

    # ─── Sub-scorers ──────────────────────────────────────────

    @staticmethod
    def _future_behavior_similarity(a: PTANode, b: PTANode) -> float:
        """How similar are the outgoing transition sets?"""
        a_trans = set(a.children.keys())
        b_trans = set(b.children.keys())
        if not a_trans and not b_trans:
            return 1.0  # Both leaf nodes
        if not a_trans or not b_trans:
            return 0.0  # One leaf, one internal

        intersection = len(a_trans & b_trans)
        union = len(a_trans | b_trans)
        return intersection / union if union > 0 else 0.0

    @staticmethod
    def _outgoing_transition_similarity(a: PTANode, b: PTANode) -> float:
        """How similar are the outgoing message type distributions?"""
        a_dist = Counter(a.children.keys())
        b_dist = Counter(b.children.keys())
        all_keys = set(a_dist.keys()) | set(b_dist.keys())

        if not all_keys:
            return 1.0

        # Jensen-Shannon divergence approximation via simple overlap
        overlap = sum(1 for k in all_keys if k in a_dist and k in b_dist)
        return overlap / len(all_keys)

    @staticmethod
    def _trace_count_similarity(a: PTANode, b: PTANode) -> float:
        """States with similar trace counts are more mergeable."""
        if a.trace_count == 0 and b.trace_count == 0:
            return 1.0
        max_count = max(a.trace_count, b.trace_count)
        min_count = min(a.trace_count, b.trace_count)
        if max_count == 0:
            return 0.0
        return min_count / max_count

    @staticmethod
    def _depth_similarity(a: PTANode, b: PTANode) -> float:
        """States at similar depths in the tree are more mergeable."""
        diff = abs(a.depth - b.depth)
        max_depth = max(a.depth, b.depth, 1)
        return 1.0 - (diff / (max_depth * 2))
