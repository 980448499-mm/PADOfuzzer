r"""Blue-Fringe Evidence-Driven State Merging (EDSM) algorithm.

Algorithm:
  1. Build Prefix Tree Acceptor (PTA) from traces
  2. Mark root as RED (deterministic / final)
  3. Mark all children of RED nodes as BLUE (candidates for merging)
  4. For each BLUE state:
     a. Compute compatibility score with each RED state
     b. Merge BLUE with most compatible RED if score >= threshold
     c. Otherwise, promote BLUE to RED
  5. Repeat until no BLUE states remain
  6. Return minimized FSM

The result is a deterministic finite automaton that generalizes
from the observed traces.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from src.fsm_learner.compatibility import CompatibilityScorer
from src.fsm_learner.fsm_model import ProtocolFSM
from src.fsm_learner.prefix_tree import PTANode, PrefixTreeAcceptor


@dataclass
class MergedState:
    """A merged state in the resulting FSM."""
    name: str
    original_nodes: Set[int] = field(default_factory=set)  # PTA node IDs merged here
    is_initial: bool = False
    is_accepting: bool = False
    outgoing: Dict[str, str] = field(default_factory=dict)  # trigger -> state_name


class BlueFringeEDSM:
    """Evidence-Driven State Merging algorithm.

    Builds a generalized FSM from a PTA by merging compatible states.
    """

    def __init__(self, compatibility_threshold: float = 0.85):
        self.scorer = CompatibilityScorer(threshold=compatibility_threshold)
        self.red_states: Dict[int, PTANode] = {}  # node_id -> node (deterministic)
        self.blue_states: Dict[int, PTANode] = {}  # node_id -> node (candidates)
        self.merged_fsm: Optional[ProtocolFSM] = None
        self.node_merge_map: Dict[int, str] = {}  # node_id -> merged state name

    def run(self, pta: PrefixTreeAcceptor, protocol: str = "unknown",
            fsm_name: str = "LearnedFSM") -> ProtocolFSM:
        """Run the Blue-Fringe EDSM algorithm on a PTA.

        Args:
            pta: Prefix Tree Acceptor built from traces
            protocol: Protocol name (e.g., "nas-5gs")
            fsm_name: Name for the learned FSM

        Returns:
            Minimized ProtocolFSM
        """
        # Step 1: Mark root as RED
        self.red_states[pta.root.node_id] = pta.root
        self.node_merge_map[pta.root.node_id] = "INIT"

        # Step 2: Mark all children of RED nodes as BLUE
        self._update_blue_fringe()

        # Step 3-5: Main merging loop
        while self.blue_states:
            best_blue = self._select_best_blue()
            if best_blue is None:
                break

            best_red = self._find_best_red(best_blue)

            if best_red is not None and self.scorer.can_merge(best_red, best_blue):
                self._merge(best_blue, best_red)
            else:
                self._promote(best_blue)

            self._update_blue_fringe()

        # Step 6: Build result FSM
        return self._build_fsm(protocol, fsm_name)

    def _update_blue_fringe(self) -> None:
        """Identify BLUE states: non-RED children of RED states."""
        self.blue_states.clear()
        for red_id, red_node in self.red_states.items():
            for child_label, child_node in red_node.children.items():
                if child_node.node_id not in self.red_states:
                    self.blue_states[child_node.node_id] = child_node

    def _select_best_blue(self) -> Optional[PTANode]:
        """Select the best BLUE state to process next.

        Strategy: Pick the BLUE state with highest trace count
        (most evidence for generalization decisions).
        """
        if not self.blue_states:
            return None
        return max(self.blue_states.values(), key=lambda n: n.trace_count)

    def _find_best_red(self, blue_node: PTANode) -> Optional[PTANode]:
        """Find the RED state most compatible with this BLUE state."""
        best_red = None
        best_score = -1.0

        for red_id, red_node in self.red_states.items():
            score = self.scorer.score(red_node, blue_node)
            if score > best_score:
                best_score = score
                best_red = red_node

        return best_red

    def _merge(self, blue_node: PTANode, red_node: PTANode) -> None:
        """Merge BLUE state into RED state."""
        self.node_merge_map[blue_node.node_id] = self.node_merge_map[red_node.node_id]

        # Transfer blue's children to red
        for label, child in blue_node.children.items():
            if label not in red_node.children:
                red_node.children[label] = child
                child.parent = red_node
            else:
                # Child exists in both — recursively merge
                existing = red_node.children[label]
                if existing.node_id != child.node_id:
                    self.node_merge_map[child.node_id] = self.node_merge_map.get(
                        existing.node_id,
                        self.node_merge_map.get(red_node.node_id, "MERGED")
                    )

        # Combine accept flags
        red_node.is_accepting = red_node.is_accepting or blue_node.is_accepting
        red_node.trace_count += blue_node.trace_count

    def _promote(self, blue_node: PTANode) -> None:
        """Promote BLUE state to RED."""
        self.red_states[blue_node.node_id] = blue_node
        state_name = f"S_{len(self.red_states) - 1}"
        self.node_merge_map[blue_node.node_id] = state_name

    def _build_fsm(self, protocol: str, fsm_name: str) -> ProtocolFSM:
        """Build ProtocolFSM from merged state space."""
        fsm = ProtocolFSM(protocol=protocol, name=fsm_name)

        # Collect unique merged states
        merged_states: Dict[str, MergedState] = {}
        for node_id, state_name in self.node_merge_map.items():
            if state_name not in merged_states:
                merged_states[state_name] = MergedState(name=state_name)
            node = self._find_node(node_id)
            if node:
                merged_states[state_name].original_nodes.add(node_id)
                merged_states[state_name].is_accepting = (
                    merged_states[state_name].is_accepting or node.is_accepting
                )

        # Set initial state — find the root node (depth 0)
        root_state_name = "INIT"
        if self.red_states:
            first_red_id = list(self.red_states.keys())[0]
            root_state_name = self.node_merge_map.get(first_red_id, "INIT")
        for node_id, state_name in self.node_merge_map.items():
            node = self._find_node(node_id)
            if node and node.depth == 0:
                root_state_name = state_name
                break

        # Build FSM states and transitions
        for name, ms in merged_states.items():
            fsm.add_state(
                name,
                is_initial=(name == root_state_name),
                is_accepting=ms.is_accepting,
            )

        # Build transitions by walking PTA again
        for red_id, red_node in self.red_states.items():
            from_state = self.node_merge_map.get(red_id, f"S_{red_id}")
            for label, child_node in red_node.children.items():
                to_state = self.node_merge_map.get(
                    child_node.node_id,
                    f"S_{child_node.node_id}"
                )
                if from_state != to_state:
                    existing = fsm.get_transition(from_state, to_state)
                    if existing is None:
                        fsm.add_transition(from_state, to_state, label)
                    else:
                        existing.probability = min(1.0, existing.probability + 0.1)

        return fsm

    def _find_node(self, node_id: int) -> Optional[PTANode]:
        """Find a PTA node by ID."""
        if node_id in self.red_states:
            return self.red_states[node_id]
        if node_id in self.blue_states:
            return self.blue_states[node_id]
        return None
