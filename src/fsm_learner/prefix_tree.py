"""Prefix Tree Acceptor (PTA) for FSM learning.

A PTA is a tree-shaped automaton where each path from root to a node
represents a sequence of observed protocol messages. Nodes are merged
during Blue-Fringe EDSM to generalize the learned FSM.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class PTANode:
    node_id: int
    label: str  # Message type that led to this node
    is_accepting: bool = False
    children: Dict[str, "PTANode"] = field(default_factory=dict)
    parent: Optional["PTANode"] = None
    incoming_label: str = ""  # Label of edge from parent to this node
    depth: int = 0
    trace_count: int = 0  # Number of traces passing through this node


class PrefixTreeAcceptor:
    """Builds a Prefix Tree Acceptor from protocol message traces.

    Each trace is a list of message type strings representing
    a complete protocol interaction (e.g., registration).

    Example trace for 5G Registration:
      ["RegistrationRequest", "AuthenticationRequest",
       "AuthenticationResponse", "SecurityModeCommand",
       "SecurityModeComplete", "RegistrationAccept",
       "RegistrationComplete"]
    """

    def __init__(self):
        self.nodes: List[PTANode] = []
        self._next_id = 1
        self.root = self._create_node("START", depth=0)

    def _create_node(self, label: str, parent: Optional[PTANode] = None,
                     depth: int = 0, is_accepting: bool = False) -> PTANode:
        node = PTANode(
            node_id=self._next_id,
            label=label,
            parent=parent,
            depth=depth,
            is_accepting=is_accepting,
        )
        self._next_id += 1
        self.nodes.append(node)
        return node

    def insert_trace(self, messages: List[str]) -> None:
        """Insert a message sequence into the PTA."""
        current = self.root
        current.trace_count += 1

        for i, msg in enumerate(messages):
            if msg not in current.children:
                child = self._create_node(
                    label=msg,
                    parent=current,
                    depth=current.depth + 1,
                )
                child.incoming_label = msg
                current.children[msg] = child

            current = current.children[msg]
            current.trace_count += 1

        current.is_accepting = True

    def insert_traces(self, traces: List[List[str]]) -> None:
        """Insert multiple traces."""
        for trace in traces:
            self.insert_trace(trace)

    def get_unique_prefixes(self) -> List[List[str]]:
        """Extract all unique paths from root to leaves."""
        paths: List[List[str]] = []

        def dfs(node: PTANode, current_path: List[str]) -> None:
            if node.is_accepting or not node.children:
                if current_path:
                    paths.append(list(current_path))
            for label, child in node.children.items():
                dfs(child, current_path + [label])

        dfs(self.root, [])
        return paths

    def get_total_traces(self) -> int:
        return self.root.trace_count

    def get_total_nodes(self) -> int:
        return len(self.nodes)
