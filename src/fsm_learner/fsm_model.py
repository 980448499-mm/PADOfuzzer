"""Finite State Machine model for protocol state tracking."""

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class FSMState:
    name: str
    is_initial: bool = False
    is_accepting: bool = False
    is_error: bool = False
    entry_actions: List[str] = field(default_factory=list)
    exit_actions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FSMTransition:
    from_state: str
    to_state: str
    trigger: str  # Message type that triggers this transition
    guard: Optional[str] = None  # Conditional expression
    probability: float = 1.0  # Observed probability of this transition
    timing_median_ms: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProtocolFSM:
    """Learned FSM for a single protocol procedure."""

    protocol: str
    name: str  # e.g., "5GMM Registration"
    states: Dict[str, FSMState] = field(default_factory=dict)
    transitions: List[FSMTransition] = field(default_factory=list)
    initial_state: Optional[str] = None
    message_type_map: Dict[int, str] = field(default_factory=dict)

    def add_state(self, name: str, **kwargs: Any) -> FSMState:
        state = FSMState(name=name, **kwargs)
        self.states[name] = state
        if kwargs.get("is_initial"):
            self.initial_state = name
        return state

    def add_transition(self, from_state: str, to_state: str, trigger: str,
                       **kwargs: Any) -> FSMTransition:
        if from_state not in self.states:
            self.add_state(from_state)
        if to_state not in self.states:
            self.add_state(to_state)
        t = FSMTransition(from_state=from_state, to_state=to_state,
                          trigger=trigger, **kwargs)
        self.transitions.append(t)
        return t

    def get_transition(self, from_state: str, to_state: str) -> Optional[FSMTransition]:
        for t in self.transitions:
            if t.from_state == from_state and t.to_state == to_state:
                return t
        return None

    def get_outgoing(self, state: str) -> List[FSMTransition]:
        return [t for t in self.transitions if t.from_state == state]

    def get_incoming(self, state: str) -> List[FSMTransition]:
        return [t for t in self.transitions if t.to_state == state]

    def get_allowed_messages(self, state: str) -> List[str]:
        return [t.trigger for t in self.get_outgoing(state)]

    def get_forbidden_messages(self, state: str) -> List[str]:
        """Messages NOT allowed in this state (for negative testing)."""
        allowed = set(self.get_allowed_messages(state))
        all_msgs = set(self.message_type_map.values())
        return list(all_msgs - allowed)

    def shortest_path(self, from_state: str, to_state: str) -> List[str]:
        """BFS shortest path between two states."""
        if from_state not in self.states or to_state not in self.states:
            return []

        queue = deque([(from_state, [from_state])])
        visited = {from_state}

        while queue:
            current, path = queue.popleft()
            if current == to_state:
                return path

            for t in self.get_outgoing(current):
                if t.to_state not in visited:
                    visited.add(t.to_state)
                    queue.append((t.to_state, path + [t.to_state]))

        return []

    def state_depth(self, state_name: str) -> int:
        """Compute depth from initial state."""
        path = self.shortest_path(self.initial_state or "", state_name)
        return len(path) - 1 if path else 0

    def get_rare_states(self, visit_counts: Dict[str, int],
                        threshold_visits: int = 5) -> List[str]:
        """Return states visited fewer times than threshold."""
        return [s for s in self.states
                if visit_counts.get(s, 0) < threshold_visits]

    def to_mermaid(self) -> str:
        """Export FSM as Mermaid diagram for visualization."""
        lines = ["stateDiagram-v2"]
        for state_name in self.states:
            lines.append(f"    {state_name}")
        for t in self.transitions:
            prob = f" ({t.probability:.2f})" if t.probability < 1.0 else ""
            lines.append(f"    {t.from_state} --> {t.to_state} : {t.trigger}{prob}")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "protocol": self.protocol,
            "name": self.name,
            "states": {n: {
                "is_initial": s.is_initial,
                "is_accepting": s.is_accepting,
                "is_error": s.is_error,
            } for n, s in self.states.items()},
            "transitions": [{
                "from": t.from_state,
                "to": t.to_state,
                "trigger": t.trigger,
                "probability": t.probability,
            } for t in self.transitions],
            "initial_state": self.initial_state,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProtocolFSM":
        fsm = cls(
            protocol=data["protocol"],
            name=data["name"],
        )
        for name, info in data["states"].items():
            fsm.add_state(name, **info)
        for t_data in data["transitions"]:
            fsm.add_transition(
                t_data["from"], t_data["to"], t_data["trigger"],
                probability=t_data.get("probability", 1.0),
            )
        fsm.initial_state = data.get("initial_state")
        return fsm
