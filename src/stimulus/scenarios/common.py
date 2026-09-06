"""Common scenario definitions and utilities.

Each scenario produces a sequence of protocol messages
that represent a valid 5G procedure. These traces are used to:
  1. Train FSM models (FSMLearner learns state machines)
  2. Generate seed corpus (valid messages as fuzzing starting points)
  3. Validate codec round-trip correctness
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from src import ProtocolType, NFType


class Direction(Enum):
    UPLINK = "uplink"
    DOWNLINK = "downlink"


@dataclass
class ScenarioStep:
    """One step in a benign scenario trace."""
    message_type: str  # e.g., "Registration Request"
    direction: Direction
    protocol: ProtocolType
    fields: Dict[str, Any] = field(default_factory=dict)
    description: str = ""


@dataclass
class BenignScenario:
    """A complete benign scenario producing one or more traces."""
    name: str
    description: str
    protocol: ProtocolType
    procedure: str  # e.g., "registration", "pdu_session_establishment"
    steps: List[ScenarioStep] = field(default_factory=list)
    n_runs: int = 20  # How many trace variants to generate

    def as_trace_events(self) -> List[Dict[str, Any]]:
        """Convert steps to FSMLearner trace event dicts."""
        events = []
        for step in self.steps:
            events.append({
                "timestamp": 0.0,
                "message_type": step.message_type,
                "direction": step.direction.value,
                "protocol": step.protocol.value,
                "fields": step.fields,
            })
        return events

    def get_message_sequence(self) -> List[str]:
        """Return ordered list of message type names."""
        return [s.message_type for s in self.steps]

    def get_uplink_messages(self) -> List[ScenarioStep]:
        """Return only uplink (UE-to-network) messages."""
        return [s for s in self.steps if s.direction == Direction.UPLINK]

    def get_downlink_messages(self) -> List[ScenarioStep]:
        """Return only downlink (network-to-UE) messages."""
        return [s for s in self.steps if s.direction == Direction.DOWNLINK]
