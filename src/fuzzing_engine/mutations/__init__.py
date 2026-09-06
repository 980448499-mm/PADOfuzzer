"""Mutation strategy modules for the 5G protocol fuzzing engine.

Six strategies are provided:
  1. BitFlipMutation — AFL-style bit/byte/word flips
  2. StructurePreservingMutation — field-aware protocol structure mutations
  3. StateAwareMutation — FSM state-guided invalid transition injection
  4. CrossProtocolMutation — cross-protocol payload embedding
  5. SequenceLevelMutation — message sequence reorder/duplicate/omit/interleave
  6. HTTP2Mutation — HTTP/2 + JSON SBI-specific fuzzing
"""

from .bit_flip import BitFlipMutation
from .structure_preserving import StructurePreservingMutation
from .state_aware import StateAwareMutation
from .cross_protocol import CrossProtocolMutation
from .sequence_level import SequenceLevelMutation
from .http2_mutation import HTTP2Mutation

__all__ = [
    "BitFlipMutation",
    "StructurePreservingMutation",
    "StateAwareMutation",
    "CrossProtocolMutation",
    "SequenceLevelMutation",
    "HTTP2Mutation",
]
