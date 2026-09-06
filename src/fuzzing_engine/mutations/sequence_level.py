"""Sequence-level mutation strategy.

Mutates at the message sequence level rather than individual PDUs.
Operations include reordering, duplication, omission, and interleaving
of protocol messages to test state machine robustness.
"""

from typing import List

from .base import MutationStrategy, MutationContext
from src.fuzzing_engine.seed_manager import Seed


class SequenceLevelMutation(MutationStrategy):
    """Mutate at the message sequence level.

    Operations: reorder, duplicate, omit, insert, interleave sessions.
    """

    name = "sequence_level"

    def __init__(self, max_sequence_length: int = 8):
        self.max_sequence_length = max_sequence_length
        self._sequence_buffer: List[bytes] = []

    def push_to_sequence(self, pdu: bytes) -> None:
        """Add a PDU to the sequence buffer for sequence-level mutations."""
        self._sequence_buffer.append(pdu)
        if len(self._sequence_buffer) > self.max_sequence_length:
            self._sequence_buffer = self._sequence_buffer[-self.max_sequence_length:]

    def mutate(self, seed: Seed, context: MutationContext) -> bytes:
        r = context.random
        self.push_to_sequence(seed.raw_pdu)

        if len(self._sequence_buffer) < 2:
            return seed.raw_pdu

        operation = r.choice(["reorder", "duplicate", "omit", "interleave"])

        if operation == "reorder" and len(self._sequence_buffer) >= 2:
            seq = list(self._sequence_buffer)
            i, j = r.randint(0, len(seq) - 1), r.randint(0, len(seq) - 1)
            seq[i], seq[j] = seq[j], seq[i]
            return seq[-1]

        elif operation == "duplicate":
            return self._sequence_buffer[-1]

        elif operation == "omit":
            if len(self._sequence_buffer) >= 2:
                return self._sequence_buffer[-2]
            return seed.raw_pdu

        elif operation == "interleave":
            if len(self._sequence_buffer) >= 2:
                a = self._sequence_buffer[-1]
                b = self._sequence_buffer[-2]
                min_len = min(len(a), len(b))
                interleaved = bytes(x ^ y for x, y in zip(a[:min_len], b[:min_len]))
                return interleaved or seed.raw_pdu

        return seed.raw_pdu
