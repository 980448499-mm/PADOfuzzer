"""Field-aware structure-preserving mutations that maintain protocol structure.

Decodes the message, mutates specific fields, then re-encodes.
"""

import copy
import random
from typing import TYPE_CHECKING

from .base import MutationStrategy, MutationContext
from src.fuzzing_engine.seed_manager import Seed


class StructurePreservingMutation(MutationStrategy):
    """Field-aware mutations that maintain protocol structure."""

    name = "structure_preserving"

    def mutate(self, seed: Seed, context: MutationContext) -> bytes:
        codec = context.codec
        if codec is None or seed.parsed_message is None:
            from .bit_flip import BitFlipMutation
            return BitFlipMutation().mutate(seed, context)

        msg = copy.deepcopy(seed.parsed_message)
        r = context.random

        if not msg.fields:
            return seed.raw_pdu

        field_name = r.choice(list(msg.fields.keys()))
        field_value = msg.fields[field_name]

        if isinstance(field_value, int):
            msg.fields[field_name] = self._mutate_int(field_value, r)
        elif isinstance(field_value, bytes):
            msg.fields[field_name] = self._mutate_bytes(field_value, r)
        elif isinstance(field_value, str):
            msg.fields[field_name] = self._mutate_str(field_value, r)
        elif isinstance(field_value, dict):
            if field_value:
                sub_key = r.choice(list(field_value.keys()))
                sub_val = field_value[sub_key]
                if isinstance(sub_val, bytes):
                    field_value[sub_key] = self._mutate_bytes(sub_val, r)

        try:
            return codec.encode(msg)
        except Exception:
            return seed.raw_pdu

    @staticmethod
    def _mutate_int(value: int, r: random.Random) -> int:
        strategies = [
            lambda v: v + 1,
            lambda v: v - 1,
            lambda v: 0,
            lambda v: -1,
            lambda v: 2**32 - 1,
            lambda v: 2**32,
            lambda v: r.randint(0, 65535),
            lambda v: v ^ (1 << r.randint(0, 31)),
        ]
        return r.choice(strategies)(value)

    @staticmethod
    def _mutate_bytes(value: bytes, r: random.Random) -> bytes:
        if not value:
            return b"\xFF" * r.randint(1, 8)
        data = bytearray(value)
        strategies = [
            lambda d: d[: len(d) // 2],
            lambda d: d + bytes([r.randint(0, 255)] * r.randint(1, 16)),
            lambda d: bytes([r.randint(0, 255) for _ in range(len(d))]),
        ]
        return r.choice(strategies)(data)

    @staticmethod
    def _mutate_str(value: str, r: random.Random) -> str:
        if not value:
            return "FUZZED"
        pos = r.randint(0, len(value) - 1)
        result = list(value)
        result[pos] = chr(r.randint(0, 127))
        return "".join(result)
