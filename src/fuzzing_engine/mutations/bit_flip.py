"""AFL-style bit/byte/word flip mutation strategy."""

import random
from typing import TYPE_CHECKING

from .base import MutationStrategy, MutationContext
from src.fuzzing_engine.seed_manager import Seed


class BitFlipMutation(MutationStrategy):
    """AFL-style bit/byte/word flips with variable magnitude."""

    name = "bit_flip"

    def mutate(self, seed: Seed, context: MutationContext) -> bytes:
        data = bytearray(seed.raw_pdu)
        if not data:
            return bytes([0xFF])
        r = context.random

        choice = r.random()
        if choice < 0.4:
            byte_pos = r.randint(0, len(data) - 1)
            bit_pos = r.randint(0, 7)
            data[byte_pos] ^= 1 << bit_pos
        elif choice < 0.7:
            byte_pos = r.randint(0, len(data) - 1)
            data[byte_pos] = r.randint(0, 255)
        elif choice < 0.9:
            if len(data) >= 2:
                pos = r.randint(0, len(data) - 2)
                val = r.randint(0, 65535)
                data[pos : pos + 2] = val.to_bytes(2, "big")
        else:
            if len(data) > 4:
                start = r.randint(0, len(data) - 4)
                end = r.randint(start + 1, min(start + 16, len(data)))
                del data[start:end]

        return bytes(data)
