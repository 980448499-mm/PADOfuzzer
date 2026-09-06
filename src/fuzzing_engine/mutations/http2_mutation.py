"""HTTP/2 specific mutation strategy for SBI fuzzing.

Mutates JSON bodies, HPACK headers, HTTP/2 frame headers, and
Content-Type confusion attacks targeting the Service-Based Interface.
"""

import random

from .base import MutationStrategy, MutationContext
from src.fuzzing_engine.seed_manager import Seed
from .bit_flip import BitFlipMutation


class HTTP2Mutation(MutationStrategy):
    """HTTP/2 specific mutations for SBI fuzzing.

    Mutates JSON bodies, HTTP/2 frames, and content-type headers
    to test SBI endpoint robustness.
    """

    name = "http2"

    def mutate(self, seed: Seed, context: MutationContext) -> bytes:
        r = context.random
        choice = r.random()

        if choice < 0.3 and b"{" in seed.raw_pdu:
            return self._mutate_json(seed.raw_pdu, r)
        elif choice < 0.5:
            return self._mutate_http2_frame(seed.raw_pdu, r)
        elif choice < 0.7:
            return self._mutate_content_type(seed.raw_pdu)
        else:
            return BitFlipMutation().mutate(seed, context)

    def _mutate_json(self, data: bytes, r: random.Random) -> bytes:
        """Fuzz JSON body by injecting malformed values."""
        text = data.decode("utf-8", errors="replace")
        mutations = [
            text.replace('"', "'"),
            text + ',"__fuzz__":"' + "A" * 1024 + '"}',
            text.replace("true", '"INVALID_BOOL"'),
            text.replace("1", "999999999999999999999999999999"),
        ]
        result = r.choice(mutations)
        return result.encode("utf-8", errors="replace")

    def _mutate_http2_frame(self, data: bytes, r: random.Random) -> bytes:
        """Corrupt HTTP/2 frame headers (stream ID, flags, type)."""
        if len(data) < 9:
            return data
        result = bytearray(data)
        pos = r.choice([3, 4, 5])
        result[pos] = r.randint(0, 255)
        return bytes(result)

    def _mutate_content_type(self, data: bytes) -> bytes:
        """Change Content-Type to confuse endpoint parsing."""
        text = data.decode("utf-8", errors="replace")
        text = text.replace("application/json", "application/xml")
        text = text.replace("application/json", "application/octet-stream")
        return text.encode("utf-8", errors="replace")
