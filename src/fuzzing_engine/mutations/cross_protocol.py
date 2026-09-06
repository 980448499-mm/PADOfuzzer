"""Cross-protocol payload injection mutation strategy.

Embeds payload from one protocol inside another protocol's message body,
testing parser isolation between protocol layers
(e.g., NAS-in-GTPU, PFCP-in-NGAP, SBI-in-NAS).
"""

from typing import Dict, List, Optional

from src import ProtocolType
from .base import MutationStrategy, MutationContext
from src.fuzzing_engine.seed_manager import Seed
from .bit_flip import BitFlipMutation


class CrossProtocolMutation(MutationStrategy):
    """Cross-protocol payload injection.

    Embeds payload from one protocol inside another protocol's field,
    testing parser isolation between NFs.
    """

    name = "cross_protocol"

    def __init__(self, protocol_pools: Optional[Dict[ProtocolType, List[bytes]]] = None):
        self.protocol_pools: Dict[ProtocolType, List[bytes]] = protocol_pools or {}

    def add_protocol_sample(self, proto: ProtocolType, pdu: bytes) -> None:
        """Add a sample PDU to the cross-protocol injection pool."""
        if proto not in self.protocol_pools:
            self.protocol_pools[proto] = []
        self.protocol_pools[proto].append(pdu)

    def mutate(self, seed: Seed, context: MutationContext) -> bytes:
        r = context.random
        target_proto = context.protocol

        other_protos = [p for p in self.protocol_pools if p != target_proto]
        if not other_protos or not seed.raw_pdu:
            return BitFlipMutation().mutate(seed, context)

        inject_from = r.choice(other_protos)
        inject_payloads = self.protocol_pools.get(inject_from, [])
        if not inject_payloads:
            return seed.raw_pdu

        inject_pdu = r.choice(inject_payloads)
        data = bytearray(seed.raw_pdu)

        # Injection strategies: middle-injection or append
        if len(data) > 8:
            inject_pos = r.randint(4, len(data) - 1)
            data = data[:inject_pos] + inject_pdu[:64] + data[inject_pos:]
        else:
            data.extend(inject_pdu[:64])

        return bytes(data)
