"""PFCP stimulus client — injects PFCP messages on the N4 interface.

Connects to UPF via UDP (N4), sends fuzzed PFCP messages,
and captures responses for coverage/crash analysis.
"""

import asyncio
import logging
import socket
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from src.codec.pfcp_codec import PFCPCodec, PFCP_MESSAGE_TYPES
from src.codec.base import ParsedMessage

logger = logging.getLogger(__name__)


@dataclass
class PFCPResponse:
    message_type: str
    fields: Dict[str, Any]
    raw_bytes: bytes
    latency_ms: float


class PFCPClient:
    """PFCP N4 client for fuzzing SMF-UPF communication.

    Supports:
      - PFCP Association Setup/Update/Release
      - PFCP Session Establishment/Modification/Deletion
      - Raw PFCP message injection for fuzzing
    """

    def __init__(self, upf_host: str = "127.0.0.1", upf_port: int = 8805,
                 seid: int = 0):
        self.upf_host = upf_host
        self.upf_port = upf_port
        self.seid = seid
        self.sequence_number = 0
        self.codec = PFCPCodec()
        self._sock: Optional[socket.socket] = None
        self._session_seid: int = 0

    # ─── Connection management ───────────────────────────────────

    async def connect(self) -> bool:
        """Create UDP socket for PFCP communication."""
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.settimeout(5.0)
            logger.info(f"PFCP client bound to {self.upf_host}:{self.upf_port}")
            return True
        except OSError as e:
            logger.error(f"PFCP socket creation failed: {e}")
            return False

    async def close(self) -> None:
        if self._sock:
            self._sock.close()
            self._sock = None

    # ─── High-level operations ────────────────────────────────────

    async def association_setup(self, node_id: bytes,
                                 recovery_time: int) -> Optional[PFCPResponse]:
        """Perform PFCP Association Setup."""
        msg = ParsedMessage(
            protocol="pfcp",
            message_type="PFCP Association Setup Request",
            message_name="PFCP Association Setup Request",
            fields={
                "node_id": node_id,
                "recovery_time_stamp": recovery_time,
                "node_features": 0x0F,
            },
        )
        return await self.send_msg(msg)

    async def session_establishment(self, pdr_rules: List[bytes],
                                     far_rules: List[bytes],
                                     qer_rules: Optional[List[bytes]] = None
                                     ) -> Optional[PFCPResponse]:
        """Establish a PFCP session on N4."""
        fields: Dict[str, Any] = {
            "node_id": socket.inet_aton(self.upf_host),
            "f_seid": struct.pack("!QQ", self.seid, 0),
        }
        for i, pdr in enumerate(pdr_rules):
            fields[f"create_pdr_{i}"] = pdr
        for i, far in enumerate(far_rules):
            fields[f"create_far_{i}"] = far
        if qer_rules:
            for i, qer in enumerate(qer_rules):
                fields[f"create_qer_{i}"] = qer

        msg = ParsedMessage(
            protocol="pfcp",
            message_type="PFCP Session Establishment Request",
            message_name="PFCP Session Establishment Request",
            fields=fields,
        )
        return await self.send_msg(msg)

    # ─── Raw fuzzing interface ────────────────────────────────────

    async def send_msg(self, msg: ParsedMessage) -> Optional[PFCPResponse]:
        """Encode and send a PFCP message, await response."""
        if not self._sock:
            logger.error("PFCP socket not connected")
            return None

        msg.fields.setdefault("seid", self._session_seid)
        msg.fields["sequence_number"] = self._next_seq()

        encoded = self.codec.encode(msg)
        return await self.send_raw(encoded)

    async def send_raw(self, data: bytes) -> Optional[PFCPResponse]:
        """Send raw PFCP bytes and capture response."""
        if not self._sock:
            return None

        import time as _time
        start = _time.monotonic()

        try:
            self._sock.sendto(data, (self.upf_host, self.upf_port))
            resp_data, addr = self._sock.recvfrom(65535)
            latency = (_time.monotonic() - start) * 1000

            decoded = self.codec.decode(resp_data)
            return PFCPResponse(
                message_type=decoded.message_type,
                fields=decoded.fields,
                raw_bytes=resp_data,
                latency_ms=latency,
            )
        except socket.timeout:
            logger.debug("PFCP response timeout (may be expected for crash detection)")
            return None
        except OSError as e:
            logger.error(f"PFCP send/recv error: {e}")
            return None

    async def send_without_response(self, data: bytes) -> bool:
        """Send PFCP data without expecting a response (for crash injection)."""
        if not self._sock:
            return False
        try:
            self._sock.sendto(data, (self.upf_host, self.upf_port))
            return True
        except OSError:
            return False

    # ─── Fuzzing helpers ──────────────────────────────────────────

    async def fuzz_session_setup(self, mutated_pdu: bytes) -> Optional[PFCPResponse]:
        """Inject a mutated PFCP Session Establishment message.

        Used by the fuzzing engine to test UPF session handling.
        """
        return await self.send_raw(mutated_pdu)

    async def inject_malformed_tlv(self, base_msg: ParsedMessage,
                                    ie_type: int, malformed_value: bytes
                                    ) -> Optional[PFCPResponse]:
        """Inject a malformed TLV IE into a valid message."""
        encoded = self.codec.encode(base_msg)
        corrupted = self.codec.inject_unknown_ie(encoded, ie_type, malformed_value)
        return await self.send_raw(corrupted)

    # ─── Helpers ─────────────────────────────────────────────────

    def _next_seq(self) -> int:
        self.sequence_number = (self.sequence_number + 1) & 0xFFFFFF
        return self.sequence_number

    @staticmethod
    def get_available_messages() -> List[str]:
        return list(PFCP_MESSAGE_TYPES.values())
