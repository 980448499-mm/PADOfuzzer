"""GTP-U stimulus client — injects GTP-U packets on N3/N9 interfaces.

Sends GTP-U messages to UPF via UDP (N3 port 2152).
Supports G-PDU (user data), Echo, Error Indication, and End Marker messages.
"""

import asyncio
import logging
import socket
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from src.codec.gtpu_codec import GTPUCodec, GTPU_MESSAGE_TYPES, GTPUHeader
from src.codec.base import ParsedMessage

logger = logging.getLogger(__name__)


@dataclass
class GTPUResponse:
    message_type: str
    teid: int
    fields: Dict[str, Any]
    raw_bytes: bytes
    latency_ms: float


class GTPUClient:
    """GTP-U client for N3/N9 user-plane fuzzing.

    Simulates gNB or I-UPF sending GTP-U packets.
    Supports:
      - G-PDU tunneling (user data)
      - Echo/Echo Response path management
      - Error Indication testing
      - Extension header injection
    """

    def __init__(self, upf_host: str = "127.0.0.1", upf_port: int = 2152,
                 teid: int = 0):
        self.upf_host = upf_host
        self.upf_port = upf_port
        self.teid = teid
        self.sequence_number = 0
        self.codec = GTPUCodec()
        self._sock: Optional[socket.socket] = None

    async def connect(self) -> bool:
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.settimeout(5.0)
            logger.info(f"GTP-U client bound to {self.upf_host}:{self.upf_port}")
            return True
        except OSError as e:
            logger.error(f"GTP-U socket creation failed: {e}")
            return False

    async def close(self) -> None:
        if self._sock:
            self._sock.close()
            self._sock = None

    # ─── High-level operations ────────────────────────────────────

    async def send_gpdu(self, teid: int, t_pdu: bytes) -> Optional[GTPUResponse]:
        """Send a G-PDU (user-plane data packet)."""
        hdr = GTPUHeader(
            version=1, pt=1, msg_type=0, teid=teid,
            seq_no=self._next_seq(), has_seq=True, payload=t_pdu,
        )
        return await self.send_raw(hdr.encode() + t_pdu)

    async def echo_request(self) -> Optional[GTPUResponse]:
        """Send GTP-U Echo Request for path management."""
        msg = self.codec.random_valid("Echo Request")
        return await self.send_msg(msg)

    async def error_indication(self, teid: int, offending_data: bytes = b""
                                ) -> Optional[GTPUResponse]:
        """Send Error Indication (for testing error handling)."""
        msg = ParsedMessage(
            protocol="gtp-u",
            message_type="Error Indication",
            message_name="Error Indication",
            fields={
                "teid": teid,
                "t_pdu": offending_data,
            },
        )
        return await self.send_msg(msg)

    async def end_marker(self, teid: int) -> Optional[GTPUResponse]:
        """Send End Marker (for path switch testing)."""
        msg = self.codec.random_valid("End Marker")
        msg.fields["teid"] = teid
        return await self.send_msg(msg)

    # ─── Raw fuzzing interface ────────────────────────────────────

    async def send_msg(self, msg: ParsedMessage) -> Optional[GTPUResponse]:
        """Encode and send a GTP-U message."""
        if not self._sock:
            return None

        msg.fields.setdefault("teid", self.teid)
        if "sequence_number" not in msg.fields:
            msg.fields["sequence_number"] = self._next_seq()

        encoded = self.codec.encode(msg)
        return await self.send_raw(encoded)

    async def send_raw(self, data: bytes) -> Optional[GTPUResponse]:
        """Send raw GTP-U bytes and capture response."""
        if not self._sock:
            return None

        import time as _time
        start = _time.monotonic()

        try:
            self._sock.sendto(data, (self.upf_host, self.upf_port))
            resp_data, addr = self._sock.recvfrom(65535)
            latency = (_time.monotonic() - start) * 1000

            decoded = self.codec.decode(resp_data)
            return GTPUResponse(
                message_type=decoded.message_type,
                teid=decoded.fields.get("teid", 0),
                fields=decoded.fields,
                raw_bytes=resp_data,
                latency_ms=latency,
            )
        except socket.timeout:
            logger.debug("GTP-U response timeout")
            return None
        except OSError as e:
            logger.error(f"GTP-U send/recv error: {e}")
            return None

    # ─── Fuzzing helpers ──────────────────────────────────────────

    async def inject_extension_header_attack(self, base_gpdu: bytes,
                                              ext_type: int,
                                              malformed_content: bytes) -> bytes:
        """Inject a malformed extension header for fuzzing.

        Returns the modified bytes (caller must send_raw).
        """
        return self.codec.inject_extension_header(base_gpdu, ext_type, malformed_content)

    async def teid_spoofing_attack(self, base_gpdu: bytes, spoofed_teid: int) -> bytes:
        """Replace TEID with a spoofed value."""
        return self.codec.corrupt_teid(base_gpdu, spoofed_teid)

    async def length_corruption_attack(self, base_data: bytes) -> bytes:
        """Corrupt GTP-U length field."""
        return self.codec.corrupt_length(base_data)

    async def wrap_as_gpdu(self, teid: int, payload: bytes) -> bytes:
        """Wrap arbitrary payload as G-PDU for N3 injection."""
        return self.codec.wrap_payload_as_gpdu(teid, payload, self._next_seq())

    # ─── Helpers ─────────────────────────────────────────────────

    def _next_seq(self) -> int:
        self.sequence_number = (self.sequence_number + 1) & 0xFFFF
        return self.sequence_number

    @staticmethod
    def get_available_messages() -> List[str]:
        return list(GTPU_MESSAGE_TYPES.values())
