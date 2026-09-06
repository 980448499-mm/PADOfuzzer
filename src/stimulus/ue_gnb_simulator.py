r"""UE/gNB Simulator for 5G protocol fuzzing.

Implements a simulated UE + gNB that:
  1. Establishes SCTP association with AMF (N2 interface)
  2. Performs 5G registration (NGAP InitialUEMessage → NAS Registration)
  3. Handles authentication (AKA, Security Mode Command)
  4. Establishes PDU Sessions
  5. Supports raw NGAP/NAS injection for fuzzing

Transport: SCTP (Linux kernel SCTP or lksctp-tools wrapper)
Protocols: NGAP (N2) + NAS (N1)
"""

import asyncio
import logging
import socket
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from uuid import uuid4

from src.codec.nas_codec import (
    EPD_5GMM,
    FIVEGMM_MSG_TYPES_REV,
    NAS5GSCodec,
)
from src.codec.ngap_codec import NGAPCodec
from src.codec.base import ParsedMessage
from src.stimulus.nas_security import (
    NASMessageProtector,
    SecurityContext,
    SecurityContextFactory,
)

logger = logging.getLogger(__name__)


# ─── UE State Machine ───

class UERegistrationState(Enum):
    DEREGISTERED = "deregistered"
    REGISTERING = "registering"
    AUTHENTICATING = "authenticating"
    SECURING = "securing"  # Security Mode procedure
    REGISTERED = "registered"
    PDU_SESSION_ACTIVE = "pdu_session_active"


@dataclass
class PDUSessionContext:
    pdu_session_id: int
    dnn: str
    s_nssai: bytes  # SST + SD
    pdu_session_type: int  # 1=IPv4, 2=IPv6, 3=IPv4v6
    ssc_mode: int
    state: str = "inactive"  # inactive, active, released


@dataclass
class UEContext:
    """State for a single simulated UE."""

    supi: str  # IMSI
    guti: Optional[str] = None
    security_context: SecurityContext = field(default_factory=SecurityContext)
    current_state: UERegistrationState = UERegistrationState.DEREGISTERED
    pdu_sessions: Dict[int, PDUSessionContext] = field(default_factory=dict)
    amf_ue_ngap_id: Optional[int] = None
    ran_ue_ngap_id: int = field(default_factory=lambda: hash(str(uuid4())) & 0xFFFFFFFF)
    tai: bytes = b"\x00\xF1\x10\x00\x00\x01"  # Default TAI


# ─── SCTP Transport ───

class SCTPTransport:
    """SCTP transport for NGAP (N2 interface).

    Uses Linux kernel SCTP via socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP).
    Falls back to TCP for environments without SCTP kernel module.
    """

    def __init__(self, local_addr: str = "127.0.0.1", local_port: int = 0):
        self.local_addr = local_addr
        self.local_port = local_port
        self.sock: Optional[socket.socket] = None
        self._use_sctp = self._check_sctp_support()

    @staticmethod
    def _check_sctp_support() -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM,
                              socket.IPPROTO_SCTP)
            s.close()
            return True
        except (OSError, AttributeError):
            return False

    def connect(self, remote_addr: str, remote_port: int = 38412) -> None:
        if self._use_sctp:
            self._connect_sctp(remote_addr, remote_port)
        else:
            self._connect_tcp(remote_addr, remote_port)

    def _connect_sctp(self, remote_addr: str, remote_port: int) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM,
                                  socket.IPPROTO_SCTP)
        # SCTP-specific: enable SCTP events for association state changes
        try:
            import sctp as sctp_mod
            self.sock.setsockopt(socket.IPPROTO_SCTP,
                                sctp_mod.SCTP_EVENTS,
                                struct.pack("@8B", 0, 0, 0, 0, 0, 0, 1, 0))
        except ImportError:
            pass
        self.sock.connect((remote_addr, remote_port))

    def _connect_tcp(self, remote_addr: str, remote_port: int) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((remote_addr, remote_port))

    def send(self, data: bytes) -> int:
        if self.sock is None:
            raise RuntimeError("SCTP transport not connected")
        return self.sock.send(data)

    def recv(self, bufsize: int = 65536) -> bytes:
        if self.sock is None:
            raise RuntimeError("SCTP transport not connected")
        return self.sock.recv(bufsize)

    def settimeout(self, timeout: float) -> None:
        if self.sock:
            self.sock.settimeout(timeout)

    def close(self) -> None:
        if self.sock:
            self.sock.close()
            self.sock = None

    @property
    def is_connected(self) -> bool:
        return self.sock is not None


# ─── UE/gNB Simulator ───

class UEGNBSimulator:
    """Simulated UE + gNB for 5G fuzzing.

    Usage:
        sim = UEGNBSimulator(amf_addr="192.168.1.10")
        await sim.connect()
        result = await sim.register_ue("001010123456789")
        pdu = await sim.establish_pdu_session(...)
        # For fuzzing:
        await sim.send_raw_nas(fuzzed_nas_bytes)
    """

    def __init__(
        self,
        amf_addr: str = "127.0.0.1",
        amf_port: int = 38412,
        codec: Optional[NGAPCodec] = None,
        nas_codec: Optional[NAS5GSCodec] = None,
    ):
        self.amf_addr = amf_addr
        self.amf_port = amf_port
        self.transport = SCTPTransport()
        self.ngap_codec = codec or NGAPCodec()
        self.nas_codec = nas_codec or NAS5GSCodec()
        self.ues: Dict[str, UEContext] = {}
        self._ngap_id_counter = 0
        self._connected = False

    # ─── Connection management ────────────────────────────────

    def connect(self) -> None:
        """Establish SCTP association with AMF."""
        self.transport.connect(self.amf_addr, self.amf_port)
        self._connected = True
        logger.info(f"Connected to AMF at {self.amf_addr}:{self.amf_port}")

    def disconnect(self) -> None:
        self.transport.close()
        self._connected = False

    # ─── Registration procedure ───────────────────────────────

    def register_ue(
        self,
        supi: str,
        plmn: bytes = bytes([0x00, 0xF1, 0x10]),
    ) -> UEContext:
        """Perform full 5G registration procedure.

        Steps:
          1. Send NGAP InitialUEMessage (NAS Registration Request)
          2. Receive Authentication Request, send Authentication Response
          3. Receive Security Mode Command, send Security Mode Complete
          4. Receive Registration Accept, send Registration Complete

        Args:
            supi: IMSI string (e.g., "001010123456789")
            plmn: PLMN encoded as 3 bytes (MCC+MNC)

        Returns:
            UEContext with registration state
        """
        ue = UEContext(supi=supi)
        ue.current_state = UERegistrationState.REGISTERING
        self.ues[supi] = ue

        # Step 1: Send Registration Request via NGAP InitialUEMessage
        reg_req = self._build_registration_request(supi)
        ngap_init = self.ngap_codec.encode(
            ParsedMessage(
                protocol="ngap",
                message_type="InitialUEMessage",
                message_name="InitialUEMessage",
                fields={
                    "pdu_type": "INITIATING",
                    "procedure_code": 17,  # InitialUEMessage
                    "criticality": 0,
                    "ran_ue_ngap_id": ue.ran_ue_ngap_id,
                    "nas_pdu": reg_req,
                },
            )
        )
        self.transport.send(ngap_init)
        logger.debug(f"Sent InitialUEMessage (Registration Request) for {supi}")

        # Step 2-4: Handle response messages
        self._handle_registration_response(ue)

        return ue

    def _handle_registration_response(self, ue: UEContext) -> None:
        """Process AMF responses for registration."""
        try:
            self.transport.settimeout(5.0)

            # Step 2: Auth Request → Auth Response
            while ue.current_state == UERegistrationState.REGISTERING:
                raw = self.transport.recv()
                ngap_msg = self.ngap_codec.decode(raw)
                nas_pdu = ngap_msg.fields.get("NAS-PDU", b"")
                if nas_pdu:
                    nas_msg = self.nas_codec.decode(nas_pdu)
                    self._process_nas_response(ue, nas_msg, nas_pdu)

        except socket.timeout:
            logger.warning(f"Timeout during registration for {ue.supi}")
        finally:
            self.transport.settimeout(None)

    def _process_nas_response(
        self, ue: UEContext, nas_msg: ParsedMessage, raw_nas: bytes
    ) -> None:
        """Process a NAS response message during registration."""
        msg_type = nas_msg.message_type

        if msg_type == "Authentication Request":
            ue.current_state = UERegistrationState.AUTHENTICATING
            rand = nas_msg.fields.get("authentication_parameter_rand", b"\x00" * 16)
            autn = nas_msg.fields.get("authentication_parameter_autn", b"\x00" * 16)
            self._send_authentication_response(ue, rand, autn)

        elif msg_type == "Security Mode Command":
            ue.current_state = UERegistrationState.SECURING
            self._handle_security_mode_command(ue, nas_msg)
            self._send_security_mode_complete(ue)

        elif msg_type == "Registration Accept":
            ue.current_state = UERegistrationState.REGISTERED
            ue.guti = nas_msg.fields.get("5g_guti")
            self._send_registration_complete(ue)
            logger.info(f"UE {ue.supi} registered successfully")

        elif msg_type == "Registration Reject":
            ue.current_state = UERegistrationState.DEREGISTERED
            cause = nas_msg.fields.get("5gmm_cause")
            logger.warning(f"Registration rejected for {ue.supi}: cause={cause}")

    # ─── NAS message builders and senders ──────────────────────

    def _build_registration_request(self, supi: str) -> bytes:
        """Build a NAS Registration Request message."""
        return self.nas_codec.encode(
            ParsedMessage(
                protocol="nas-5gs",
                message_type="Registration Request",
                message_name="Registration Request",
                fields={
                    "5gs_registration_type": 1,  # Initial Registration
                    "ng_ksi": 0,
                    "5gs_mobile_identity_supi": supi,
                },
            )
        )

    def _send_authentication_response(
        self, ue: UEContext, rand: bytes, autn: bytes
    ) -> None:
        """Compute and send Authentication Response."""
        sec_ctx, success = SecurityContextFactory.create_from_aka(rand, autn)
        if not success:
            logger.error(f"AKA authentication failed for {ue.supi}")
            self._send_authentication_failure(ue, cause=0x15)  # MAC failure
            return

        ue.security_context = sec_ctx

        auth_resp = self.nas_codec.encode(
            ParsedMessage(
                protocol="nas-5gs",
                message_type="Authentication Response",
                message_name="Authentication Response",
                fields={
                    "authentication_response_parameter": sec_ctx.res or b"",
                },
            )
        )
        self._send_uplink_nas(ue, auth_resp)
        logger.debug(f"Sent Authentication Response for {ue.supi}")

    def _send_authentication_failure(self, ue: UEContext, cause: int = 0x15) -> None:
        msg = self.nas_codec.encode(
            ParsedMessage(
                protocol="nas-5gs",
                message_type="Authentication Failure",
                message_name="Authentication Failure",
                fields={"5gmm_cause": cause},
            )
        )
        self._send_uplink_nas(ue, msg)

    def _handle_security_mode_command(
        self, ue: UEContext, nas_msg: ParsedMessage
    ) -> None:
        """Derive security keys from selected algorithms."""
        # Selected algorithms from network
        replayed_nas = nas_msg.fields.get("nas_message_container", b"")
        self._verify_security_mode_complete_mac(ue, replayed_nas)

    def _verify_security_mode_complete_mac(
        self, ue: UEContext, replayed: bytes
    ) -> None:
        """Verify Security Mode Complete via replayed NAS container."""
        protector = NASMessageProtector(ue.security_context)
        _, verified = protector.protect_downlink(replayed)
        if not verified:
            logger.warning(f"MAC verification failed in SMC for {ue.supi}")

    def _send_security_mode_complete(self, ue: UEContext) -> None:
        """Send Security Mode Complete."""
        smc = self.nas_codec.encode(
            ParsedMessage(
                protocol="nas-5gs",
                message_type="Security Mode Complete",
                message_name="Security Mode Complete",
                fields={},
            )
        )
        # If security established, protect the message
        if ue.security_context.security_established:
            protector = NASMessageProtector(ue.security_context)
            epd = EPD_5GMM
            mt = FIVEGMM_MSG_TYPES_REV["Security Mode Complete"]
            # Message type byte + IEs
            payload = bytes([mt]) + smc[smc.index(bytes([mt])) + 1 :] if bytes([mt]) in smc else smc
            # Rebuild properly
            payload = smc[2:]  # Strip EPD + security header
            protected = protector.protect_uplink(EPD_5GMM, mt, payload[1:] if len(payload) > 1 else b"")
            smc = protected

        self._send_uplink_nas(ue, smc)

    def _send_registration_complete(self, ue: UEContext) -> None:
        """Send Registration Complete."""
        reg_complete = self.nas_codec.encode(
            ParsedMessage(
                protocol="nas-5gs",
                message_type="Registration Complete",
                message_name="Registration Complete",
                fields={},
            )
        )
        if ue.security_context.security_established:
            protector = NASMessageProtector(ue.security_context)
            mt = FIVEGMM_MSG_TYPES_REV["Registration Complete"]
            payload = b"\x00"  # No IEs
            protected = protector.protect_uplink(EPD_5GMM, mt, payload)
            reg_complete = protected

        self._send_uplink_nas(ue, reg_complete)
        logger.info(f"Sent Registration Complete for {ue.supi}")

    def _send_uplink_nas(self, ue: UEContext, nas_pdu: bytes) -> None:
        """Wrap NAS PDU in NGAP UplinkNASTransport and send."""
        amf_id = ue.amf_ue_ngap_id or 0
        ngap_ul = self.ngap_codec.encode(
            ParsedMessage(
                protocol="ngap",
                message_type="UplinkNASTransport",
                message_name="UplinkNASTransport",
                fields={
                    "pdu_type": "INITIATING",
                    "procedure_code": 17,
                    "criticality": 0,
                    "amf_ue_ngap_id": amf_id,
                    "ran_ue_ngap_id": ue.ran_ue_ngap_id,
                    "nas_pdu": nas_pdu,
                },
            )
        )
        self.transport.send(ngap_ul)

    # ─── PDU Session Establishment ────────────────────────────

    def establish_pdu_session(
        self,
        ue: UEContext,
        dnn: str = "internet",
        s_nssai_sst: int = 1,
        s_nssai_sd: int = 0xFFFFFF,
        pdu_session_type: int = 1,  # IPv4
        ssc_mode: int = 1,
    ) -> Optional[PDUSessionContext]:
        """Establish a PDU session for a registered UE."""
        if ue.current_state != UERegistrationState.REGISTERED:
            logger.error(f"UE {ue.supi} not in REGISTERED state")
            return None

        pdu_session_id = self._next_pdu_session_id(ue)
        pdu = PDUSessionContext(
            pdu_session_id=pdu_session_id,
            dnn=dnn,
            s_nssai=struct.pack("!BI", s_nssai_sst, s_nssai_sd & 0xFFFFFF),
            pdu_session_type=pdu_session_type,
            ssc_mode=ssc_mode,
        )

        pdu_req = self._build_pdu_session_establishment_request(pdu)
        self._send_uplink_nas(ue, pdu_req)

        ue.pdu_sessions[pdu_session_id] = pdu
        ue.current_state = UERegistrationState.PDU_SESSION_ACTIVE
        logger.info(
            f"PDU Session {pdu_session_id} established for {ue.supi} (DNN={dnn})"
        )
        return pdu

    def _build_pdu_session_establishment_request(
        self, pdu: PDUSessionContext
    ) -> bytes:
        nas_pdu = self.nas_codec.encode(
            ParsedMessage(
                protocol="nas-5gs",
                message_type="PDU Session Establishment Request",
                message_name="PDU Session Establishment Request",
                fields={
                    "pdu_session_type": pdu.pdu_session_type,
                    "ssc_mode": pdu.ssc_mode,
                },
            )
        )
        return nas_pdu

    def _next_pdu_session_id(self, ue: UEContext) -> int:
        used = set(ue.pdu_sessions.keys())
        for sid in range(1, 16):
            if sid not in used:
                return sid
        return 1

    # ─── Fuzzing interface ────────────────────────────────────

    def send_raw_nas(self, ue: UEContext, nas_pdu: bytes) -> None:
        """Send raw NAS PDU wrapped in NGAP UplinkNASTransport (fuzzing entry point).

        This bypasses the normal NAS state machine and sends arbitrary NAS
        payload to the AMF. The payload may be plain or security-protected.
        """
        self._send_uplink_nas(ue, nas_pdu)

    def send_raw_ngap(self, ngap_pdu: bytes) -> None:
        """Send raw NGAP PDU directly to AMF (fuzzing entry point)."""
        self.transport.send(ngap_pdu)

    def send_fuzzed_nas(
        self,
        ue: UEContext,
        fuzzed_fields: Dict[str, Any],
        base_message_type: str = "Registration Request",
    ) -> None:
        """Build and send a fuzzed NAS message with mutated fields."""
        msg = ParsedMessage(
            protocol="nas-5gs",
            message_type=base_message_type,
            message_name=base_message_type,
            fields=fuzzed_fields,
        )
        encoded = self.nas_codec.encode(msg)

        if ue.security_context.security_established:
            protector = NASMessageProtector(ue.security_context)
            mt = FIVEGMM_MSG_TYPES_REV.get(base_message_type, 0x41)
            # Extract payload from encoded (strip EPD + sec header)
            payload = encoded[3:]  # Simplified
            encoded = protector.protect_uplink(EPD_5GMM, mt, payload)

        self._send_uplink_nas(ue, encoded)

    def recv_response(self, timeout: float = 2.0) -> Optional[bytes]:
        """Receive a response from AMF."""
        try:
            self.transport.settimeout(timeout)
            return self.transport.recv()
        except socket.timeout:
            return None
        finally:
            self.transport.settimeout(None)

    @property
    def is_connected(self) -> bool:
        return self._connected
