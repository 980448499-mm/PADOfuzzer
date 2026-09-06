r"""NGAP codec per 3GPP TS 38.413.

NGAP (NG Application Protocol) uses ASN.1 UPER (Unaligned Packed Encoding Rules).
NGAP messages are carried over SCTP on the N2 interface between gNB and AMF.

Message structure (ASN.1):
  NGAP-PDU ::= CHOICE {
    initiatingMessage    InitiatingMessage,
    successfulOutcome    SuccessfulOutcome,
    unsuccessfulOutcome  UnsuccessfulOutcome,
    ...
  }

  InitiatingMessage ::= SEQUENCE {
    procedureCode    INTEGER (0..255),
    criticality      Criticality,
    value            <procedure-specific ASN.1 type>
  }

Key procedure codes from TS 38.413 Table 6.1-1:
  0:  AMFConfigurationUpdate
  1:  AMFStatusIndication
  2:  CellTrafficTrace
  ...
  9:  HandoverCancel
  10: HandoverCommand
  12: HandoverPreparation
  13: HandoverRequest
  14: HandoverRequired
  15: HandoverNotify
  16: InitialContextSetup
  17: InitialUEMessage
  18: NASNonDeliveryIndication
  19: NGReset
  20: NGSetup
  21: OverloadStart
  22: OverloadStop
  23: Paging
  24: PDU Session ResourceModify
  25: PDU Session ResourceModifyIndication
  26: PDU Session ResourceRelease
  27: PDU Session ResourceReleaseResponse
  28: PDU Session ResourceSetup
  29: PDU Session ResourceSetupResponse
  30: PDU Session ResourceNotify
  31: PathSwitchRequest
  32: PathSwitchRequestAcknowledge
  33: RerouteNASRequest
  34: UEContextModification
  35: UEContextModificationResponse
  36: UEContextRelease
  37: UEContextReleaseComplete
  38: UEContextResume
  39: UEContextSuspend
  40: UERadioCapabilityCheck
  41: UERadioCapabilityInfoIndication
  42: UERadioCapabilityMatch
  43: UETNLABindingRelease
  44: WriteReplaceWarning
  ...
"""

import struct
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from src.codec.base import CodecContext, ParsedMessage, ProtocolCodec
from src.codec.schema import FieldDef, FieldType, FieldConstraint, MessageSchema


class NGAPPDUType(Enum):
    INITIATING = 0
    SUCCESSFUL = 1
    UNSUCCESSFUL = 2


class Criticality(Enum):
    REJECT = 0
    IGNORE = 1
    NOTIFY = 2


NGAP_PROCEDURE_CODES: Dict[int, str] = {
    0: "AMFConfigurationUpdate",
    1: "AMFStatusIndication",
    9: "HandoverCancel",
    10: "HandoverCommand",
    12: "HandoverPreparation",
    13: "HandoverRequest",
    14: "HandoverRequired",
    15: "HandoverNotify",
    16: "InitialContextSetup",
    17: "InitialUEMessage",
    18: "NASNonDeliveryIndication",
    19: "NGReset",
    20: "NGSetup",
    21: "OverloadStart",
    22: "OverloadStop",
    23: "Paging",
    24: "PDUSessionResourceModify",
    25: "PDUSessionResourceModifyIndication",
    26: "PDUSessionResourceRelease",
    27: "PDUSessionResourceReleaseResponse",
    28: "PDUSessionResourceSetup",
    29: "PDUSessionResourceSetupResponse",
    30: "PDUSessionResourceNotify",
    31: "PathSwitchRequest",
    32: "PathSwitchRequestAcknowledge",
    33: "RerouteNASRequest",
    34: "UEContextModification",
    35: "UEContextModificationResponse",
    36: "UEContextRelease",
    37: "UEContextReleaseComplete",
    38: "UEContextResume",
    39: "UEContextSuspend",
    40: "UERadioCapabilityCheck",
    41: "UERadioCapabilityInfoIndication",
    42: "UERadioCapabilityMatch",
    43: "UETNLABindingRelease",
    44: "WriteReplaceWarning",
    45: "UplinkNASTransport",
    46: "DownlinkNASTransport",
    47: "ErrorIndication",
    48: "UEContextReleaseRequest",
    49: "PDUSessionResourceSetupRequest",
    50: "PDUSessionResourceSetupResponse",
    51: "PDUSessionResourceReleaseCommand",
    52: "PDUSessionResourceReleaseResponse",
    53: "PDUSessionResourceModifyRequest",
    54: "PDUSessionResourceModifyResponse",
    55: "PDUSessionResourceNotify",
    56: "PDUSessionResourceModifyIndication",
    57: "PDUSessionResourceModifyConfirm",
}

NGAP_PROCEDURE_CODES_REV: Dict[str, int] = {
    v: k for k, v in NGAP_PROCEDURE_CODES.items()
}

# ─── IE ID constants (simplified subset) ───

NGAP_IE_AMF_UE_NGAP_ID = 0
NGAP_IE_RAN_UE_NGAP_ID = 1
NGAP_IE_USER_LOCATION_INFO = 2
NGAP_IE_NAS_PDU = 3
NGAP_IE_GUAMI = 4
NGAP_IE_AMF_NAME = 5
NGAP_IE_SST = 6
NGAP_IE_SD = 7
NGAP_IE_RRC_ESTABLISHMENT_CAUSE = 8
NGAP_IE_UE_CONTEXT_REQUEST = 9
NGAP_IE_TAI_LIST_FOR_RESTART = 10
NGAP_IE_PAGING_DRX = 11
NGAP_IE_UEPAGING_IDENTITY = 12
NGAP_IE_TAI_LIST_FOR_PAGING = 13
NGAP_IE_NSSAI = 14
NGAP_IE_CAUSE = 15
NGAP_IE_UE_SECURITY_CAPABILITIES = 16
NGAP_IE_SECURITY_KEY = 17
NGAP_IE_UE_AGGREGATE_MAXIMUM_BIT_RATE = 18
NGAP_IE_PDU_SESSION_RESOURCE_SETUP_LIST = 19
NGAP_IE_PDU_SESSION_RESOURCE_MODIFY_LIST = 20
NGAP_IE_PDU_SESSION_RESOURCE_RELEASE_LIST = 21
NGAP_IE_PDU_SESSION_ID = 22
NGAP_IE_S_NSSAI = 23
NGAP_IE_PDU_SESSION_TYPE = 24
NGAP_IE_QOS_FLOW_SETUP_LIST = 25
NGAP_IE_UP_TRANSPORT_LAYER_INFO = 26
NGAP_IE_NRUPP_MODE_INFO = 27
NGAP_IE_ALLOWED_NSSAI = 28
NGAP_IE_UE_AMBR = 29
NGAP_IE_MOBILITY_RESTRICTION_LIST = 30
NGAP_IE_INDEX_TO_RFSP = 31
NGAP_IE_MASKED_IMEISV = 32

IE_NAMES: Dict[int, str] = {
    0: "AMF-UE-NGAP-ID",
    1: "RAN-UE-NGAP-ID",
    2: "UserLocationInformation",
    3: "NAS-PDU",
    4: "GUAMI",
    5: "AMFName",
    10: "TAIListForRestart",
    15: "Cause",
    17: "SecurityKey",
    22: "PDUSessionID",
    23: "S-NSSAI",
}


class CachedNGAPCodec:
    """Skeleton cache for NGAP messages to avoid full re-encoding."""

    def __init__(self, max_cache_size: int = 1000):
        self._skeleton_cache: Dict[str, bytes] = {}
        self._field_offsets: Dict[str, Dict[str, Tuple[int, int]]] = {}
        self.max_cache_size = max_cache_size

    def get_skeleton(self, msg_type: str) -> Optional[bytes]:
        return self._skeleton_cache.get(msg_type)

    def put_skeleton(self, msg_type: str, skeleton: bytes) -> None:
        if len(self._skeleton_cache) >= self.max_cache_size:
            oldest = next(iter(self._skeleton_cache))
            del self._skeleton_cache[oldest]
        self._skeleton_cache[msg_type] = skeleton

    def get_field_offset(self, msg_type: str,
                         field_name: str) -> Optional[Tuple[int, int]]:
        offsets = self._field_offsets.get(msg_type, {})
        return offsets.get(field_name)

    def set_field_offset(self, msg_type: str, field_name: str,
                         offset: int, length: int) -> None:
        if msg_type not in self._field_offsets:
            self._field_offsets[msg_type] = {}
        self._field_offsets[msg_type][field_name] = (offset, length)


class NGAPCodec(ProtocolCodec):
    """NGAP ASN.1 UPER codec.

    Implements a simplified but functional encoding/decoding for the
    most important NGAP message types used in fuzzing. Uses manual
    ASN.1 packing for performance rather than full asn1tools compilation.

    For full ASN.1 compliance, an asn1tools backend can be swapped in
    by replacing encode/decode methods.
    """

    protocol = "ngap"

    def __init__(self, context: Optional[CodecContext] = None):
        self.context = context or CodecContext()
        self.cache = CachedNGAPCodec()
        self._schemas: Dict[str, MessageSchema] = {}
        self._build_schemas()

    # ─── Public API ───────────────────────────────────────────

    def encode(self, msg: ParsedMessage) -> bytes:
        procedure_code = NGAP_PROCEDURE_CODES_REV.get(msg.message_type, 0)
        skeleton = self.cache.get_skeleton(msg.message_type)

        if skeleton is not None and msg.fields:
            return self._patch_skeleton(skeleton, msg)

        return self._encode_full(msg, procedure_code)

    def decode(self, raw: bytes) -> ParsedMessage:
        if len(raw) < 4:
            raise ValueError(f"NGAP PDU too short: {len(raw)} bytes")

        pdu_type_byte = raw[0]
        pdu_type = NGAPPDUType(pdu_type_byte) if pdu_type_byte < 3 else NGAPPDUType.INITIATING

        if pdu_type == NGAPPDUType.INITIATING:
            procedure_code, criticality = struct.unpack("!BB", raw[1:3])
        else:
            procedure_code, criticality = struct.unpack("!BB", raw[1:3])

        msg_name = NGAP_PROCEDURE_CODES.get(procedure_code,
                                            f"UnknownProcedure({procedure_code})")

        value_bytes = raw[3:]
        fields = self._decode_value(msg_name, value_bytes)

        return ParsedMessage(
            protocol=self.protocol,
            message_type=msg_name,
            message_name=msg_name,
            fields={
                "pdu_type": pdu_type.name,
                "procedure_code": procedure_code,
                "criticality": criticality,
                **fields,
            },
            raw_bytes=raw,
        )

    def get_message_schema(self, message_type: str) -> Optional[MessageSchema]:
        return self._schemas.get(message_type)

    def random_valid(self) -> ParsedMessage:
        import random

        msg_name = random.choice(list(NGAP_PROCEDURE_CODES.values()))
        procedure_code = NGAP_PROCEDURE_CODES_REV[msg_name]

        fields: Dict[str, Any] = {}
        if msg_name == "InitialUEMessage":
            fields["ran_ue_ngap_id"] = random.randint(0, 2**32 - 1)
            fields["nas_pdu"] = bytes([0x7E, 0x00, 0x41, 0x01, 0x00])
        elif msg_name == "NGSetup":
            fields["amf_name"] = b"AMF-TEST"

        return ParsedMessage(
            protocol=self.protocol,
            message_type=msg_name,
            message_name=msg_name,
            fields={
                "pdu_type": "INITIATING",
                "procedure_code": procedure_code,
                "criticality": 0,
                **fields,
            },
        )

    def get_message_types(self) -> List[str]:
        return list(NGAP_PROCEDURE_CODES.values())

    # ─── Internal encoding ────────────────────────────────────

    def _encode_full(self, msg: ParsedMessage, procedure_code: int) -> bytes:
        buf = bytearray()
        buf.append(NGAPPDUType.INITIATING.value)
        buf.append(procedure_code & 0xFF)
        buf.append(0)  # criticality = REJECT

        msg_name = msg.message_type
        encoders = {
            "InitialUEMessage": self._encode_initial_ue_message,
            "NGSetup": self._encode_ng_setup,
            "UplinkNASTransport": self._encode_uplink_nas_transport,
            "UEContextReleaseRequest": self._encode_ue_context_release,
            "PDUSessionResourceSetupRequest": self._encode_pdu_session_setup,
        }
        encoder = encoders.get(msg_name, self._encode_generic)
        encoder(buf, msg.fields)

        skeleton = bytes(buf)
        self.cache.put_skeleton(msg_name, skeleton)
        return skeleton

    def _patch_skeleton(self, skeleton: bytes, msg: ParsedMessage) -> bytes:
        """Byte-patch fields in a pre-encoded skeleton."""
        buf = bytearray(skeleton)
        msg_name = msg.message_type
        for field_name, value in msg.fields.items():
            offset_info = self.cache.get_field_offset(msg_name, field_name)
            if offset_info is not None:
                offset, max_len = offset_info
                val_bytes = self._to_bytes(value)
                actual_len = min(len(val_bytes), max_len)
                buf[offset : offset + actual_len] = val_bytes[:actual_len]
        return bytes(buf)

    def _to_bytes(self, value: Any) -> bytes:
        if isinstance(value, bytes):
            return value
        elif isinstance(value, str):
            return value.encode()
        elif isinstance(value, int):
            n = max(1, (value.bit_length() + 7) // 8)
            return value.to_bytes(n, "big")
        return str(value).encode()

    # ─── Message-specific encoders ─────────────────────────────

    def _encode_initial_ue_message(self, buf: bytearray,
                                    fields: Dict[str, Any]) -> None:
        # Encode RAN UE NGAP ID (IE ID=1, integer)
        ran_id = fields.get("ran_ue_ngap_id", 0)
        self._encode_ie_integer_le(buf, NGAP_IE_RAN_UE_NGAP_ID, ran_id)
        # Encode NAS-PDU (IE ID=3, octet string)
        nas_pdu = fields.get("nas_pdu", b"")
        self._cache_field_offset("InitialUEMessage", "nas_pdu",
                                  len(buf), len(nas_pdu))
        self._encode_ie_octet_string(buf, NGAP_IE_NAS_PDU, nas_pdu)

    def _encode_ng_setup(self, buf: bytearray, fields: Dict[str, Any]) -> None:
        name = fields.get("amf_name", b"AMF-DEFAULT")
        self._encode_ie_octet_string(buf, NGAP_IE_AMF_NAME, name)

    def _encode_uplink_nas_transport(self, buf: bytearray,
                                      fields: Dict[str, Any]) -> None:
        amf_id = fields.get("amf_ue_ngap_id", 0)
        ran_id = fields.get("ran_ue_ngap_id", 0)
        nas_pdu = fields.get("nas_pdu", b"")
        self._encode_ie_integer_le(buf, NGAP_IE_AMF_UE_NGAP_ID, amf_id)
        self._encode_ie_integer_le(buf, NGAP_IE_RAN_UE_NGAP_ID, ran_id)
        self._cache_field_offset("UplinkNASTransport", "nas_pdu",
                                  len(buf), len(nas_pdu))
        self._encode_ie_octet_string(buf, NGAP_IE_NAS_PDU, nas_pdu)

    def _encode_ue_context_release(self, buf: bytearray,
                                    fields: Dict[str, Any]) -> None:
        amf_id = fields.get("amf_ue_ngap_id", 0)
        ran_id = fields.get("ran_ue_ngap_id", 0)
        self._encode_ie_integer_le(buf, NGAP_IE_AMF_UE_NGAP_ID, amf_id)
        self._encode_ie_integer_le(buf, NGAP_IE_RAN_UE_NGAP_ID, ran_id)

    def _encode_pdu_session_setup(self, buf: bytearray,
                                   fields: Dict[str, Any]) -> None:
        amf_id = fields.get("amf_ue_ngap_id", 0)
        ran_id = fields.get("ran_ue_ngap_id", 0)
        self._encode_ie_integer_le(buf, NGAP_IE_AMF_UE_NGAP_ID, amf_id)
        self._encode_ie_integer_le(buf, NGAP_IE_RAN_UE_NGAP_ID, ran_id)
        # PDU Session Resource Setup List
        setup_list = fields.get("pdu_session_resource_setup_list", b"")
        if setup_list:
            self._encode_ie_octet_string(
                buf, NGAP_IE_PDU_SESSION_RESOURCE_SETUP_LIST, setup_list
            )

    def _encode_generic(self, buf: bytearray, fields: Dict[str, Any]) -> None:
        """Encode all fields as generic IEs."""
        for name, value in fields.items():
            if isinstance(value, int):
                ie_id = self._field_name_to_ie_id(name)
                self._encode_ie_integer_le(buf, ie_id or 0, value)
            elif isinstance(value, (bytes, str)):
                ie_id = self._field_name_to_ie_id(name)
                self._encode_ie_octet_string(buf, ie_id or 0, value)

    # ─── Low-level IE encoding ─────────────────────────────────

    def _encode_ie_integer_le(self, buf: bytearray, ie_id: int,
                               value: int) -> None:
        """Encode an integer IE with little-endian encoding."""
        n_bytes = max(1, min(8, (value.bit_length() + 7) // 8))
        buf.append(ie_id & 0xFF)
        buf.append(n_bytes & 0xFF)
        buf.extend(value.to_bytes(n_bytes, "little"))

    def _encode_ie_octet_string(self, buf: bytearray, ie_id: int,
                                 value: bytes) -> None:
        """Encode an octet string IE."""
        if isinstance(value, str):
            value = value.encode()
        buf.append(ie_id & 0xFF)
        if len(value) < 256:
            buf.append(len(value) & 0xFF)
        else:
            buf.extend(struct.pack("!H", len(value)))
        buf.extend(value)

    # ─── Internal decoding ────────────────────────────────────

    def _decode_value(self, msg_name: str, raw: bytes) -> Dict[str, Any]:
        fields: Dict[str, Any] = {}
        offset = 0
        while offset + 1 < len(raw):
            ie_id = raw[offset]
            offset += 1
            if offset >= len(raw):
                break
            ie_len = raw[offset]
            offset += 1
            if offset + ie_len > len(raw):
                break
            value = raw[offset : offset + ie_len]
            offset += ie_len
            ie_name = IE_NAMES.get(ie_id, f"ie_{ie_id}")
            fields[ie_name] = value
        return fields

    # ─── Helpers ──────────────────────────────────────────────

    def _cache_field_offset(self, msg_name: str, field_name: str,
                            offset: int, length: int) -> None:
        self.cache.set_field_offset(msg_name, field_name, offset, length)

    @staticmethod
    def _field_name_to_ie_id(name: str) -> Optional[int]:
        mapping = {
            "amf_ue_ngap_id": NGAP_IE_AMF_UE_NGAP_ID,
            "ran_ue_ngap_id": NGAP_IE_RAN_UE_NGAP_ID,
            "nas_pdu": NGAP_IE_NAS_PDU,
            "guami": NGAP_IE_GUAMI,
            "amf_name": NGAP_IE_AMF_NAME,
            "user_location_info": NGAP_IE_USER_LOCATION_INFO,
            "s_nssai": NGAP_IE_S_NSSAI,
            "cause": NGAP_IE_CAUSE,
            "pdu_session_id": NGAP_IE_PDU_SESSION_ID,
            "security_key": NGAP_IE_SECURITY_KEY,
            "ue_security_capabilities": NGAP_IE_UE_SECURITY_CAPABILITIES,
            "ue_ambr": NGAP_IE_UE_AMBR,
            "allowed_nssai": NGAP_IE_ALLOWED_NSSAI,
            "pdu_session_resource_setup_list": NGAP_IE_PDU_SESSION_RESOURCE_SETUP_LIST,
        }
        return mapping.get(name.lower())

    def _build_schemas(self) -> None:
        # Register NGAP message schemas for fuzzing
        self._schemas["InitialUEMessage"] = MessageSchema(
            protocol="ngap",
            message_type="InitialUEMessage",
            message_name="InitialUEMessage",
            fields=[
                FieldDef("ran_ue_ngap_id", FieldType.INTEGER,
                         constraint=FieldConstraint(range_min=0, range_max=2**32 - 1)),
                FieldDef("nas_pdu", FieldType.OCTET_STRING, max_len=4096),
            ],
        )

        self._schemas["UplinkNASTransport"] = MessageSchema(
            protocol="ngap",
            message_type="UplinkNASTransport",
            message_name="UplinkNASTransport",
            fields=[
                FieldDef("amf_ue_ngap_id", FieldType.INTEGER),
                FieldDef("ran_ue_ngap_id", FieldType.INTEGER),
                FieldDef("nas_pdu", FieldType.OCTET_STRING, max_len=4096),
            ],
        )

        self._schemas["NGSetup"] = MessageSchema(
            protocol="ngap",
            message_type="NGSetup",
            message_name="NGSetup",
            fields=[
                FieldDef("amf_name", FieldType.OCTET_STRING, max_len=150),
            ],
        )
