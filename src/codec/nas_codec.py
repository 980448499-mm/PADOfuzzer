r"""NAS 5GS codec per 3GPP TS 24.501.

Message structure:
  - Extended Protocol Discriminator (1 byte, value 0x7E for 5GMM, 0x2E for 5GSM)
  - Security Header Type (4 bits) + Spare (4 bits), or PDU Session ID for 5GSM
  - Message Type (1 byte)
  - Information Elements (V, TV, TLV, LVE, TLVE formats)

IE Format types:
  V:    Value only (fixed length, implicit type from position)
  TV:   Type (4 bits IEI) + Value (fixed length)
  TLV:  Type (1 byte IEI) + Length (1 byte) + Value
  LVE:  Length (2 bytes) + Value + Extended
  TLVE: Type (1 byte IEI) + Length (2 bytes) + Value + Extended
"""

import struct
from typing import Any, Dict, List, Optional, Tuple

from src.codec.base import (
    CodecContext,
    ParsedMessage,
    ProtocolCodec,
)
from src.codec.schema import FieldDef, FieldType, FieldConstraint, MessageSchema

# ─── 5GMM Message Types (TS 24.501 Table 8.2.1.1) ───

FIVEGMM_MSG_TYPES: Dict[int, str] = {
    0x41: "Registration Request",
    0x42: "Registration Accept",
    0x43: "Registration Complete",
    0x44: "Registration Reject",
    0x45: "Deregistration Request (UE originating)",
    0x46: "Deregistration Accept (UE originating)",
    0x47: "Deregistration Request (UE terminated)",
    0x48: "Deregistration Accept (UE terminated)",
    0x4C: "Service Request",
    0x4D: "Service Reject",
    0x4E: "Service Accept",
    0x50: "Configuration Update Command",
    0x51: "Configuration Update Complete",
    0x54: "Authentication Request",
    0x55: "Authentication Response",
    0x56: "Authentication Reject",
    0x57: "Authentication Failure",
    0x58: "Authentication Result",
    0x5D: "Security Mode Command",
    0x5E: "Security Mode Complete",
    0x5F: "Security Mode Reject",
    0x60: "5GMM Status",
    0x61: "Notification",
    0x62: "Notification Response",
    0x67: "UL NAS Transport",
    0x68: "DL NAS Transport",
    0x70: "Identity Request",
    0x71: "Identity Response",
}

FIVEGMM_MSG_TYPES_REV: Dict[str, int] = {v: k for k, v in FIVEGMM_MSG_TYPES.items()}

# ─── 5GSM Message Types (TS 24.501 Table 8.3.1.1) ───

FIVEGSM_MSG_TYPES: Dict[int, str] = {
    0xC1: "PDU Session Establishment Request",
    0xC2: "PDU Session Establishment Accept",
    0xC3: "PDU Session Establishment Reject",
    0xC5: "PDU Session Authentication Command",
    0xC6: "PDU Session Authentication Complete",
    0xC7: "PDU Session Authentication Result",
    0xC9: "PDU Session Modification Request",
    0xCA: "PDU Session Modification Reject",
    0xCB: "PDU Session Modification Command",
    0xCC: "PDU Session Modification Complete",
    0xCD: "PDU Session Modification Command Reject",
    0xCE: "PDU Session Release Request",
    0xCF: "PDU Session Release Reject",
    0xD0: "PDU Session Release Command",
    0xD1: "PDU Session Release Complete",
    0xD3: "5GSM Status",
}

FIVEGSM_MSG_TYPES_REV: Dict[str, int] = {v: k for k, v in FIVEGSM_MSG_TYPES.items()}

# ─── Extended Protocol Discriminators ───

EPD_5GMM = 0x7E
EPD_5GSM = 0x2E

# ─── IEI (Information Element Identifier) constants ───

# 5GMM IEs
IEI_SUCI = 0x01
IEI_5G_GUTI = 0x02
IEI_5GS_TRACKING_AREA_ID_LIST = 0x54
IEI_NAS_MESSAGE_CONTAINER = 0x71
IEI_NSSAI = 0x71  # Different context
IEI_PDU_SESSION_STATUS = 0x50
IEI_ALLOWED_NSSAI = 0x15
IEI_CONFIGURED_NSSAI = 0x71
IEI_REJECTED_NSSAI = 0x11
IEI_UE_SECURITY_CAPABILITY = 0x20
IEI_NAS_SECURITY_ALGORITHMS = 0x21
IEI_5GMM_CAPABILITY = 0x10
IEI_S1_UE_NETWORK_CAPABILITY = 0x17
IEI_MS_NETWORK_CAPABILITY = 0x31
IEI_MOBILE_IDENTITY = 0x23
IEI_EAP_MESSAGE = 0x78
IEI_ABBA = 0x38
IEI_AUTHENTICATION_PARAMETER_RAND = 0x21
IEI_AUTHENTICATION_PARAMETER_AUTN = 0x20
IEI_AUTHENTICATION_RESPONSE_PARAMETER = 0x2D
IEI_AUTHENTICATION_FAILURE_PARAMETER = 0x30
IEI_NULL_CIPHERING = 0x6E
IEI_ADDITIONAL_5G_SECURITY_INFORMATION = 0x69
IEI_PAYLOAD_CONTAINER = 0x7B
IEI_PAYLOAD_CONTAINER_TYPE = 0x08
IEI_5GS_REGISTRATION_RESULT = 0x77
IEI_5GMM_CAUSE = 0x58
IEI_SERVICE_TYPE = 0x60  # TV format
IEI_T3346_VALUE = 0x5B
IEI_T3448_VALUE = 0x5A
IEI_5GS_MOBILE_IDENTITY = 0x77
IEI_DNN = 0x25
IEI_S_NSSAI = 0x22
IEI_PDU_SESSION_ID = 0x12
IEI_REQUEST_TYPE = 0x08
IEI_PDU_SESSION_TYPE = 0x09
IEI_SSC_MODE = 0x0A
IEI_5GSM_CAPABILITY = 0x28
IEI_MAXIMUM_NUMBER_OF_SUPPORTED_PACKET_FILTERS = 0x29
IEI_ALWAYS_ON_PDU_SESSION_REQUESTED = 0x0B
IEI_INTEGRITY_PROTECTION_MAXIMUM_DATA_RATE = 0x13
IEI_PDU_SESSION_TYPE = 0x09
IEI_QOS_RULES = 0x7A
IEI_QOS_FLOW_DESCRIPTIONS = 0x79
IEI_MAPPED_EPS_BEARER_CONTEXTS = 0x7F
IEI_5GSM_CAUSE = 0x59
IEI_EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS = 0x7B
IEI_PDU_ADDRESS = 0x29
IEI_SESSION_AMBR = 0x2A
IEI_GPRS_TIMER = 0x37
IEI_AUTHORIZED_QOS_RULES = 0x6E

# ─── IE Format Indicators ───

IE_FORMAT_V = 0    # Value only
IE_FORMAT_TV = 1   # Type-Value (4-bit IEI)
IE_FORMAT_TLV = 2  # Type-Length-Value (1 byte IEI, 1 byte length)
IE_FORMAT_LVE = 3  # Length-Value-Extended (2 byte length)
IE_FORMAT_TLVE = 4  # Type-Length-Value-Extended (1 byte IEI, 2 byte length)

# ─── Security Header Types ───

SECURITY_HEADER_PLAIN = 0x0
SECURITY_HEADER_INTEGRITY_PROTECTED = 0x1
SECURITY_HEADER_INTEGRITY_PROTECTED_CIPHERED = 0x2
SECURITY_HEADER_INTEGRITY_PROTECTED_WITH_NEW_SEC = 0x3
SECURITY_HEADER_INTEGRITY_PROTECTED_CIPHERED_WITH_NEW_SEC = 0x4

SECURITY_HEADER_NAMES: Dict[int, str] = {
    0: "Plain NAS message",
    1: "Integrity protected",
    2: "Integrity protected and ciphered",
    3: "Integrity protected with new 5G NAS security context",
    4: "Integrity protected and ciphered with new 5G NAS security context",
}


def _get_message_type_name(epd: int, msg_type: int) -> str:
    if epd == EPD_5GMM:
        return FIVEGMM_MSG_TYPES.get(msg_type, f"Unknown 5GMM (0x{msg_type:02X})")
    elif epd == EPD_5GSM:
        return FIVEGSM_MSG_TYPES.get(msg_type, f"Unknown 5GSM (0x{msg_type:02X})")
    return f"Unknown Protocol (EPD=0x{epd:02X})"


class NAS5GSCodec(ProtocolCodec):
    """NAS 5GS binary codec per 3GPP TS 24.501."""

    protocol = "nas-5gs"

    # ── IE format descriptors: (iei_size, len_size) ──
    # Maps IEI to (format, length_bytes)
    IE_REGISTRY: Dict[int, Tuple[int, int]] = {
        # 5GMM IEs
        IEI_SUCI: (IE_FORMAT_TLV, 1),
        IEI_5G_GUTI: (IE_FORMAT_TLV, 1),
        IEI_NAS_MESSAGE_CONTAINER: (IE_FORMAT_TLVE, 2),
        IEI_PDU_SESSION_STATUS: (IE_FORMAT_TLV, 1),
        IEI_UE_SECURITY_CAPABILITY: (IE_FORMAT_TLV, 1),
        IEI_NAS_SECURITY_ALGORITHMS: (IE_FORMAT_TV, 0),
        IEI_5GMM_CAPABILITY: (IE_FORMAT_TV, 0),
        IEI_S1_UE_NETWORK_CAPABILITY: (IE_FORMAT_TLV, 1),
        IEI_MOBILE_IDENTITY: (IE_FORMAT_TLVE, 2),
        IEI_EAP_MESSAGE: (IE_FORMAT_TLVE, 2),
        IEI_ABBA: (IE_FORMAT_TLV, 1),
        IEI_AUTHENTICATION_PARAMETER_RAND: (IE_FORMAT_TV, 0),
        IEI_AUTHENTICATION_PARAMETER_AUTN: (IE_FORMAT_TLV, 1),
        IEI_AUTHENTICATION_RESPONSE_PARAMETER: (IE_FORMAT_TLV, 1),
        IEI_AUTHENTICATION_FAILURE_PARAMETER: (IE_FORMAT_TLV, 1),
        IEI_5GS_REGISTRATION_RESULT: (IE_FORMAT_TLV, 1),
        IEI_5GMM_CAUSE: (IE_FORMAT_TV, 0),
        IEI_PAYLOAD_CONTAINER: (IE_FORMAT_TLVE, 2),
        IEI_PAYLOAD_CONTAINER_TYPE: (IE_FORMAT_TV, 0),
        IEI_5GS_TRACKING_AREA_ID_LIST: (IE_FORMAT_TLVE, 2),
        IEI_ALLOWED_NSSAI: (IE_FORMAT_TLV, 1),
        IEI_REJECTED_NSSAI: (IE_FORMAT_TLV, 1),
        IEI_CONFIGURED_NSSAI: (IE_FORMAT_TLVE, 2),
        IEI_T3346_VALUE: (IE_FORMAT_TV, 0),
        IEI_T3448_VALUE: (IE_FORMAT_TV, 0),
        IEI_NULL_CIPHERING: (IE_FORMAT_TV, 0),
        # 5GSM IEs
        IEI_DNN: (IE_FORMAT_TLV, 1),
        IEI_S_NSSAI: (IE_FORMAT_TV, 0),
        IEI_REQUEST_TYPE: (IE_FORMAT_TV, 0),
        IEI_PDU_SESSION_TYPE: (IE_FORMAT_TV, 0),
        IEI_SSC_MODE: (IE_FORMAT_TV, 0),
        IEI_5GSM_CAPABILITY: (IE_FORMAT_TLV, 1),
        IEI_MAXIMUM_NUMBER_OF_SUPPORTED_PACKET_FILTERS: (IE_FORMAT_TV, 0),
        IEI_ALWAYS_ON_PDU_SESSION_REQUESTED: (IE_FORMAT_TV, 0),
        IEI_INTEGRITY_PROTECTION_MAXIMUM_DATA_RATE: (IE_FORMAT_TLV, 1),
        IEI_QOS_RULES: (IE_FORMAT_TLVE, 2),
        IEI_QOS_FLOW_DESCRIPTIONS: (IE_FORMAT_TLVE, 2),
        IEI_MAPPED_EPS_BEARER_CONTEXTS: (IE_FORMAT_TLVE, 2),
        IEI_5GSM_CAUSE: (IE_FORMAT_TV, 0),
        IEI_EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS: (IE_FORMAT_TLVE, 2),
        IEI_PDU_ADDRESS: (IE_FORMAT_TLVE, 2),
        IEI_SESSION_AMBR: (IE_FORMAT_TLV, 1),
        IEI_GPRS_TIMER: (IE_FORMAT_TV, 0),
        IEI_AUTHORIZED_QOS_RULES: (IE_FORMAT_TLVE, 2),
        IEI_ADDITIONAL_5G_SECURITY_INFORMATION: (IE_FORMAT_TV, 0),
        IEI_MS_NETWORK_CAPABILITY: (IE_FORMAT_TLV, 1),
    }

    def __init__(self, context: Optional[CodecContext] = None):
        self.context = context or CodecContext()
        self._schemas: Dict[str, MessageSchema] = {}
        self._build_schemas()

    # ─── Public API ───────────────────────────────────────────

    def encode(self, msg: ParsedMessage) -> bytes:
        mt = FIVEGMM_MSG_TYPES_REV.get(msg.message_type)
        epd = EPD_5GMM
        if mt is None:
            mt = FIVEGSM_MSG_TYPES_REV.get(msg.message_type)
            epd = EPD_5GSM
        if mt is None:
            raise ValueError(f"Unknown NAS message type: {msg.message_type}")

        body = self._encode_ies(epd, mt, msg.fields)
        if epd == EPD_5GMM:
            header = struct.pack("!BBB", epd, SECURITY_HEADER_PLAIN, mt)
        else:
            pdu_session_id = msg.fields.get("pdu_session_id", 0)
            header = struct.pack("!BBB", epd, pdu_session_id & 0xFF, mt)
        return header + body

    def decode(self, raw: bytes) -> ParsedMessage:
        if len(raw) < 3:
            raise ValueError(f"NAS PDU too short: {len(raw)} bytes")

        epd = raw[0]
        second_byte = raw[1]
        msg_type = raw[2]
        msg_name = _get_message_type_name(epd, msg_type)

        fields: Dict[str, Any] = {}
        if epd == EPD_5GMM:
            security_header = (second_byte >> 4) & 0x0F
            fields["security_header_type"] = security_header
            fields["security_header_name"] = SECURITY_HEADER_NAMES.get(
                security_header, "Unknown"
            )
        else:
            fields["pdu_session_id"] = second_byte
            fields["procedure_transaction_identity"] = (second_byte >> 0) & 0xFF

        body = raw[3:]
        fields.update(self._decode_ies(msg_type, body))

        return ParsedMessage(
            protocol=self.protocol,
            message_type=msg_name,
            message_name=msg_name,
            fields=fields,
            raw_bytes=raw,
        )

    def get_message_schema(self, message_type: str) -> Optional[MessageSchema]:
        return self._schemas.get(message_type)

    def random_valid(self) -> ParsedMessage:
        import random

        epd = random.choice([EPD_5GMM, EPD_5GSM])
        if epd == EPD_5GMM:
            msg_type, msg_name = random.choice(list(FIVEGMM_MSG_TYPES.items()))
            fields = {"security_header_type": 0}
            if msg_name == "Registration Request":
                fields["5gs_registration_type"] = 1
                fields["ng_ksi"] = 0
                fields["5gs_mobile_identity_supi"] = "001010123456789"
            elif msg_name == "Service Request":
                fields["ng_ksi"] = 0
                fields["service_type"] = 0
        else:
            msg_type, msg_name = random.choice(list(FIVEGSM_MSG_TYPES.items()))
            fields = {"pdu_session_id": 1, "procedure_transaction_identity": 1}

        return ParsedMessage(
            protocol=self.protocol,
            message_type=msg_name,
            message_name=msg_name,
            fields=fields,
        )

    def get_message_types(self) -> List[str]:
        return list(FIVEGMM_MSG_TYPES.values()) + list(FIVEGSM_MSG_TYPES.values())

    # ─── IE Encoding ──────────────────────────────────────────

    def _encode_ies(self, epd: int, msg_type: int, fields: Dict[str, Any]) -> bytes:
        """Encode information elements based on message type.

        Each message type has mandatory IEs (no IEI prefix, fixed position)
        followed by optional IEs (prefixed by IEI).
        """
        result = bytearray()
        ie_encoders = self._get_ie_encoders(epd, msg_type)
        ie_encoders(msg_type, fields, result)
        return bytes(result)

    def _get_ie_encoders(self, epd: int, msg_type: int):
        """Return the IE encoder function for a given message type."""
        if epd == EPD_5GMM:
            encoders_5gmm = {
                0x41: self._encode_registration_request,
                0x42: self._encode_registration_accept,
                0x43: self._encode_registration_complete,
                0x4C: self._encode_service_request,
                0x55: self._encode_authentication_response,
                0x57: self._encode_authentication_failure,
                0x5E: self._encode_security_mode_complete,
            }
            return encoders_5gmm.get(msg_type, self._encode_generic_ies)
        else:
            encoders_5gsm = {
                0xC1: self._encode_pdu_session_establishment_request,
                0xCC: self._encode_pdu_session_modification_complete,
                0xD1: self._encode_pdu_session_release_complete,
            }
            return encoders_5gsm.get(msg_type, self._encode_generic_ies)

    def _encode_registration_request(
        self, msg_type: int, fields: Dict[str, Any], buf: bytearray
    ) -> None:
        # Mandatory IEs (no IEI)
        reg_type = fields.get("5gs_registration_type", 1)
        ng_ksi = fields.get("ng_ksi", 0)
        buf.append(((reg_type & 0x07) << 4) | (ng_ksi & 0x0F))
        supi = fields.get("5gs_mobile_identity_supi", "")
        self._encode_mobile_identity(buf, supi)
        # Optional IEs (with IEI)
        if "ue_security_capability" in fields:
            self._encode_tlv(buf, IEI_UE_SECURITY_CAPABILITY,
                            fields["ue_security_capability"])
        if "nas_message_container" in fields:
            self._encode_tlv(buf, IEI_NAS_MESSAGE_CONTAINER,
                            fields["nas_message_container"])

    def _encode_registration_accept(
        self, msg_type: int, fields: Dict[str, Any], buf: bytearray
    ) -> None:
        result = fields.get("5gs_registration_result", 0)
        buf.append(result & 0xFF)
        if "5g_guti" in fields:
            self._encode_tlv(buf, IEI_5G_GUTI, fields["5g_guti"])

    def _encode_registration_complete(
        self, msg_type: int, fields: Dict[str, Any], buf: bytearray
    ) -> None:
        pass  # No mandatory IEs

    def _encode_service_request(
        self, msg_type: int, fields: Dict[str, Any], buf: bytearray
    ) -> None:
        ng_ksi = fields.get("ng_ksi", 0)
        service_type = fields.get("service_type", 0)
        tmsi = fields.get("tmsi", b"\x00\x00\x00\x00")
        buf.append(((ng_ksi & 0x0F) << 4) | (service_type & 0x0F))
        buf.extend(tmsi[:4] if isinstance(tmsi, bytes) else tmsi.encode()[:4])

    def _encode_authentication_response(
        self, msg_type: int, fields: Dict[str, Any], buf: bytearray
    ) -> None:
        if "authentication_response_parameter" in fields:
            self._encode_tlv(
                buf, IEI_AUTHENTICATION_RESPONSE_PARAMETER,
                fields["authentication_response_parameter"],
            )

    def _encode_authentication_failure(
        self, msg_type: int, fields: Dict[str, Any], buf: bytearray
    ) -> None:
        cause = fields.get("5gmm_cause", 0x15)
        self._encode_tv(buf, IEI_5GMM_CAUSE, cause)

    def _encode_security_mode_complete(
        self, msg_type: int, fields: Dict[str, Any], buf: bytearray
    ) -> None:
        if "nas_message_container" in fields:
            self._encode_tlv(
                buf, IEI_NAS_MESSAGE_CONTAINER,
                fields["nas_message_container"],
            )

    def _encode_pdu_session_establishment_request(
        self, msg_type: int, fields: Dict[str, Any], buf: bytearray
    ) -> None:
        pdu_type = fields.get("pdu_session_type", 1)
        ssc_mode = fields.get("ssc_mode", 1)
        buf.append(((pdu_type & 0x07) << 4) | (ssc_mode & 0x07))
        if "dnn" in fields:
            self._encode_tlv(buf, IEI_DNN, fields["dnn"])

    def _encode_pdu_session_modification_complete(
        self, msg_type: int, fields: Dict[str, Any], buf: bytearray
    ) -> None:
        pass

    def _encode_pdu_session_release_complete(
        self, msg_type: int, fields: Dict[str, Any], buf: bytearray
    ) -> None:
        pass

    def _encode_generic_ies(
        self, msg_type: int, fields: Dict[str, Any], buf: bytearray
    ) -> None:
        """Generic IE encoder: encode all fields as TLV using their IEI from the registry."""
        for name, value in fields.items():
            iei = self._field_name_to_iei(name)
            if iei is not None and iei in self.IE_REGISTRY:
                fmt, _ = self.IE_REGISTRY[iei]
                if value is None:
                    continue
                if fmt == IE_FORMAT_TV:
                    self._encode_tv(buf, iei, value)
                elif fmt == IE_FORMAT_TLV:
                    self._encode_tlv(buf, iei, value)
                elif fmt == IE_FORMAT_TLVE:
                    self._encode_tlve(buf, iei, value)

    # ─── IE Decoding ──────────────────────────────────────────

    def _decode_ies(self, msg_type: int, body: bytes) -> Dict[str, Any]:
        fields: Dict[str, Any] = {}
        offset = 0
        while offset < len(body):
            iei = body[offset]
            # Check if this byte is an IEI (first nibble non-zero for type IEIs)
            if iei in self.IE_REGISTRY:
                fmt, len_bytes = self.IE_REGISTRY[iei]
                offset += 1
                if fmt == IE_FORMAT_TV:
                    name = self._iei_to_field_name(iei)
                    fields[name] = body[offset] if offset < len(body) else None
                    offset += 1
                elif fmt == IE_FORMAT_TLV:
                    if offset < len(body):
                        ie_len = body[offset]
                        offset += 1
                        value = body[offset : offset + ie_len]
                        offset += ie_len
                        name = self._iei_to_field_name(iei)
                        fields[name] = value
                elif fmt == IE_FORMAT_TLVE:
                    if offset + 1 < len(body):
                        ie_len = struct.unpack("!H", body[offset : offset + 2])[0]
                        offset += 2
                        value = body[offset : offset + ie_len]
                        offset += ie_len
                        name = self._iei_to_field_name(iei)
                        fields[name] = value
            else:
                break  # Unknown IEI, stop parsing
        return fields

    # ─── Low-level IE encode helpers ──────────────────────────

    def _encode_tv(self, buf: bytearray, iei: int, value: Any) -> None:
        """Type-Value: 1 byte IEI + fixed-length value."""
        buf.append(iei & 0xFF)
        if isinstance(value, int):
            buf.append(value & 0xFF)
        elif isinstance(value, bytes):
            buf.extend(value)

    def _encode_tlv(self, buf: bytearray, iei: int, value: Any) -> None:
        """Type-Length-Value: 1 byte IEI + 1 byte length + value."""
        buf.append(iei & 0xFF)
        val_bytes = self._to_bytes(value)
        buf.append(len(val_bytes) & 0xFF)
        buf.extend(val_bytes)

    def _encode_tlve(self, buf: bytearray, iei: int, value: Any) -> None:
        """Type-Length-Value-Extended: 1 byte IEI + 2 byte length + value."""
        buf.append(iei & 0xFF)
        val_bytes = self._to_bytes(value)
        buf.extend(struct.pack("!H", len(val_bytes)))
        buf.extend(val_bytes)

    def _encode_mobile_identity(self, buf: bytearray, supi: str) -> None:
        """Encode SUCI/SUPI as mobile identity IE."""
        # Simplified: encode IMSI as BCD
        if supi.startswith("00101"):
            # IMSI-based SUPI
            imsi_str = supi  # Simplified
            identity_type = 1  # IMSI
            odd_even = len(imsi_str) % 2
            identity_len = 1 + (len(imsi_str) + 1) // 2
            buf.append(identity_len & 0xFF)
            first_byte = (identity_type & 0x07)
            if odd_even:
                first_byte |= 0x08
            buf.append(first_byte)
            # BCD encode
            for i in range(0, len(imsi_str) - 1, 2):
                bcd = (int(imsi_str[i + 1]) << 4) | int(imsi_str[i])
                buf.append(bcd)
            if odd_even:
                buf.append((0xF0 | int(imsi_str[-1])) & 0xFF)
        else:
            buf.append(0x01)
            buf.append(0xF0)

    # ─── Helpers ──────────────────────────────────────────────

    @staticmethod
    def _to_bytes(value: Any) -> bytes:
        if isinstance(value, bytes):
            return value
        elif isinstance(value, str):
            return value.encode()
        elif isinstance(value, int):
            n_bytes = max(1, (value.bit_length() + 7) // 8)
            return value.to_bytes(n_bytes, "big")
        elif isinstance(value, list):
            return b"".join(NAS5GSCodec._to_bytes(v) for v in value)
        return str(value).encode()

    @staticmethod
    def _field_name_to_iei(name: str) -> Optional[int]:
        mapping = {
            "suci": IEI_SUCI,
            "5g_guti": IEI_5G_GUTI,
            "nas_message_container": IEI_NAS_MESSAGE_CONTAINER,
            "ue_security_capability": IEI_UE_SECURITY_CAPABILITY,
            "nas_security_algorithms": IEI_NAS_SECURITY_ALGORITHMS,
            "5gmm_capability": IEI_5GMM_CAPABILITY,
            "mobile_identity": IEI_MOBILE_IDENTITY,
            "eap_message": IEI_EAP_MESSAGE,
            "abba": IEI_ABBA,
            "authentication_parameter_rand": IEI_AUTHENTICATION_PARAMETER_RAND,
            "authentication_parameter_autn": IEI_AUTHENTICATION_PARAMETER_AUTN,
            "authentication_response_parameter": IEI_AUTHENTICATION_RESPONSE_PARAMETER,
            "authentication_failure_parameter": IEI_AUTHENTICATION_FAILURE_PARAMETER,
            "5gs_registration_result": IEI_5GS_REGISTRATION_RESULT,
            "5gmm_cause": IEI_5GMM_CAUSE,
            "payload_container": IEI_PAYLOAD_CONTAINER,
            "dnn": IEI_DNN,
            "s_nssai": IEI_S_NSSAI,
            "request_type": IEI_REQUEST_TYPE,
            "pdu_session_type": IEI_PDU_SESSION_TYPE,
            "ssc_mode": IEI_SSC_MODE,
            "5gsm_capability": IEI_5GSM_CAPABILITY,
            "qos_rules": IEI_QOS_RULES,
            "5gsm_cause": IEI_5GSM_CAUSE,
            "pdu_address": IEI_PDU_ADDRESS,
            "session_ambr": IEI_SESSION_AMBR,
            "gprs_timer": IEI_GPRS_TIMER,
            "allowed_nssai": IEI_ALLOWED_NSSAI,
            "rejected_nssai": IEI_REJECTED_NSSAI,
            "t3346_value": IEI_T3346_VALUE,
            "t3448_value": IEI_T3448_VALUE,
        }
        return mapping.get(name.lower())

    @staticmethod
    def _iei_to_field_name(iei: int) -> str:
        mapping = {
            IEI_SUCI: "suci",
            IEI_5G_GUTI: "5g_guti",
            IEI_NAS_MESSAGE_CONTAINER: "nas_message_container",
            IEI_UE_SECURITY_CAPABILITY: "ue_security_capability",
            IEI_NAS_SECURITY_ALGORITHMS: "nas_security_algorithms",
            IEI_5GMM_CAPABILITY: "5gmm_capability",
            IEI_MOBILE_IDENTITY: "mobile_identity",
            IEI_EAP_MESSAGE: "eap_message",
            IEI_ABBA: "abba",
            IEI_AUTHENTICATION_PARAMETER_RAND: "authentication_parameter_rand",
            IEI_AUTHENTICATION_PARAMETER_AUTN: "authentication_parameter_autn",
            IEI_AUTHENTICATION_RESPONSE_PARAMETER: "authentication_response_parameter",
            IEI_AUTHENTICATION_FAILURE_PARAMETER: "authentication_failure_parameter",
            IEI_5GS_REGISTRATION_RESULT: "5gs_registration_result",
            IEI_5GMM_CAUSE: "5gmm_cause",
            IEI_PAYLOAD_CONTAINER: "payload_container",
            IEI_DNN: "dnn",
            IEI_S_NSSAI: "s_nssai",
            IEI_REQUEST_TYPE: "request_type",
            IEI_PDU_SESSION_TYPE: "pdu_session_type",
            IEI_SSC_MODE: "ssc_mode",
            IEI_5GSM_CAPABILITY: "5gsm_capability",
            IEI_QOS_RULES: "qos_rules",
            IEI_5GSM_CAUSE: "5gsm_cause",
            IEI_PDU_ADDRESS: "pdu_address",
            IEI_SESSION_AMBR: "session_ambr",
            IEI_GPRS_TIMER: "gprs_timer",
            IEI_ALLOWED_NSSAI: "allowed_nssai",
            IEI_REJECTED_NSSAI: "rejected_nssai",
            IEI_T3346_VALUE: "t3346_value",
            IEI_T3448_VALUE: "t3448_value",
            IEI_ADDITIONAL_5G_SECURITY_INFORMATION: "additional_5g_security_information",
        }
        return mapping.get(iei, f"ie_0x{iei:02x}")

    def _build_schemas(self) -> None:
        """Build MessageSchema objects for all supported message types."""
        common_5gmm_ies = [
            FieldDef("suci", FieldType.OCTET_STRING, optional=True),
            FieldDef("5g_guti", FieldType.OCTET_STRING, min_len=11, max_len=11, optional=True),
            FieldDef("ue_security_capability", FieldType.OCTET_STRING, min_len=2, max_len=8, optional=True),
            FieldDef("nas_security_algorithms", FieldType.OCTET_STRING, optional=True),
        ]

        self._schemas["Registration Request"] = MessageSchema(
            protocol="nas-5gs",
            message_type="Registration Request",
            message_name="Registration Request",
            fields=[
                FieldDef("5gs_registration_type", FieldType.INTEGER, constraint=FieldConstraint(range_min=0, range_max=7)),
                FieldDef("ng_ksi", FieldType.INTEGER, constraint=FieldConstraint(range_min=0, range_max=7)),
                FieldDef("5gs_mobile_identity_supi", FieldType.OCTET_STRING, min_len=3, max_len=16),
            ] + common_5gmm_ies,
        )

        self._schemas["Authentication Response"] = MessageSchema(
            protocol="nas-5gs",
            message_type="Authentication Response",
            message_name="Authentication Response",
            fields=[
                FieldDef("authentication_response_parameter", FieldType.OCTET_STRING, min_len=16, max_len=16, optional=True),
            ],
        )

        self._schemas["Security Mode Complete"] = MessageSchema(
            protocol="nas-5gs",
            message_type="Security Mode Complete",
            message_name="Security Mode Complete",
            fields=[
                FieldDef("nas_message_container", FieldType.OCTET_STRING, optional=True),
            ],
        )
