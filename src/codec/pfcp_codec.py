"""PFCP (Packet Forwarding Control Protocol) codec — TS 29.244.

N4 interface between SMF and UPF. TLV encoding:
  Type (2 bytes) | Length (2 bytes) | Value (variable)

Key message types:
  50-57: Node-level (Association, Node Report, Session Set Deletion)
  60-67: Session-level (Session Establishment/Modification/Deletion/Report)
"""

import struct
from typing import Any, Dict, List, Optional, Tuple

from src.codec.base import CodecContext, ParsedMessage, ProtocolCodec
from src.codec.schema import FieldDef, FieldType, MessageSchema


# ─── Message types ──────────────────────────────────────────────

PFCP_MESSAGE_TYPES: Dict[int, str] = {
    50: "PFCP Association Setup Request",
    51: "PFCP Association Setup Response",
    52: "PFCP Association Update Request",
    53: "PFCP Association Update Response",
    54: "PFCP Association Release Request",
    55: "PFCP Association Release Response",
    56: "PFCP Node Report Request",
    57: "PFCP Node Report Response",
    58: "PFCP Session Set Deletion Request",
    59: "PFCP Session Set Deletion Response",
    60: "PFCP Session Establishment Request",
    61: "PFCP Session Establishment Response",
    62: "PFCP Session Modification Request",
    63: "PFCP Session Modification Response",
    64: "PFCP Session Deletion Request",
    65: "PFCP Session Deletion Response",
    66: "PFCP Session Report Request",
    67: "PFCP Session Report Response",
}

# ─── IE type identifiers ─────────────────────────────────────────

PFCP_IE_TYPES: Dict[int, str] = {
    1: "Create PDR",
    2: "PDI",
    3: "Create FAR",
    4: "Forwarding Parameters",
    5: "Duplicating Parameters",
    6: "Create URR",
    7: "Create QER",
    8: "Created PDR",
    9: "Update PDR",
    10: "Update FAR",
    11: "Update QER",
    12: "Remove PDR",
    13: "Remove FAR",
    14: "Remove URR",
    15: "Remove QER",
    16: "Created TRAFFIC ENDPOINT",
    17: "Created Traffic Endpoint",
    18: "Update Traffic Endpoint",
    19: "Remove Traffic Endpoint",
    20: "Create Traffic Endpoint",
    21: "Created Traffic Endpoint (dup)",
    22: "Update Traffic Endpoint (dup)",
    23: "Remove Traffic Endpoint (dup)",
    24: "Create MAR",
    25: "Update MAR",
    26: "Remove MAR",
    27: "Created MAR",
    28: "Update MAR (dup)",
    29: "Remove MAR (dup)",
    38: "Node ID",
    39: "Node Report Type",
    40: "User Plane Path Failure Report",
    41: "User Plane Path Recovery Report",
    46: "Application ID",
    50: "F-TEID",
    51: "Network Instance",
    52: "UE IP Address",
    53: "Packet Rate",
    54: "Outer Header Creation",
    55: "Outer Header Removal",
    56: "Recovery Time Stamp",
    57: "F-SEID",
    58: "SDF Filter",
    59: "Application Instance ID",
    60: "PDI",
    61: "Forwarding Parameters",
    62: "Duplicating Parameters",
    63: "URR",
    64: "FAR",
    65: "QER",
    66: "Update PDI",
    67: "Update FAR",
    68: "Update QER",
    69: "BAR",
    70: "Update BAR",
    71: "Remove BAR",
    73: "Usage Report Trigger",
    74: "URR ID",
    75: "Sx-NSEI",
    76: "Created PDR",
    77: "Created FAR",
    78: "Created QER",
    79: "Node Features",
    80: "PFCP Association Release Request",
    81: "Graceful Release Period",
    82: "PDN Type",
    83: "Failed Rule ID",
    84: "Time Quota",
    85: "Volume Quota",
    86: "Time Threshold",
    87: "Volume Threshold",
    90: "PFCP Session Retention Information",
    91: "UE IP address Pool Identity",
    92: "Alternative SMF IP Address",
    93: "Packet Replication and Detection Carry On",
    94: "SMF Set ID",
    95: "Quota Validity Time",
    100: "Ethernet Packet Filter",
    101: "MAC address",
    102: "C-TAG",
    103: "S-TAG",
    104: "Ethertype",
    105: "QFI",
    106: "MBR",
    107: "GBR",
    110: "Redundant Transmission Parameters",
    128: "Load Control Information",
    129: "Overload Control Information",
    131: "Usage Report",
    134: "Downlink Data Service Information",
    135: "Downlink Data Notification Delay",
    142: "User ID",
    144: "Trace Information",
    146: "Framed Routing",
    147: "Framed Routing IPv6",
    148: "Event Quota",
    149: "Event Threshold",
    152: "Measurement Period",
    153: "Measurement Information",
    156: "URR Usage Report Trigger",
}

PFCP_IE_TYPE_IDS = {name: tid for tid, name in PFCP_IE_TYPES.items()}

# ─── PFCP Header ─────────────────────────────────────────────────

# PFCP header: 4 bytes version (bit 0) + spare + message type + length
# After header: SEID (8 bytes, 0 if not applicable) + sequence number (3 bytes)
# + spare + message priority + optional fields


class PFCPCodec(ProtocolCodec):
    """PFCP protocol codec for N4 interface fuzzing.

    Implements encode/decode/schema for PFCP messages.
    TLV format: Type(2) | Length(2) | Value(variable)
    """

    protocol = "pfcp"

    def __init__(self):
        self.version = 1

    # ─── Public API ──────────────────────────────────────────────

    def encode(self, message: ParsedMessage, context: Optional[CodecContext] = None) -> bytes:
        msg_type = message.message_type
        msg_type_id = self._get_message_type_id(msg_type)

        # Build IE payload
        ie_payload = b""
        for field_name, value in message.fields.items():
            ie_data = self._encode_field(field_name, value)
            if ie_data:
                ie_payload += ie_data

        # SEID from context or fields
        seid = message.fields.get("seid", 0)
        seq_no = message.fields.get("sequence_number", 0)

        # Build full message
        return self._build_pfcp_message(msg_type_id, seid, seq_no, ie_payload)

    def decode(self, data: bytes, context: Optional[CodecContext] = None) -> ParsedMessage:
        if len(data) < 4:
            raise ValueError("PFCP message too short")

        header = struct.unpack("!BB", data[:2])
        version_and_spare = header[0]
        version = (version_and_spare >> 5) & 0x07
        spare1 = version_and_spare & 0x1F if version == 1 else 0
        msg_type = header[1]
        msg_length = struct.unpack("!H", data[2:4])[0]

        offset = 4
        seid = 0
        seq_no = 0
        seid_present = bool(data[0] & 0x01)

        if seid_present:
            if len(data) >= 12:
                seid = struct.unpack("!Q", data[4:12])[0]
                offset = 12
        else:
            offset = 4

        if len(data) >= offset + 3:
            seq_raw = data[offset:offset + 3]
            seq_no = (seq_raw[0] << 16) | (seq_raw[1] << 8) | seq_raw[2]
            offset += 3

        # Parse IEs
        fields: Dict[str, Any] = {"seid": seid, "sequence_number": seq_no}
        ie_bytes = data[offset:]
        fields.update(self._parse_ies(ie_bytes))

        return ParsedMessage(
            protocol=self.protocol,
            message_type=PFCP_MESSAGE_TYPES.get(msg_type, f"Unknown-{msg_type}"),
            message_name=PFCP_MESSAGE_TYPES.get(msg_type, f"Unknown-{msg_type}"),
            fields=fields,
            raw_bytes=data,
        )

    def get_message_schema(self, message_type: str) -> Optional[MessageSchema]:
        msg_type_id = PFCP_IE_TYPE_IDS.get(message_type, PFCP_IE_TYPE_IDS.get(
            message_type, None))

        schemas = {
            "PFCP Association Setup Request": MessageSchema(
                protocol="pfcp", message_type=message_type, message_name=message_type,
                fields=[
                    FieldDef("node_id", FieldType.OCTET_STRING, optional=False, description="Node ID (FQDN or IPv4/IPv6)"),
                    FieldDef("recovery_time_stamp", FieldType.INTEGER, optional=False, description="Recovery timestamp"),
                    FieldDef("node_features", FieldType.INTEGER, optional=True, description="Supported features"),
                ]),
            "PFCP Association Setup Response": MessageSchema(
                protocol="pfcp", message_type=message_type, message_name=message_type,
                fields=[
                    FieldDef("node_id", FieldType.OCTET_STRING, optional=False),
                    FieldDef("recovery_time_stamp", FieldType.INTEGER, optional=False),
                    FieldDef("node_features", FieldType.INTEGER, optional=True),
                    FieldDef("cause", FieldType.INTEGER, optional=True),
                ]),
            "PFCP Session Establishment Request": MessageSchema(
                protocol="pfcp", message_type=message_type, message_name=message_type,
                fields=[
                    FieldDef("node_id", FieldType.OCTET_STRING, optional=True),
                    FieldDef("f_seid", FieldType.OCTET_STRING, optional=False, description="Fully Qualified SEID"),
                    FieldDef("create_pdr", FieldType.OCTET_STRING, optional=True),
                    FieldDef("create_far", FieldType.OCTET_STRING, optional=True),
                    FieldDef("create_qer", FieldType.OCTET_STRING, optional=True),
                    FieldDef("create_urr", FieldType.OCTET_STRING, optional=True),
                    FieldDef("create_bar", FieldType.OCTET_STRING, optional=True),
                    FieldDef("pdn_type", FieldType.INTEGER, optional=True),
                    FieldDef("ue_ip_address", FieldType.OCTET_STRING, optional=True),
                ]),
            "PFCP Session Establishment Response": MessageSchema(
                protocol="pfcp", message_type=message_type, message_name=message_type,
                fields=[
                    FieldDef("f_seid", FieldType.OCTET_STRING, optional=False),
                    FieldDef("node_id", FieldType.OCTET_STRING, optional=True),
                    FieldDef("cause", FieldType.INTEGER, optional=True),
                    FieldDef("created_pdr", FieldType.OCTET_STRING, optional=True),
                    FieldDef("created_far", FieldType.OCTET_STRING, optional=True),
                ]),
            "PFCP Session Modification Request": MessageSchema(
                protocol="pfcp", message_type=message_type, message_name=message_type,
                fields=[
                    FieldDef("f_seid", FieldType.OCTET_STRING, optional=False),
                    FieldDef("update_pdr", FieldType.OCTET_STRING, optional=True),
                    FieldDef("update_far", FieldType.OCTET_STRING, optional=True),
                    FieldDef("update_qer", FieldType.OCTET_STRING, optional=True),
                    FieldDef("remove_pdr", FieldType.OCTET_STRING, optional=True),
                    FieldDef("remove_far", FieldType.OCTET_STRING, optional=True),
                    FieldDef("create_pdr", FieldType.OCTET_STRING, optional=True),
                ]),
            "PFCP Session Deletion Request": MessageSchema(
                protocol="pfcp", message_type=message_type, message_name=message_type,
                fields=[
                    FieldDef("f_seid", FieldType.OCTET_STRING, optional=False),
                ]),
            "PFCP Node Report Request": MessageSchema(
                protocol="pfcp", message_type=message_type, message_name=message_type,
                fields=[
                    FieldDef("node_id", FieldType.OCTET_STRING, optional=False),
                    FieldDef("node_report_type", FieldType.INTEGER, optional=False),
                    FieldDef("user_plane_path_failure_report", FieldType.OCTET_STRING, optional=True),
                ]),
        }

        return schemas.get(message_type)

    def random_valid(self, message_type: str) -> ParsedMessage:
        import random as _random
        schema = self.get_message_schema(message_type)
        fields: Dict[str, Any] = {}

        if schema:
            for field_def in schema.fields:
                if field_def.field_type == FieldType.INTEGER:
                    fields[field_def.name] = _random.randint(0, 2**32 - 1)
                elif field_def.field_type == FieldType.OCTET_STRING:
                    fields[field_def.name] = bytes(_random.randint(0, 255)
                                                   for _ in range(_random.randint(4, 32)))
                else:
                    fields[field_def.name] = bytes(_random.randint(0, 255)
                                                   for _ in range(_random.randint(1, 16)))

        if "seid" not in fields:
            seid = _random.randint(1, 2**64 - 1)
            msg_type_id = self._get_message_type_id(message_type)
            if msg_type_id >= 60:
                fields["seid"] = seid
        fields.setdefault("sequence_number", _random.randint(1, 2**24 - 1))

        return ParsedMessage(
            protocol=self.protocol,
            message_type=message_type,
            message_name=message_type,
            fields=fields,
        )

    def get_mutable_fields(self, message_type: str) -> List[FieldDef]:
        schema = self.get_message_schema(message_type)
        if schema:
            return schema.get_mutable_fields()
        return []

    # ─── Internal helpers ────────────────────────────────────────

    def _build_pfcp_message(self, msg_type: int, seid: int, seq_no: int,
                             ie_payload: bytes) -> bytes:
        """Build full PFCP message with header, SEID, sequence number, and IEs."""
        seid_present = (seid != 0)
        version_byte = (self.version << 5) | (1 if seid_present else 0)

        total_length = 4  # header
        if seid_present:
            total_length += 8  # SEID
        total_length += 3  # sequence number
        total_length += len(ie_payload)

        header = struct.pack("!BBH", version_byte, msg_type, total_length)
        result = bytearray(header)

        if seid_present:
            result.extend(struct.pack("!Q", seid & 0xFFFFFFFFFFFFFFFF))

        seq_bytes = bytes([(seq_no >> 16) & 0xFF, (seq_no >> 8) & 0xFF, seq_no & 0xFF])
        result.extend(seq_bytes)
        result.extend(ie_payload)

        return bytes(result)

    def _parse_ies(self, data: bytes) -> Dict[str, Any]:
        """Parse TLV-encoded IEs from byte data."""
        fields: Dict[str, Any] = {}
        offset = 0
        while offset + 4 <= len(data):
            ie_type = struct.unpack("!H", data[offset:offset + 2])[0]
            ie_length = struct.unpack("!H", data[offset + 2:offset + 4])[0]
            offset += 4

            if offset + ie_length > len(data):
                break

            ie_value = data[offset:offset + ie_length]
            offset += ie_length

            ie_name = PFCP_IE_TYPES.get(ie_type, f"ie_{ie_type}")
            fields[ie_name] = ie_value

        return fields

    def _encode_field(self, field_name: str, value: Any) -> bytes:
        """Encode a single field into TLV format."""
        ie_type = PFCP_IE_TYPE_IDS.get(field_name)

        if ie_type is None:
            # Try common aliases
            alias_map = {
                "node_id": "Node ID",
                "f_seid": "F-SEID",
                "recovery_time_stamp": "Recovery Time Stamp",
                "cause": "PFCP Association Release Request",
                "ue_ip_address": "UE IP Address",
                "pdn_type": "PDN Type",
                "node_features": "Node Features",
                "node_report_type": "Node Report Type",
                "create_pdr": "Create PDR",
                "create_far": "Create FAR",
                "create_qer": "Create QER",
                "create_urr": "Create URR",
                "update_pdr": "Update PDR",
                "update_far": "Update FAR",
                "update_qer": "Update QER",
                "remove_pdr": "Remove PDR",
                "remove_far": "Remove FAR",
                "created_pdr": "Created PDR",
                "created_far": "Created FAR",
                "created_qer": "Created QER",
                "application_id": "Application ID",
            }
            ie_type = PFCP_IE_TYPE_IDS.get(alias_map.get(field_name, field_name))

        if ie_type is None:
            return b""  # Unknown field, skip

        if isinstance(value, int):
            val_bytes = struct.pack("!I", value)
        elif isinstance(value, bytes):
            val_bytes = value
        elif isinstance(value, str):
            val_bytes = value.encode("utf-8")
        else:
            val_bytes = bytes(value)

        tlv = struct.pack("!HH", ie_type, len(val_bytes)) + val_bytes
        return tlv

    @staticmethod
    def _get_message_type_id(message_type: str) -> int:
        for tid, tname in PFCP_MESSAGE_TYPES.items():
            if tname == message_type:
                return tid
        return 0

    # ─── Fuzzing helpers ─────────────────────────────────────────

    def get_message_types(self) -> List[str]:
        return list(PFCP_MESSAGE_TYPES.values())

    def get_ie_types(self) -> Dict[int, str]:
        return dict(PFCP_IE_TYPES)

    def inject_unknown_ie(self, data: bytes, ie_type: int, ie_value: bytes) -> bytes:
        """Inject an arbitrary TLV IE into an existing PFCP message.

        Useful for fuzzing: insert unexpected or malformed IEs.
        """
        tlv = struct.pack("!HH", ie_type, len(ie_value)) + ie_value
        # Parse header to find IE payload boundary
        if len(data) < 4:
            return data + tlv

        # Insert before last 4 bytes of existing IEs
        payload_start = self._find_payload_start(data)
        return data[:payload_start] + tlv + data[payload_start:]

    @staticmethod
    def _find_payload_start(data: bytes) -> int:
        """Find the start of IE payload after header+SEID+sequence fields."""
        offset = 4  # header
        if data[0] & 0x01:  # SEID present
            offset += 8
        return offset + 3  # after sequence number

    def corrupt_tlv_length(self, ie_data: bytes) -> bytes:
        """Corrupt the length field of a TLV IE for fuzzing."""
        if len(ie_data) < 4:
            return ie_data
        # Set length to 0xFFFF regardless of actual value
        return ie_data[:2] + b"\xff\xff" + ie_data[4:]
