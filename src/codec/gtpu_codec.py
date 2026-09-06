"""GTP-U (GPRS Tunnelling Protocol - User plane) codec — TS 29.281.

N3/N9 interface between RAN/UPF/I-UPF. GTP-U v1 header over UDP:
  Version(3) | PT(1) | E(1) | S(1) | PN(1)
  Message Type (1 byte)
  Length (2 bytes)
  TEID (4 bytes)
  Sequence Number (2 bytes, optional)
  N-PDU Number (1 byte, optional)
  Next Extension Header Type (1 byte, optional)

Message types:
  0: G-PDU (user data T-PDU)
  1: Echo Request
  2: Echo Response
  255: End Marker

Extension headers per TS 29.281 clause 5.2:
  0x00: No more extension headers
  0x01: MBMS Support Indication
  0x10: UDP Port
  0x40: PDCP PDU Number
  0x85: PDU Session Container (5GS)
  0x86: NR RAN Container
"""

import struct
from typing import Any, Dict, List, Optional, Tuple

from src.codec.base import CodecContext, ParsedMessage, ProtocolCodec
from src.codec.schema import FieldDef, FieldType, MessageSchema


GTPU_MESSAGE_TYPES: Dict[int, str] = {
    0: "G-PDU",
    1: "Echo Request",
    2: "Echo Response",
    26: "Error Indication",
    31: "Supported Extension Headers Notification",
    254: "End Marker",
    255: "G-PDU (End Marker)",
}

GTPU_EXT_HEADER_TYPES: Dict[int, str] = {
    0x00: "No More Extension Headers",
    0x01: "MBMS Support Indication",
    0x10: "UDP Port",
    0x40: "PDCP PDU Number",
    0x85: "PDU Session Container",
    0x86: "NR RAN Container",
}


class GTPUExtensionHeader:
    """GTP-U extension header."""

    def __init__(self, ext_type: int, content: bytes = b""):
        self.ext_type = ext_type  # 0-255
        self.content = content

    @property
    def name(self) -> str:
        return GTPU_EXT_HEADER_TYPES.get(self.ext_type, f"Ext-{self.ext_type:#04x}")

    def encode(self) -> bytes:
        if self.ext_type == 0x00:
            return b"\x00"
        length = len(self.content)
        if length == 0:
            return struct.pack("!B", self.ext_type)
        return struct.pack("!BB", self.ext_type, length) + self.content

    @staticmethod
    def parse(data: bytes) -> Tuple["GTPUExtensionHeader", int]:
        """Parse extension header from data. Returns (header, bytes_consumed)."""
        if len(data) < 1:
            raise ValueError("Extension header too short")

        ext_type = data[0]
        if ext_type == 0x00:
            return GTPUExtensionHeader(ext_type, b""), 1

        if len(data) < 2:
            raise ValueError("Extension header too short for type > 0")

        length = data[1]
        content = data[2:2 + length] if length > 0 else b""
        consumed = 2 + length
        return GTPUExtensionHeader(ext_type, content), consumed


class GTPUHeader:
    """Parsed GTP-U header fields."""

    def __init__(
        self,
        version: int = 1,
        pt: int = 1,
        has_ext: bool = False,
        has_seq: bool = False,
        has_npdu: bool = False,
        msg_type: int = 0,
        length: int = 0,
        teid: int = 0,
        seq_no: int = 0,
        npdu_no: int = 0,
        next_ext_type: int = 0,
        ext_headers: Optional[List[GTPUExtensionHeader]] = None,
        payload: bytes = b"",
    ):
        self.version = version
        self.pt = pt
        self.has_ext = has_ext
        self.has_seq = has_seq
        self.has_npdu = has_npdu
        self.msg_type = msg_type
        self.length = length  # payload length
        self.teid = teid
        self.seq_no = seq_no
        self.npdu_no = npdu_no
        self.next_ext_type = next_ext_type
        self.ext_headers = ext_headers or []
        self.payload = payload

    @property
    def message_type_name(self) -> str:
        return GTPU_MESSAGE_TYPES.get(self.msg_type, f"Unknown-{self.msg_type}")

    def encode(self) -> bytes:
        """Encode GTP-U header to bytes (without payload)."""
        flags = (self.version << 5) | (self.pt << 4)
        if self.has_ext:
            flags |= 0x04
        if self.has_seq:
            flags |= 0x02
        if self.has_npdu:
            flags |= 0x01

        header = bytearray()
        header.append(flags)
        header.append(self.msg_type)
        # Length: rest of message after the 8-byte mandatory header
        length = len(self.payload)
        header.extend(struct.pack("!H", length))
        header.extend(struct.pack("!I", self.teid))

        if self.has_seq or self.has_npdu or self.has_ext:
            header.extend(struct.pack("!H", self.seq_no))
        if self.has_npdu:
            header.append(self.npdu_no)
        if self.has_ext:
            header.append(self.next_ext_type)

        for ext_hdr in self.ext_headers:
            header.extend(ext_hdr.encode())

        return bytes(header)

    @staticmethod
    def parse(data: bytes) -> "GTPUHeader":
        """Parse GTP-U header from bytes. Returns GTPUHeader with payload."""
        if len(data) < 8:
            raise ValueError(f"GTP-U header too short: {len(data)} < 8")

        header_byte = data[0]
        version = (header_byte >> 5) & 0x07
        pt = (header_byte >> 4) & 0x01
        has_ext = bool(header_byte & 0x04)
        has_seq = bool(header_byte & 0x02)
        has_npdu = bool(header_byte & 0x01)

        msg_type = data[1]
        length = struct.unpack("!H", data[2:4])[0]
        teid = struct.unpack("!I", data[4:8])[0]

        offset = 8
        seq_no = 0
        npdu_no = 0
        next_ext_type = 0
        ext_headers: List[GTPUExtensionHeader] = []

        if has_seq or has_npdu or has_ext:
            if len(data) >= offset + 2:
                seq_no = struct.unpack("!H", data[offset:offset + 2])[0]
                offset += 2
        if has_npdu:
            if len(data) >= offset + 1:
                npdu_no = data[offset]
                offset += 1
        if has_ext:
            if len(data) >= offset + 1:
                next_ext_type = data[offset]
                offset += 1

        # Parse extension headers
        if has_ext and len(data) > offset:
            ext_data = data[offset:]
            pos = 0
            while pos < len(ext_data):
                ext_hdr, consumed = GTPUExtensionHeader.parse(ext_data[pos:])
                ext_headers.append(ext_hdr)
                pos += consumed
                if ext_hdr.ext_type == 0x00:
                    break
            offset += pos

        payload = data[offset:offset + length] if length > 0 else b""

        return GTPUHeader(
            version=version, pt=pt, has_ext=has_ext, has_seq=has_seq,
            has_npdu=has_npdu, msg_type=msg_type, length=length, teid=teid,
            seq_no=seq_no, npdu_no=npdu_no, next_ext_type=next_ext_type,
            ext_headers=ext_headers, payload=payload,
        )


class GTPUCodec(ProtocolCodec):
    """GTP-U protocol codec for N3/N9 user-plane fuzzing.

    Handles GTP-U header encoding/decoding, extension headers,
    and user-plane payload manipulation.
    """

    protocol = "gtp-u"

    def encode(self, message: ParsedMessage, context: Optional[CodecContext] = None) -> bytes:
        msg_type_id = self._get_msg_type_id(message.message_type)
        fields = message.fields
        payload = fields.get("payload", fields.get("t_pdu", b""))
        if isinstance(payload, str):
            payload = payload.encode("utf-8")

        header = GTPUHeader(
            version=fields.get("version", 1),
            pt=fields.get("pt", 1),
            msg_type=msg_type_id,
            teid=fields.get("teid", 0),
            seq_no=fields.get("sequence_number", 0),
            has_seq=fields.get("has_seq", True),
            has_npdu=fields.get("has_npdu", False),
            has_ext=fields.get("has_ext", bool(fields.get("ext_headers"))),
            payload=payload,
        )

        # Handle extension headers
        ext_headers_raw = fields.get("ext_headers", [])
        if ext_headers_raw:
            header.has_ext = True
            for eh in ext_headers_raw:
                if isinstance(eh, GTPUExtensionHeader):
                    header.ext_headers.append(eh)
                elif isinstance(eh, dict):
                    header.ext_headers.append(GTPUExtensionHeader(
                        ext_type=eh.get("type", 0), content=eh.get("content", b"")
                    ))

        encoded_header = header.encode()
        return encoded_header + header.payload

    def decode(self, data: bytes, context: Optional[CodecContext] = None) -> ParsedMessage:
        header = GTPUHeader.parse(data)

        fields: Dict[str, Any] = {
            "version": header.version,
            "pt": header.pt,
            "teid": header.teid,
            "sequence_number": header.seq_no,
            "npdu_number": header.npdu_no,
            "has_seq": header.has_seq,
            "has_npdu": header.has_npdu,
            "has_ext": header.has_ext,
            "next_ext_type": header.next_ext_type,
            "t_pdu": header.payload,
        }

        if header.ext_headers:
            fields["ext_headers"] = [
                {"type": eh.ext_type, "name": eh.name, "content": eh.content}
                for eh in header.ext_headers
            ]

        return ParsedMessage(
            protocol=self.protocol,
            message_type=header.message_type_name,
            message_name=header.message_type_name,
            fields=fields,
            raw_bytes=data,
        )

    def get_message_schema(self, message_type: str) -> Optional[MessageSchema]:
        schemas = {
            "G-PDU": MessageSchema(
                protocol=self.protocol, message_type=message_type,
                fields=[
                    FieldDef("teid", FieldType.INTEGER, required=True, description="Tunnel Endpoint Identifier"),
                    FieldDef("sequence_number", FieldType.INTEGER, required=False),
                    FieldDef("t_pdu", FieldType.OCTET_STRING, required=True, description="User-plane payload (e.g., IP packet)"),
                    FieldDef("ext_headers", FieldType.SEQUENCE, required=False),
                ]),
            "Echo Request": MessageSchema(
                protocol=self.protocol, message_type=message_type,
                fields=[
                    FieldDef("teid", FieldType.INTEGER, required=False),
                    FieldDef("sequence_number", FieldType.INTEGER, required=False),
                    FieldDef("recovery", FieldType.INTEGER, required=False, description="Recovery IE value"),
                ]),
            "Echo Response": MessageSchema(
                protocol=self.protocol, message_type=message_type,
                fields=[
                    FieldDef("teid", FieldType.INTEGER, required=False),
                    FieldDef("sequence_number", FieldType.INTEGER, required=False),
                    FieldDef("recovery", FieldType.INTEGER, required=False),
                ]),
            "Error Indication": MessageSchema(
                protocol=self.protocol, message_type=message_type,
                fields=[
                    FieldDef("teid", FieldType.INTEGER, required=False),
                    FieldDef("t_pdu", FieldType.OCTET_STRING, required=False, description="Offending packet fragment"),
                ]),
            "End Marker": MessageSchema(
                protocol=self.protocol, message_type=message_type,
                fields=[
                    FieldDef("teid", FieldType.INTEGER, required=True),
                ]),
        }
        return schemas.get(message_type)

    def random_valid(self, message_type: str) -> ParsedMessage:
        import random as _random

        msg_type_id = self._get_msg_type_id(message_type)
        teid = _random.randint(1, 2**32 - 1) if msg_type_id != 1 else 0
        seq = _random.randint(0, 2**16 - 1)
        has_seq = msg_type_id in (0, 1, 2, 26)

        payload = b""
        if msg_type_id == 0:
            # Minimal IP packet as T-PDU
            payload = bytes([0x45, 0x00, 0x00, 0x14] + [_random.randint(0, 255) for _ in range(16)])
        elif msg_type_id == 255 or msg_type_id == 254:
            payload = b""

        return ParsedMessage(
            protocol=self.protocol,
            message_type=message_type,
            message_name=message_type,
            fields={
                "teid": teid,
                "sequence_number": seq,
                "has_seq": has_seq,
                "has_npdu": False,
                "has_ext": False,
                "version": 1,
                "pt": 1,
                "t_pdu": payload,
            },
        )

    def get_mutable_fields(self, message_type: str) -> List[FieldDef]:
        schema = self.get_message_schema(message_type)
        if schema:
            return schema.get_mutable_fields()
        return [
            FieldDef("teid", FieldType.INTEGER),
            FieldDef("sequence_number", FieldType.INTEGER),
            FieldDef("t_pdu", FieldType.OCTET_STRING),
        ]

    # ─── Fuzzing helpers ─────────────────────────────────────────

    def inject_extension_header(self, data: bytes, ext_type: int, content: bytes) -> bytes:
        """Inject a GTP-U extension header into an existing message.

        Used for PDU Session Container and NR RAN Container fuzzing.
        """
        hdr = GTPUHeader.parse(data)
        hdr.has_ext = True
        hdr.ext_headers.append(GTPUExtensionHeader(ext_type, content))
        hdr.ext_headers.append(GTPUExtensionHeader(0x00, b""))  # terminator
        return hdr.encode() + hdr.payload

    def corrupt_teid(self, data: bytes, new_teid: int) -> bytes:
        """Replace TEID in GTP-U header. Tests tunnel handling."""
        if len(data) < 8:
            return data
        corrupted = bytearray(data)
        corrupted[4:8] = struct.pack("!I", new_teid)
        return bytes(corrupted)

    def corrupt_length(self, data: bytes) -> bytes:
        """Set GTP-U length field to 0xFFFF. Tests buffer handling."""
        if len(data) < 4:
            return data
        corrupted = bytearray(data)
        corrupted[2:4] = b"\xff\xff"
        return bytes(corrupted)

    # ─── Helpers ─────────────────────────────────────────────────

    @staticmethod
    def _get_msg_type_id(message_type: str) -> int:
        for tid, tname in GTPU_MESSAGE_TYPES.items():
            if tname == message_type:
                return tid
        return 0

    @staticmethod
    def get_message_types() -> List[str]:
        return list(GTPU_MESSAGE_TYPES.values())

    @staticmethod
    def get_ext_header_types() -> Dict[int, str]:
        return dict(GTPU_EXT_HEADER_TYPES)

    def wrap_payload_as_gpdu(self, teid: int, payload: bytes, seq: int = 0) -> bytes:
        """Wrap a T-PDU payload as a G-PDU GTP-U message."""
        hdr = GTPUHeader(
            version=1, pt=1, msg_type=0, teid=teid,
            seq_no=seq, has_seq=True, payload=payload,
        )
        return hdr.encode() + payload
