"""Abstract base class for protocol codecs."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Type, TypeVar

from src.codec.schema import FieldDef, FieldConstraint, MessageSchema


@dataclass
class ParsedMessage:
    protocol: str
    message_type: str
    message_name: str
    fields: Dict[str, Any] = field(default_factory=dict)
    raw_bytes: Optional[bytes] = None

    def get_field(self, path: str) -> Any:
        parts = path.split(".")
        current: Any = self.fields
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            elif isinstance(current, list):
                current = current[int(part)]
            else:
                return None
        return current

    def set_field(self, path: str, value: Any) -> None:
        parts = path.split(".")
        current: Any = self.fields
        for part in parts[:-1]:
            if isinstance(current, dict):
                current = current[part]
            elif isinstance(current, list):
                current = current[int(part)]
        last = parts[-1]
        if isinstance(current, dict):
            current[last] = value
        elif isinstance(current, list):
            current[int(last)] = value


T = TypeVar("T", bound="ProtocolCodec")


class ProtocolCodec(ABC):
    """Abstract base for protocol-specific codecs."""

    protocol: str = ""

    @abstractmethod
    def encode(self, msg: ParsedMessage) -> bytes:
        """Encode a parsed message to raw bytes."""

    @abstractmethod
    def decode(self, raw: bytes) -> ParsedMessage:
        """Decode raw bytes to a parsed message."""

    @abstractmethod
    def get_message_schema(self, message_type: str) -> Optional[MessageSchema]:
        """Return the schema for a given message type."""

    @abstractmethod
    def random_valid(self) -> ParsedMessage:
        """Generate a random valid message for corpus seeding."""

    def get_field(self, msg: ParsedMessage, path: str) -> Any:
        return msg.get_field(path)

    def set_field(self, msg: ParsedMessage, path: str, value: Any) -> None:
        msg.set_field(path, value)

    def get_message_types(self) -> List[str]:
        """Return all supported message types."""
        return []

    def roundtrip_check(self, msg: ParsedMessage) -> bool:
        """Verify encode(decode(raw)) produces identical parsed message."""
        encoded = self.encode(msg)
        decoded = self.decode(encoded)
        return decoded.message_type == msg.message_type


@dataclass
class CodecContext:
    security_enabled: bool = False
    ciphering_key: Optional[bytes] = None
    integrity_key: Optional[bytes] = None
    uplink_count: int = 0
    downlink_count: int = 0
