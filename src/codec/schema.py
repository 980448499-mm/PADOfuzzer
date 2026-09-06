"""Message schema definitions for protocol-aware fuzzing."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class FieldType(Enum):
    INTEGER = "integer"
    ENUM = "enum"
    OCTET_STRING = "octet_string"
    BIT_STRING = "bit_string"
    SEQUENCE = "sequence"
    CHOICE = "choice"
    SEQUENCE_OF = "sequence_of"
    BOOLEAN = "boolean"
    NULL = "null"


@dataclass
class FieldConstraint:
    range_min: Optional[int] = None
    range_max: Optional[int] = None
    enum_values: Optional[List[Any]] = None
    pattern: Optional[str] = None
    required_fields: Optional[List[str]] = None
    fixed_length: Optional[int] = None
    min_length: Optional[int] = None
    max_length: Optional[int] = None


@dataclass
class FieldDef:
    name: str
    field_type: FieldType
    length: Optional[int] = None
    min_len: Optional[int] = None
    max_len: Optional[int] = None
    allowed_values: Optional[List[Any]] = None
    children: Optional[List["FieldDef"]] = None
    constraint: Optional[FieldConstraint] = None
    optional: bool = False
    description: str = ""


@dataclass
class MessageSchema:
    protocol: str
    message_type: str
    message_name: str
    fields: List[FieldDef] = field(default_factory=list)
    mandatory_fields: Set[str] = field(default_factory=set)
    constraints: Dict[str, FieldConstraint] = field(default_factory=dict)

    def get_field_def(self, name: str) -> Optional[FieldDef]:
        for f in self.fields:
            if f.name == name:
                return f
        return None

    def get_mutable_fields(self) -> List[FieldDef]:
        """Fields that can be mutated (non-fixed, non-enum where applicable)."""
        mutable: List[FieldDef] = []
        for f in self.fields:
            if f.field_type in (FieldType.OCTET_STRING, FieldType.INTEGER):
                mutable.append(f)
            elif f.field_type == FieldType.SEQUENCE and f.children:
                mutable.extend(f.children)
        return mutable

    def get_boundary_values(self, field_name: str) -> List[Any]:
        """Generate boundary test values for a field."""
        fd = self.get_field_def(field_name)
        if fd is None:
            return []
        values: List[Any] = []
        if fd.field_type == FieldType.INTEGER:
            if fd.constraint:
                lo = fd.constraint.range_min or 0
                hi = fd.constraint.range_max or 2**32 - 1
                values = [lo - 1, lo, lo + 1, hi - 1, hi, hi + 1, 0, -1, 2**31, 2**32]
            else:
                values = [0, 1, -1, 255, 256, 65535, 65536, 2**31, 2**32 - 1]
        elif fd.field_type == FieldType.ENUM and fd.allowed_values:
            values = [fd.allowed_values[0], fd.allowed_values[-1]]
            values.append("INVALID_ENUM_VALUE_FF")
        elif fd.field_type == FieldType.OCTET_STRING:
            values = [b"", b"\x00", b"\xff" * 256, b"A" * 65536]
        return values
