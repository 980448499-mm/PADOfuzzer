"""SBI (Service-Based Interface) codec — HTTP/2 + JSON/OpenAPI 3.0.

5G Core SBI per TS 29.500 series. All NF-to-NF communication uses:
  - HTTP/2 transport (TLS or plain TCP)
  - JSON request/response bodies
  - RESTful resource URIs
  - OpenAPI 3.0 schemas for request/response validation

Key SBI services:
  - Nnrf_NFManagement: NF register/discover
  - Namf_Communication: N1N2 message transfer
  - Nsmf_PDUSession: PDU session create/update/release
  - Nudm_UECM: UE context management
  - Nausf_UEAuthentication: UE authentication
  - Npcf_SMPolicyControl: SM policy create/update/delete

For fuzzing, we:
  1. Build/parse valid JSON bodies from schemas
  2. Corrupt JSON (type confusion, boundary values, null/missing fields)
  3. Manipulate HTTP/2 headers (pseudo-headers, content-type)
  4. Violate OpenAPI constraints (invalid enum, out-of-range, missing required)
"""

import json
import random as _random
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from src.codec.base import CodecContext, ParsedMessage, ProtocolCodec
from src.codec.schema import FieldDef, FieldType, MessageSchema


# ─── SBI Operation registry ──────────────────────────────────────

class SBIHttpMethod(Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


@dataclass
class SBIOperation:
    """Describes a single SBI service operation."""
    service: str  # e.g., "Nnrf_NFManagement"
    operation: str  # e.g., "NFRegister"
    method: SBIHttpMethod
    uri_template: str  # e.g., "/nnrf-nfm/v1/nf-instances/{nfInstanceId}"
    request_schema: Dict[str, Any] = field(default_factory=dict)
    response_schema: Dict[str, Any] = field(default_factory=dict)


# Registry of key SBI operations
SBI_OPERATIONS: Dict[str, SBIOperation] = {}

def _register(op: SBIOperation) -> SBIOperation:
    SBI_OPERATIONS[f"{op.service}/{op.operation}"] = op
    return op


_register(SBIOperation(
    "Nnrf_NFManagement", "NFRegister", SBIHttpMethod.PUT,
    "/nnrf-nfm/v1/nf-instances/{nfInstanceId}",
    request_schema={
        "type": "object",
        "required": ["nfInstanceId", "nfType", "nfStatus", "ipv4Addresses"],
        "properties": {
            "nfInstanceId": {"type": "string"},
            "nfType": {"type": "string", "enum": ["AMF", "SMF", "UPF", "NRF", "UDM", "AUSF", "PCF", "NSSF"]},
            "nfStatus": {"type": "string", "enum": ["REGISTERED", "SUSPENDED", "UNDISCOVERED"]},
            "ipv4Addresses": {"type": "array", "items": {"type": "string"}},
            "fqdn": {"type": "string"},
            "priority": {"type": "integer", "minimum": 0, "maximum": 65535},
        },
    },
))

_register(SBIOperation(
    "Nnrf_NFManagement", "NFDiscover", SBIHttpMethod.GET,
    "/nnrf-disc/v1/nf-instances",
    request_schema={
        "type": "object",
        "properties": {
            "nfType": {"type": "string"},
            "limit": {"type": "integer"},
        },
    },
))

_register(SBIOperation(
    "Nnrf_NFManagement", "NFAccessToken", SBIHttpMethod.POST,
    "/nnrf-nfm/v1/oauth2/token",
    request_schema={
        "type": "object",
        "required": ["grant_type", "nfInstanceId", "scope"],
        "properties": {
            "grant_type": {"type": "string", "enum": ["client_credentials"]},
            "nfInstanceId": {"type": "string"},
            "scope": {"type": "string"},
        },
    },
))

_register(SBIOperation(
    "Namf_Communication", "N1N2MessageTransfer", SBIHttpMethod.POST,
    "/namf-comm/v1/ue-contexts/{ueContextId}/n1-n2-messages",
    request_schema={
        "type": "object",
        "required": ["n1MessageContainer", "n2InfoContainer"],
        "properties": {
            "n1MessageContainer": {
                "type": "object",
                "required": ["n1MessageClass", "n1MessageContent"],
                "properties": {
                    "n1MessageClass": {"type": "string", "enum": ["5GMM", "SM", "SMS", "LPP"]},
                    "n1MessageContent": {"type": "object",
                        "properties": {
                            "contentId": {"type": "string"},
                        }},
                },
            },
            "n2InfoContainer": {
                "type": "object",
                "required": ["n2InformationClass"],
                "properties": {
                    "n2InformationClass": {"type": "string"},
                },
            },
            "pduSessionId": {"type": "integer"},
            "skipInd": {"type": "boolean"},
        },
    },
))

_register(SBIOperation(
    "Nsmf_PDUSession", "PDUSessionCreateSMContext", SBIHttpMethod.POST,
    "/nsmf-pdusession/v1/pdu-sessions/{pduSessionRef}/modify",
    request_schema={
        "type": "object",
        "required": ["supi", "dnn", "sNssai", "pduSessionId"],
        "properties": {
            "supi": {"type": "string", "pattern": "^imsi-[0-9]{5,15}$"},
            "dnn": {"type": "string"},
            "sNssai": {
                "type": "object",
                "required": ["sst", "sd"],
                "properties": {
                    "sst": {"type": "integer", "minimum": 1, "maximum": 255},
                    "sd": {"type": "string"},
                },
            },
            "pduSessionId": {"type": "integer", "minimum": 1, "maximum": 255},
            "pduSessionType": {"type": "string", "enum": ["IPV4", "IPV6", "IPV4V6", "ETHERNET", "UNSTRUCTURED"]},
            "sscMode": {"type": "string", "enum": ["SSC_MODE_1", "SSC_MODE_2", "SSC_MODE_3"]},
            "ueLocationInfo": {"type": "object"},
            "guami": {"type": "object"},
        },
    },
))

_register(SBIOperation(
    "Nausf_UEAuthentication", "UEAuthenticate", SBIHttpMethod.POST,
    "/nausf-auth/v1/ue-authentications",
    request_schema={
        "type": "object",
        "required": ["supiOrSuci", "servingNetworkName"],
        "properties": {
            "supiOrSuci": {"type": "string"},
            "servingNetworkName": {"type": "string"},
            "authType": {"type": "string", "enum": ["5G_AKA", "EAP_AKA_PRIME"]},
            "resynchronizationInfo": {"type": "object"},
        },
    },
))

_register(SBIOperation(
    "Nudm_UECM", "UEContextRegistration", SBIHttpMethod.PUT,
    "/nudm-uecm/v1/{ueId}/registrations/amf-3gpp-access",
    request_schema={
        "type": "object",
        "required": ["amfInstanceId", "guami"],
        "properties": {
            "amfInstanceId": {"type": "string"},
            "guami": {
                "type": "object",
                "required": ["plmnId", "amfId"],
                "properties": {
                    "plmnId": {"type": "string", "pattern": "^[0-9]{5,6}$"},
                    "amfId": {"type": "string"},
                },
            },
            "ratType": {"type": "string", "enum": ["NR", "EUTRA", "WLAN"]},
        },
    },
))

_register(SBIOperation(
    "Npcf_SMPolicyControl", "SMPolicyCreate", SBIHttpMethod.POST,
    "/npcf-smpolicycontrol/v1/sm-policies",
    request_schema={
        "type": "object",
        "required": ["supi", "pduSessionId", "dnn", "sNssai"],
        "properties": {
            "supi": {"type": "string"},
            "pduSessionId": {"type": "integer"},
            "dnn": {"type": "string"},
            "sNssai": {"type": "object"},
            "notificationUri": {"type": "string"},
        },
    },
))


# ─── HTTP/2 frame helpers ────────────────────────────────────────

class HTTP2Frame:
    """Minimal HTTP/2 frame representation for SBI fuzzing.

    In production, use h2 library; here we build frames manually
    for fuzzing control (header corruption, frame splitting, etc.).
    """

    def __init__(self, stream_id: int = 1):
        self.stream_id = stream_id
        self.pseudo_headers: Dict[str, str] = {}
        self.headers: Dict[str, str] = {}
        self.body: bytes = b""

    def set_request(self, method: str, path: str, authority: str = ""):
        self.pseudo_headers[":method"] = method
        self.pseudo_headers[":path"] = path
        self.pseudo_headers[":scheme"] = "https"
        self.pseudo_headers[":authority"] = authority or "5gc.local"

    def set_json_body(self, body: Dict[str, Any]):
        self.body = json.dumps(body, indent=2).encode("utf-8")
        self.headers["content-type"] = "application/json"
        self.headers["content-length"] = str(len(self.body))

    def encode_headers_block(self) -> bytes:
        """Encode HPACK-style header block (simplified for fuzzing).

        In a full implementation this would use real HPACK compression.
        For fuzzing, we encode as plain text to allow byte-level corruption.
        """
        lines = []
        for k, v in self.pseudo_headers.items():
            lines.append(f"{k}: {v}")
        for k, v in self.headers.items():
            lines.append(f"{k}: {v}")
        return "\r\n".join(lines).encode("utf-8")

    def to_bytes(self) -> bytes:
        """Serialize to a byte representation suitable for fuzzing."""
        hdr_block = self.encode_headers_block()
        # Simplified: concatenate headers block + body
        # In real HTTP/2, this would be proper frame format with length prefixes
        result = bytearray()
        result.extend(hdr_block)
        result.extend(b"\r\n\r\n")
        result.extend(self.body)
        return bytes(result)

    @staticmethod
    def from_bytes(data: bytes) -> "HTTP2Frame":
        """Parse HTTP/2 frame data back."""
        parts = data.split(b"\r\n\r\n", 1)
        hdr_block = parts[0].decode("utf-8", errors="replace") if parts else ""
        body = parts[1] if len(parts) > 1 else b""

        frame = HTTP2Frame()
        for line in hdr_block.split("\r\n"):
            if ": " in line:
                k, v = line.split(": ", 1)
                if k.startswith(":"):
                    frame.pseudo_headers[k] = v
                else:
                    frame.headers[k.lower()] = v

        frame.body = body
        return frame


# ─── SBI Codec ───────────────────────────────────────────────────

class SBICodec(ProtocolCodec):
    """SBI protocol codec for HTTP/2 + JSON fuzzing.

    Builds/parses SBI service operation messages.
    Supports JSON body manipulation for fuzzing.
    """

    protocol = "sbi"

    def __init__(self):
        self._schema_cache: Dict[str, Dict[str, Any]] = {}
        for key, op in SBI_OPERATIONS.items():
            self._schema_cache[key] = op.request_schema

    # ─── Public API ──────────────────────────────────────────────

    def encode(self, message: ParsedMessage, context: Optional[CodecContext] = None) -> bytes:
        sbi_op_key = message.message_type  # "Nnrf_NFManagement/NFRegister"
        op = SBI_OPERATIONS.get(sbi_op_key)

        method = message.fields.get("method", "POST")
        path = message.fields.get("path", "")
        if op and not path:
            path = op.uri_template

        body = message.fields.get("body", message.fields.get("json_body", {}))
        if isinstance(body, str):
            body_bytes = body.encode("utf-8")
        elif isinstance(body, dict):
            body_bytes = json.dumps(body, indent=2).encode("utf-8")
        elif isinstance(body, bytes):
            body_bytes = body
        else:
            body_bytes = json.dumps({}).encode("utf-8")

        authority = message.fields.get("authority", "5gc.local")
        extra_headers = message.fields.get("headers", {})

        frame = HTTP2Frame()
        if isinstance(method, SBIHttpMethod):
            method = method.value
        frame.set_request(method, path, authority)
        if body_bytes:
            frame.body = body_bytes
            frame.headers["content-type"] = "application/json"
            frame.headers["content-length"] = str(len(body_bytes))
        for k, v in extra_headers.items():
            frame.headers[k.lower()] = str(v)

        return frame.to_bytes()

    def decode(self, data: bytes, context: Optional[CodecContext] = None) -> ParsedMessage:
        frame = HTTP2Frame.from_bytes(data)

        method = frame.pseudo_headers.get(":method", "POST")
        path = frame.pseudo_headers.get(":path", "")
        auth = frame.pseudo_headers.get(":authority", "")

        # Guess operation from path
        op_key = self._guess_operation(method, path)
        op_name = op_key or f"{method} {path}"

        body: Dict[str, Any] = {}
        if frame.body:
            try:
                body = json.loads(frame.body.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                body = {"_raw_body": frame.body.hex()}

        fields: Dict[str, Any] = {
            "method": method,
            "path": path,
            "authority": auth,
            "body": body,
            "headers": dict(frame.headers),
        }

        return ParsedMessage(
            protocol=self.protocol,
            message_type=op_name,
            message_name=op_name,
            fields=fields,
            raw_bytes=data,
        )

    def get_message_schema(self, message_type: str) -> Optional[MessageSchema]:
        op = SBI_OPERATIONS.get(message_type)
        if op is None:
            return None

        req_schema = op.request_schema
        fields = self._json_schema_to_fields(req_schema)
        return MessageSchema(
            protocol=self.protocol,
            message_type=message_type,
            message_name=message_type,
            fields=fields,
        )

    def random_valid(self, message_type: str) -> ParsedMessage:
        op = SBI_OPERATIONS.get(message_type)

        if op:
            method = op.method.value
            path = op.uri_template
            body = self._generate_random_body(op.request_schema)
        else:
            method = "POST"
            path = "/"
            body = {}

        return ParsedMessage(
            protocol=self.protocol,
            message_type=message_type,
            message_name=message_type,
            fields={
                "method": method,
                "path": path,
                "authority": "5gc.local",
                "body": body,
            },
        )

    def get_mutable_fields(self, message_type: str) -> List[FieldDef]:
        schema = self.get_message_schema(message_type)
        if schema:
            return schema.get_mutable_fields()
        return [
            FieldDef("path", FieldType.OCTET_STRING),
            FieldDef("body", FieldType.SEQUENCE),
        ]

    # ─── SBI-specific fuzzing helpers ────────────────────────────

    def fuzz_json_body(self, body: Dict[str, Any], mutation_type: str) -> Dict[str, Any]:
        """Apply JSON-specific mutations to an SBI request body.

        mutation_type options:
          - "type_confusion": change field types (int→string, string→array, etc.)
          - "boundary": set integers to extreme values
          - "null_required": null out required fields
          - "extra_field": add unexpected fields
          - "empty_string": set string fields to empty
          - "oversized": set arrays/strings to large sizes
        """
        mutated = json.loads(json.dumps(body))  # deep copy

        if mutation_type == "type_confusion":
            for k in list(mutated.keys()):
                if isinstance(mutated[k], int):
                    mutated[k] = str(mutated[k])
                elif isinstance(mutated[k], str):
                    mutated[k] = _random.randint(0, 99999)

        elif mutation_type == "boundary":
            for k, v in mutated.items():
                if isinstance(v, int):
                    mutated[k] = _random.choice([-1, 0, 2**31 - 1, 2**32 - 1, 2**63 - 1])
                elif isinstance(v, dict):
                    mutated[k] = self.fuzz_json_body(v, "boundary")

        elif mutation_type == "null_required":
            required = body.keys() if isinstance(body, dict) else []
            if required:
                field = _random.choice(list(required))
                mutated[field] = None

        elif mutation_type == "extra_field":
            mutated[f"_fuzz_extra_{_random.randint(0, 1000)}"] = "injected_value"

        elif mutation_type == "empty_string":
            for k, v in mutated.items():
                if isinstance(v, str):
                    mutated[k] = ""
                elif isinstance(v, list):
                    mutated[k] = []
                elif isinstance(v, dict):
                    mutated[k] = {}

        elif mutation_type == "oversized":
            for k, v in mutated.items():
                if isinstance(v, str):
                    mutated[k] = "A" * 10000
                elif isinstance(v, list):
                    mutated[k] = [0] * 1000

        return mutated

    def corrupt_http2_header(self, data: bytes, header_name: str, header_value: str) -> bytes:
        """Inject or replace an HTTP/2 header for fuzzing."""
        frame = HTTP2Frame.from_bytes(data)
        frame.headers[header_name.lower()] = header_value
        return frame.to_bytes()

    def inject_pseudo_header(self, data: bytes, pseudo_name: str, value: str) -> bytes:
        """Add or modify an HTTP/2 pseudo-header."""
        frame = HTTP2Frame.from_bytes(data)
        frame.pseudo_headers[pseudo_name] = value
        return frame.to_bytes()

    def content_type_confusion(self, data: bytes, new_content_type: str) -> bytes:
        """Change Content-Type header. Tests content negotiation."""
        return self.corrupt_http2_header(data, "content-type", new_content_type)

    # ─── Helpers ─────────────────────────────────────────────────

    @staticmethod
    def get_operations() -> Dict[str, SBIOperation]:
        return dict(SBI_OPERATIONS)

    @staticmethod
    def get_operation_names() -> List[str]:
        return list(SBI_OPERATIONS.keys())

    def _guess_operation(self, method: str, path: str) -> Optional[str]:
        """Guess SBI operation from HTTP method and URI path."""
        for key, op in SBI_OPERATIONS.items():
            if op.method.value != method:
                continue
            template_start = op.uri_template.split("{")[0]
            if path.startswith(template_start):
                return key
        return None

    def _json_schema_to_fields(self, schema: Dict[str, Any]) -> List[FieldDef]:
        """Convert a JSON Schema object to FieldDef list."""
        fields: List[FieldDef] = []
        props = schema.get("properties", {})
        required = schema.get("required", [])

        for prop_name, prop_schema in props.items():
            json_type = prop_schema.get("type", "string")
            field_type = {
                "string": FieldType.OCTET_STRING,
                "integer": FieldType.INTEGER,
                "boolean": FieldType.INTEGER,
                "array": FieldType.SEQUENCE,
                "object": FieldType.SEQUENCE,
            }.get(json_type, FieldType.OCTET_STRING)

            fields.append(FieldDef(
                name=prop_name,
                field_type=field_type,
                optional=prop_name not in required,
                description=prop_schema.get("description", ""),
            ))

        return fields

    def _generate_random_body(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a random-but-valid JSON body from an OpenAPI schema."""
        body: Dict[str, Any] = {}
        props = schema.get("properties", {})

        for prop_name, prop_schema in props.items():
            json_type = prop_schema.get("type", "string")

            if "enum" in prop_schema:
                body[prop_name] = _random.choice(prop_schema["enum"])
            elif json_type == "string":
                if prop_name in ("supi",):
                    body[prop_name] = "imsi-001010123456789"
                elif prop_name in ("nfInstanceId", "amfInstanceId"):
                    body[prop_name] = f"{_random.choice(['AMF','SMF','UPF'])}-instance-{_random.randint(0,999):03d}"
                elif prop_name == "dnn":
                    body[prop_name] = _random.choice(["internet", "ims", "enterprise"])
                elif prop_name == "plmnId":
                    body[prop_name] = f"{_random.randint(100,999)}{_random.randint(10,99)}"
                else:
                    body[prop_name] = f"value-{_random.randint(0, 9999)}"
            elif json_type == "integer":
                lo = prop_schema.get("minimum", 0)
                hi = prop_schema.get("maximum", 65535)
                body[prop_name] = _random.randint(lo, min(hi, 99999))
            elif json_type == "boolean":
                body[prop_name] = _random.choice([True, False])
            elif json_type == "array":
                body[prop_name] = [f"item-{i}" for i in range(_random.randint(0, 3))]
            elif json_type == "object":
                body[prop_name] = self._generate_random_body(prop_schema)

        return body
