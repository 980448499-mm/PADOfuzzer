"""Cross-protocol mutation engine for 5G protocol fuzzing.

Implements field-level injection across 5G protocol layers:
  NAS-5GS ⇄ SBI (HTTP/JSON) ⇄ NGAP ⇄ PFCP ⇄ GTP-U

Attack model:
  1. Extract a field from protocol A's PDU (e.g., SUCI from NAS)
  2. Inject it into protocol B's PDU at a semantically matching position
     (e.g., NAS SUCI → SBI JSON supi field)
  3. Protocol confusion: send protocol A's raw bytes to protocol B's port

Supports the ablation experiment: --no-cross-protocol disables this module.
"""

import json
import os
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Field mapping: protocol_source → SBI JSON field target
# Maps semantically equivalent fields across protocol boundaries
CROSS_PROTOCOL_FIELD_MAP: Dict[str, List[Tuple[str, str, str]]] = {
    # (source_protocol, source_field_path, target_sbi_field)
    "nas": [
        ("nas-5gs", "supiOrSuci", "supi"),
        ("nas-5gs", "supiOrSuci", "supiOrSuci"),
        ("nas-5gs", "imei", "pei"),
        ("nas-5gs", "sst", "sNssai.sst"),
        ("nas-5gs", "sd", "sNssai.sd"),
    ],
    "ngap": [
        ("ngap", "amfUeNgapId", "amfUeNgapId"),
        ("ngap", "ranUeNgapId", "ranUeNgapId"),
        ("ngap", "tac", "tai.tac"),
        ("ngap", "plmnIdentity", "plmnId"),
    ],
    "pfcp": [
        ("pfcp", "seid", "seid"),
        ("pfcp", "pdrId", "pdrId"),
        ("pfcp", "farId", "farId"),
        ("pfcp", "urrId", "urrId"),
    ],
}


# Pre-generated NAS/NGAP/PFCP "seed" PDUs with known field values.
# These are hand-crafted valid PDUs that we extract semantically
# meaningful fields from. In production, these would be harvested
# from benign traffic traces.
CROSS_PROTOCOL_SEEDS: Dict[str, List[bytes]] = {
    "nas": [
        # Registration Request (simplified, valid bit pattern)
        b'\x7e\x00\x41\x01\x01\x02\xf0\x70\x00\x01\x00\x02\x10\x32\x54\x76',
        # Service Request
        b'\x7e\x00\x4c\x01\x02\x03\xf0\x70\x00\x01\x00\x02',
        # PDU Session Establishment Request
        b'\x7e\x00\x67\x01\x00\x03\x12\x01\x01\x02\x03\x04',
    ],
    "ngap": [
        # NGSetup Request
        b'\x00\x15\x00\x0d\x00\x00\x01\x00\x1b\x00\x08\x00\x00\xf1\x10\x00\x00\x00\x01',
        # Initial UE Message
        b'\x00\x0f\x00\x45\x00\x00\x03\x00\x1b\x00\x08\x00\x00\xf1\x10\x00\x00\x00\x02',
    ],
    "pfcp": [
        # PFCP Association Setup Request
        b'\x21\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x01\x00\x3a\x00\x05\x00\x01\x02\x03\x04',
    ],
}

# Pre-parsed field values extracted from the seeds above.
# (raw_bytes are decoded to these table entries for injection)
CROSS_PROTOCOL_FIELD_VALUES: Dict[str, List[Dict[str, Any]]] = {
    "nas": [
        {"supiOrSuci": "imsi-001010000000001", "imei": "123456789012345",
         "sst": 1, "sd": "010203"},
        {"supiOrSuci": "suci-0-208-93-0000-0-0-0000000001",
         "sst": 2, "sd": "112233"},
        {"supiOrSuci": "", "imei": "", "sst": 3, "sd": "ffffff"},
    ],
    "ngap": [
        {"amfUeNgapId": 1, "ranUeNgapId": 2, "tac": "0001",
         "plmnIdentity": "02f899"},
        {"amfUeNgapId": 0xFFFF_FFFF, "ranUeNgapId": 0,
         "tac": "FFFF", "plmnIdentity": "000000"},
        {"amfUeNgapId": -1, "ranUeNgapId": 999999,
         "tac": "\x00\x01", "plmnIdentity": None},
    ],
    "pfcp": [
        {"seid": 0, "pdrId": 1, "farId": 2, "urrId": 3},
        {"seid": 0xFFFFFFFF_FFFFFFFF, "pdrId": 0, "farId": 65535, "urrId": -1},
        {"seid": None, "pdrId": -1, "farId": 0, "urrId": 9999999},
    ],
}

# Protocol confusion payloads: raw bytes designed to look like
# one protocol but sent to another protocol's port.
PROTOCOL_CONFUSION_PAYLOADS: Dict[str, List[bytes]] = {
    "nas_to_sbi": [
        b'\x7e\x00\x41\x01\x01\x02\xf0\x70',  # NAS RR as HTTP body
        b'\x00\x00\x00\x00\x00\x00\x00\x00' * 16,  # zero-fill
    ],
    "ngap_to_sbi": [
        b'\x00\x15\x00\x0d\x00\x00\x01\x00',  # NGSetup as HTTP body
        b'\xff\xff\xff\xff' * 64,              # max-fill
    ],
    "pfcp_to_sbi": [
        b'\x21\x00\x00\x0c\x00\x00\x00\x00',  # PFCP as HTTP body
        b'\x01\x02\x03\x04\x05\x06\x07\x08' * 32,
    ],
}


@dataclass
class CrossProtocolMutation:
    """Result of a cross-protocol mutation."""
    strategy: str  # "field_injection" | "protocol_confusion" | "multi_protocol"
    source_protocol: str
    target_protocol: str
    injected_field: Optional[str] = None
    injected_value: Optional[Any] = None
    raw_payload: Optional[bytes] = None


class CrossProtocolMutator:
    """Provides cross-protocol mutations for the fuzzing engine.

    Usage:
        mutator = CrossProtocolMutator()
        mutation = mutator.mutate(sbi_body, sbi_path)
        if mutation:
            # Apply the mutation to the SBI request
            mutated_body, mutated_path = mutation.apply(sbi_body, sbi_path)
    """

    def __init__(
        self,
        enabled: bool = True,
        injection_probability: float = 0.3,
        confusion_probability: float = 0.1,
    ):
        self.enabled = enabled
        self.injection_prob = injection_probability
        self.confusion_prob = confusion_probability
        self._mutation_count = 0
        self._injection_count = 0
        self._confusion_count = 0

    @property
    def stats(self) -> Dict[str, int]:
        return {
            "total_mutations": self._mutation_count,
            "field_injections": self._injection_count,
            "protocol_confusions": self._confusion_count,
        }

    def mutate(
        self, body: Optional[Dict], path: str
    ) -> Optional[Tuple[Optional[Dict], str, Dict[str, Any]]]:
        """Apply a cross-protocol mutation to an SBI request.

        Args:
            body: SBI JSON body (may be None for GET/DELETE)
            path: SBI URI path

        Returns:
            (mutated_body, mutated_path, metadata) or None if no mutation applied
        """
        if not self.enabled:
            return None

        self._mutation_count += 1

        # Decide mutation type
        if random.random() < self.confusion_prob:
            return self._protocol_confusion(body, path)
        elif body and random.random() < self.injection_prob:
            return self._field_injection(body, path)
        else:
            # Random byte injection from raw protocol seeds
            return self._raw_injection(body, path)

    def _field_injection(
        self, body: Dict, path: str
    ) -> Optional[Tuple[Dict, str, Dict[str, Any]]]:
        """Inject a field from NAS/NGAP/PFCP into SBI JSON."""
        self._injection_count += 1

        # Pick a source protocol
        source_proto = random.choice(["nas", "ngap", "pfcp"])
        mappings = CROSS_PROTOCOL_FIELD_MAP.get(source_proto, [])
        if not mappings:
            return None

        # Pick a field mapping
        proto_name, source_field, sbi_field = random.choice(mappings)

        # Get a pre-parsed value for this field
        field_pool = CROSS_PROTOCOL_FIELD_VALUES.get(source_proto, [])
        if not field_pool:
            return None
        entry = random.choice(field_pool)
        value = entry.get(source_field)

        if value is None:
            return None

        # Inject into SBI body
        mutated = json.loads(json.dumps(body))
        self._set_nested(mutated, sbi_field, value)

        metadata = {
            "cross_protocol": True,
            "strategy": "field_injection",
            "source_protocol": proto_name,
            "source_field": source_field,
            "target_field": sbi_field,
            "injected_value": str(value)[:100],
        }

        return mutated, path, metadata

    def _protocol_confusion(
        self, body: Optional[Dict], path: str
    ) -> Optional[Tuple[Optional[Dict], str, Dict[str, Any]]]:
        """Replace SBI body with raw protocol bytes."""
        self._confusion_count += 1

        conf_type = random.choice(["nas_to_sbi", "ngap_to_sbi", "pfcp_to_sbi"])
        payloads = PROTOCOL_CONFUSION_PAYLOADS.get(conf_type, [])
        if not payloads:
            return None

        raw = random.choice(payloads)
        source_proto = conf_type.split("_")[0]

        # Return raw bytes as the body (not JSON)
        metadata = {
            "cross_protocol": True,
            "strategy": "protocol_confusion",
            "source_protocol": source_proto,
            "raw_payload_size": len(raw),
        }

        return raw, path, metadata

    def _raw_injection(
        self, body: Optional[Dict], path: str
    ) -> Optional[Tuple[Optional[Dict], str, Dict[str, Any]]]:
        """Inject raw bytes from NAS/NGAP/PFCP seeds into SBI fields."""
        if body is None:
            return None

        self._injection_count += 1
        source_proto = random.choice(["nas", "ngap", "pfcp"])
        seeds = CROSS_PROTOCOL_SEEDS.get(source_proto, [])
        if not seeds:
            return None

        raw = random.choice(seeds)

        # Inject raw bytes into a random SBI field
        mutated = json.loads(json.dumps(body))
        candidate_fields = self._find_string_fields(mutated)
        if not candidate_fields:
            return None

        target = random.choice(candidate_fields)
        # Navigate to the target and set
        parts = target.split(".")
        current = mutated
        for part in parts[:-1]:
            if isinstance(current, dict):
                current = current[part]
            elif isinstance(current, list) and part.isdigit():
                current = current[int(part)]
            else:
                break
        else:
            last = parts[-1]
            if isinstance(current, dict) and last in current:
                current[last] = raw.hex()[:64]

        metadata = {
            "cross_protocol": True,
            "strategy": "raw_injection",
            "source_protocol": source_proto,
            "target_field": target,
            "raw_bytes_hex": raw.hex()[:64],
        }

        return mutated, path, metadata

    @staticmethod
    def _find_string_fields(obj: Any, prefix: str = "") -> List[str]:
        """Recursively find all string-typed fields in a dict."""
        result = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                key = f"{prefix}.{k}" if prefix else k
                if isinstance(v, str):
                    result.append(key)
                elif isinstance(v, dict):
                    result.extend(
                        CrossProtocolMutator._find_string_fields(v, key))
        return result

    @staticmethod
    def _set_nested(obj: Dict, field_path: str, value: Any) -> None:
        """Set a nested field by dot-separated path (creates intermediate dicts)."""
        parts = field_path.split(".")
        current = obj
        for part in parts[:-1]:
            if part not in current:
                current[part] = {}
            current = current[part]
        current[parts[-1]] = value
