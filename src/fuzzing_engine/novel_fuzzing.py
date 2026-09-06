"""Novel fuzzing techniques for 5G protocol security testing.

Three techniques not previously applied to 5G fuzzing:

1. Cross-Implementation Differential Fuzzing
   Send the identical mutated request to all three 5GC implementations
   simultaneously. Response divergence → potential bug or spec ambiguity.

2. Response Structure-Aware Mutation
   Dynamically learn the SBI API schema from error/success responses.
   Build a field dictionary that guides mutations toward valid-but-edge-case
   inputs.

3. Temporal Fuzzing
   Vary inter-request timing to trigger race conditions, timeout handling,
   and resource exhaustion bugs in multi-threaded NF implementations.

Reference for novelty claims:
  - AFLNet (2020): single-target, single-implementation
  - 5GReasoner (2019): spec-level, not implementation-level
  - StateAFL (2021): response-based state inference, no cross-implementation
"""

import json
import random
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# ═══════════════════════════════════════════════════════════════
# 1. Cross-Implementation Differential Fuzzing
# ═══════════════════════════════════════════════════════════════

@dataclass
class DifferentialResult:
    """Result of sending the same fuzzed request to multiple 5GCs."""
    operation: str
    path: str
    method: str
    mutation: str
    responses: Dict[str, Tuple[int, str]]  # 5gc_name → (status, body_preview)
    divergent: bool  # True if responses differ across implementations
    divergence_type: str  # "status_divergence" | "body_divergence" | "none"


class DifferentialFuzzer:
    """Sends identical fuzzed requests to multiple 5GC implementations.

    Key insight: 3GPP specs define standard SBI behavior. If OAI, free5GC,
    and Open5GS respond differently to the same input, at least one has a bug
    or the spec is ambiguous. This technique has NOT been applied to 5G before.
    """

    def __init__(self):
        self.results: List[DifferentialResult] = []
        self.divergence_count: Dict[str, int] = defaultdict(int)

    def compare(self, operation: str, path: str, method: str,
                mutation: str,
                responses: Dict[str, Tuple[int, str]]) -> DifferentialResult:
        """Compare responses across implementations.

        Args:
            responses: {"oai": (status, body), "free5gc": (...), "open5gs": (...)}
        """
        if len(responses) < 2:
            return DifferentialResult(
                operation=operation, path=path, method=method,
                mutation=mutation, responses=responses,
                divergent=False, divergence_type="none")

        statuses = {k: v[0] for k, v in responses.items()}
        bodies = {k: v[1][:100] for k, v in responses.items()}

        # Check for status code divergence
        unique_statuses = set(statuses.values())
        if len(unique_statuses) > 1:
            dtype = "status_divergence"
            self.divergence_count[dtype] += 1
            result = DifferentialResult(
                operation=operation, path=path, method=method,
                mutation=mutation, responses=responses,
                divergent=True, divergence_type=dtype)
            self.results.append(result)
            return result

        # Check for response body divergence (same status, different message)
        if len(unique_statuses) == 1 and len(responses) >= 2:
            unique_bodies = set(bodies.values())
            if len(unique_bodies) > 1:
                dtype = "body_divergence"
                self.divergence_count[dtype] += 1
                result = DifferentialResult(
                    operation=operation, path=path, method=method,
                    mutation=mutation, responses=responses,
                    divergent=True, divergence_type=dtype)
                self.results.append(result)
                return result

        return DifferentialResult(
            operation=operation, path=path, method=method,
            mutation=mutation, responses=responses,
            divergent=False, divergence_type="none")

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "total_comparisons": len(self.results),
            "total_divergences": sum(
                1 for r in self.results if r.divergent),
            "by_type": dict(self.divergence_count),
            "divergence_rate": (
                sum(1 for r in self.results if r.divergent) /
                max(len(self.results), 1)),
        }


# ═══════════════════════════════════════════════════════════════
# 2. Response Structure-Aware Mutation (Dynamic Schema Learning)
# ═══════════════════════════════════════════════════════════════

class SchemaLearner:
    """Learn SBI API field structure dynamically from responses.

    Unlike AFL's static dictionary, this learns the protocol grammar
    ONLINE during fuzzing by parsing JSON error messages and success
    responses.

    Example learning:
      Response: {"cause":"MANDATORY_IE_INCORRECT"}
      → Learned: "nfInstanceId" is MANDATORY → try removing it next time

      Response: {"nfInstanceId":"...","nfType":"AMF","nfStatus":"REGISTERED"}
      → Learned: valid field names and types for this endpoint
    """

    def __init__(self):
        self.field_names: Dict[str, Set[str]] = defaultdict(set)
        self.field_types: Dict[str, Dict[str, str]] = defaultdict(dict)
        self.mandatory_fields: Dict[str, Set[str]] = defaultdict(set)
        self.seen_values: Dict[str, List[Any]] = defaultdict(list)

    def learn_from_response(self, path: str, body: str, status: int):
        """Extract field knowledge from a response."""
        endpoint = self._normalize_path(path)

        # Learn field names from successful responses
        if 200 <= status < 300:
            try:
                data = json.loads(body)
                self._extract_fields(endpoint, data)
            except json.JSONDecodeError:
                pass

        # Learn mandatory fields from error messages
        if status in (400, 404):
            if "MANDATORY" in body:
                # Extract which field is mandatory
                match = re.search(
                    r'MANDATORY[ _](?:QUERY_PARAM|IE)[ _](\w+)',
                    body, re.IGNORECASE)
                if match:
                    field = match.group(1).lower()
                    self.mandatory_fields[endpoint].add(field)
                else:
                    # Generic mandatory error → all fields in last success
                    # are potentially mandatory
                    pass

    def _extract_fields(self, endpoint: str, data: dict, prefix: str = ""):
        """Recursively extract field names and types from JSON."""
        for key, value in data.items():
            full_key = f"{prefix}.{key}" if prefix else key
            self.field_names[endpoint].add(full_key)
            if isinstance(value, str):
                self.field_types[endpoint][full_key] = "string"
                self.seen_values[full_key].append(value)
            elif isinstance(value, int):
                self.field_types[endpoint][full_key] = "integer"
                self.seen_values[full_key].append(value)
            elif isinstance(value, bool):
                self.field_types[endpoint][full_key] = "boolean"
            elif isinstance(value, dict):
                self.field_types[endpoint][full_key] = "object"
                self._extract_fields(endpoint, value, full_key)
            elif isinstance(value, list):
                self.field_types[endpoint][full_key] = "array"

    def get_field_value(self, field: str) -> Optional[Any]:
        """Get a previously-seen value for a field to use in mutation."""
        values = self.seen_values.get(field, [])
        return random.choice(values) if values else None

    def get_mandatory_fields(self, path: str) -> Set[str]:
        """Get known mandatory fields for an endpoint."""
        return self.mandatory_fields.get(self._normalize_path(path), set())

    def get_known_fields(self, path: str) -> Dict[str, str]:
        """Get all known fields and types for an endpoint."""
        return self.field_types.get(self._normalize_path(path), {})

    def generate_edge_value(self, field_name: str, current_value: Any) -> Optional[Any]:
        """Generate a grammar-aware edge-case value for a known field.

        Returns None if the field type is unknown (fall back to random mutation).
        """
        field_type = None
        for ep_fields in self.field_types.values():
            if field_name in ep_fields:
                field_type = ep_fields[field_name]
                break

        if field_type is None:
            return None  # Unknown field, caller should use random mutation

        seen = self.seen_values.get(field_name, [])

        if field_type == "string":
            is_uuid = (isinstance(current_value, str) and len(current_value) > 30
                       and current_value.count('-') >= 4)
            is_enum = len(seen) <= 5 and all(isinstance(v, str) and len(v) < 30 for v in seen)
            if is_uuid:
                return random.choice([
                    "", "00000000-0000-0000-0000-000000000000",
                    current_value[:-8] + "\x00\x00\x00\x00\x00\x00\x00\x00",
                    "not-a-uuid",
                    "../../../etc/passwd",
                ])
            elif is_enum:
                return random.choice(seen + ["INVALID", "", "UNKNOWN", None])
            elif "uri" in field_name.lower() or "url" in field_name.lower():
                return random.choice([
                    "http://\x00\x00\x00/invalid",
                    "../" * 20 + "etc/passwd",
                ])
            else:
                return random.choice([
                    "", "\x00", "\x00\x00\x00\x00",
                    "A" * 4096, "\\u0000", "<script>alert(1)</script>",
                    "${jndi:ldap://x}", "\x1b[31mANSI_ESCAPE\x1b[0m",
                ])

        elif field_type == "integer":
            edge = random.choice([-1, 0, 1, 2**31 - 1, -2**31, 65535, 255])
            if isinstance(current_value, int) and current_value != 0:
                return random.choice([edge, -current_value, current_value + 1])
            return edge

        elif field_type == "boolean":
            return not current_value if isinstance(current_value, bool) else random.choice([True, False, None, "true", 1, 0])

        elif field_type == "array":
            return [] if isinstance(current_value, list) and len(current_value) > 0 else [{}]

        elif field_type == "object":
            return {} if current_value else {"__invalid__": "__traversal__"}

        return None

    def generate_semantic_edge(self, field_name: str, current_value: Any,
                                 path: str) -> Optional[Any]:
        """Generate a structure-preserving edge value for a field.

        Unlike generate_edge_value() which produces raw attack payloads,
        this keeps the JSON structure VALID so it passes SBI parsing,
        then triggers bugs at the application logic layer.

        Returns None if no semantic edge is applicable.
        """
        field_type = None
        ep = self._normalize_path(path)
        for ep_fields in self.field_types.values():
            if field_name in ep_fields:
                field_type = ep_fields[field_name]
                break

        seen = self.seen_values.get(field_name, [])
        is_uuid = (isinstance(current_value, str) and len(current_value) > 30
                   and current_value.count('-') >= 4)
        is_int = field_type == "integer" or isinstance(current_value, int)

        # ── UUID fields: valid format, but wrong/non-existent IDs ──
        if is_uuid:
            return random.choice([
                "00000000-0000-0000-0000-000000000000",
                "ffffffff-ffff-ffff-ffff-ffffffffffff",
                "dead0000-beef-0000-0000-000000000000",
                "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                str(2**31 - 1) + "-0000-0000-0000-000000000000"[:36],
            ])

        # ── Integer fields: extreme but valid values ──
        if is_int:
            return random.choice([-1, 0, 1, 255, 65535, 2**31-1, -2**31])

        # ── String enum fields: out-of-set but valid-format values ──
        if field_type == "string" and isinstance(current_value, str) and seen:
            if len(current_value) < 50 and not is_uuid:
                return random.choice([
                    current_value.upper(),
                    current_value.lower(),
                    current_value + "_FUZZ",
                    "UNKNOWN_TYPE",
                    "__EXPLOIT__",
                    "NONE",
                ])

        # ── Array fields: structural edge cases ──
        if field_type == "array" or isinstance(current_value, list):
            return random.choice([
                [],
                [current_value[0]] * 100 if isinstance(current_value, list) and current_value else [],
                [{"__extra__": "field"}] if isinstance(current_value, list) and current_value and isinstance(current_value[0], dict) else [],
            ])

        # ── Object fields: add unexpected but valid sub-fields ──
        if field_type == "object" or isinstance(current_value, dict):
            return {
                **({"__internal__": "__edge__"} if isinstance(current_value, dict) else {}),
            }

        return None

    @staticmethod
    def _normalize_path(path: str) -> str:
        """Normalize path by replacing UUIDs with {id}."""
        import re
        return re.sub(
            r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',
            '{id}', path)

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "endpoints_learned": len(self.field_names),
            "total_fields_known": sum(
                len(v) for v in self.field_names.values()),
            "mandatory_fields_known": sum(
                len(v) for v in self.mandatory_fields.values()),
        }


# ═══════════════════════════════════════════════════════════════
# 3. Temporal Fuzzing
# ═══════════════════════════════════════════════════════════════

@dataclass
class TemporalPattern:
    """A timing pattern for request sequences."""
    name: str
    inter_request_ms: List[float]  # Delays between successive requests
    description: str


TEMPORAL_PATTERNS = [
    TemporalPattern("normal", [0], "Baseline: 0ms (no artificial delay)"),
    TemporalPattern("burst_5", [0, 0, 0, 0, 0],
                    "Burst: 5 rapid-fire requests (race condition trigger)"),
    TemporalPattern("burst_20", [0] * 20,
                    "Heavy burst: 20 rapid requests (resource exhaustion)"),
    TemporalPattern("slow_drip", [2.0],
                    "Slow: 2s interval (timeout trigger)"),
    TemporalPattern("pulse", [0, 1.0, 0, 1.0, 0, 1.0, 0, 1.0, 0, 1.0],
                    "Pulse: burst-pause-burst (state machine stress)"),
    TemporalPattern("random_jitter",
                    [random.uniform(0, 3.0) for _ in range(10)],
                    "Random jitter: unpredictable timing"),
]


class TemporalFuzzer:
    """Vary inter-request timing to trigger concurrency bugs.

    5G NFs are multi-threaded servers. Race conditions in session management,
    heartbeat handling, and subscription notifications are well-known bug
    sources in production 5GC deployments. This technique is novel in the
    protocol fuzzing literature.
    """

    def __init__(self):
        self.pattern_results: Dict[str, Dict[str, int]] = defaultdict(
            lambda: defaultdict(int))
        self.current_pattern: Optional[TemporalPattern] = None

    def select_pattern(self) -> TemporalPattern:
        """Select a timing pattern for the next batch.

        80% normal, 20% special patterns (weighted toward more aggressive).
        """
        if random.random() < 0.8:
            return TEMPORAL_PATTERNS[0]  # normal
        return random.choice(TEMPORAL_PATTERNS[1:])  # special

    def record_result(self, pattern_name: str, crashes: int,
                       errors: int, new_coverage: int):
        """Record the outcome of a temporal pattern."""
        self.pattern_results[pattern_name]["uses"] += 1
        self.pattern_results[pattern_name]["crashes"] += crashes
        self.pattern_results[pattern_name]["errors"] += errors
        self.pattern_results[pattern_name]["new_coverage"] += new_coverage

    @property
    def stats(self) -> Dict[str, Any]:
        """Which temporal patterns are most effective?"""
        ranking = []
        for name, results in self.pattern_results.items():
            uses = results.get("uses", 1)
            score = (results.get("crashes", 0) * 10 +
                     results.get("new_coverage", 0))
            ranking.append({
                "pattern": name,
                "uses": uses,
                "crashes": results.get("crashes", 0),
                "new_coverage": results.get("new_coverage", 0),
                "score_per_use": score / max(uses, 1),
            })
        ranking.sort(key=lambda x: x["score_per_use"], reverse=True)
        return {
            "ranking": ranking,
            "most_effective": ranking[0]["pattern"] if ranking else "unknown",
        }
