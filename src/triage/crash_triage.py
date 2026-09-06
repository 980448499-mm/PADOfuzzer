"""Crash triage: deduplication, root cause classification, and reproduction.

Multi-strategy dedup (in priority order):
  1. Stack hash — SHA256 of top 5 stack frames
  2. Crash address — same faulting PC
  3. Signal + NF — same signal on same NF type
  4. Input proximity — similar input bytes (edit distance)

Root cause categories with ASAN/signal pattern matching:
  - buffer_overflow (heap/stack/global)
  - null_deref (null pointer dereference)
  - use_after_free
  - double_free
  - integer_overflow
  - type_confusion
  - assertion_fail
  - memory_leak
  - divide_by_zero
  - uninitialized_access
"""

import hashlib
import json
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import UUID, uuid4

from src import CrashRecord, CrashSeverity, FiveGCImpl, NFType, ProtocolType


@dataclass
class CrashGroup:
    """A group of deduplicated crashes with the same root cause."""

    group_id: UUID = field(default_factory=uuid4)
    representative: Optional[CrashRecord] = None
    members: List[CrashRecord] = field(default_factory=list)
    root_cause: str = "unknown"
    severity: CrashSeverity = CrashSeverity.INFO
    first_seen: float = 0.0
    last_seen: float = 0.0
    reproduce_script: str = ""

    @property
    def count(self) -> int:
        return len(self.members)

    @property
    def affected_nfs(self) -> Set[str]:
        return {c.target_nf.value for c in self.members if c.target_nf}


class CrashTriage:
    """Deduplicate and categorize crashes from fuzzing campaigns.

    Multi-strategy approach ensures unique bugs are not merged
    while true duplicates are correctly identified.
    """

    # ASAN pattern → root cause mapping
    ASAN_PATTERNS: Dict[str, re.Pattern] = {
        "buffer_overflow_heap": re.compile(
            r"heap-buffer-overflow", re.IGNORECASE
        ),
        "buffer_overflow_stack": re.compile(
            r"stack-buffer-overflow", re.IGNORECASE
        ),
        "buffer_overflow_global": re.compile(
            r"global-buffer-overflow", re.IGNORECASE
        ),
        "use_after_free": re.compile(
            r"heap-use-after-free", re.IGNORECASE
        ),
        "double_free": re.compile(
            r"double.free|invalid free", re.IGNORECASE
        ),
        "null_deref": re.compile(
            r"(?:null pointer|NULL.*dereference|SEGV on unknown address 0x0+)",
            re.IGNORECASE,
        ),
        "integer_overflow": re.compile(
            r"(?:signed integer overflow|division by zero|integer overflow)",
            re.IGNORECASE,
        ),
        "memory_leak": re.compile(
            r"(?:memory leak|Indirect leak|Direct leak)", re.IGNORECASE
        ),
        "type_confusion": re.compile(
            r"(?:type confusion|dispatch.*invalid|bad_function_call)", re.IGNORECASE
        ),
        "use_after_return": re.compile(
            r"stack-use-after-return", re.IGNORECASE
        ),
        "uninitialized_access": re.compile(
            r"(?:uninitialized|use-of-uninitialized)", re.IGNORECASE
        ),
        "assertion_fail": re.compile(
            r"Assertion.*failed", re.IGNORECASE
        ),
        "stack_exhaustion": re.compile(
            r"(?:stack.*overflow|out of stack)", re.IGNORECASE
        ),
    }

    # Signal → root cause mapping
    SIGNAL_CAUSE_MAP: Dict[str, str] = {
        "SIGSEGV": "segmentation_fault",
        "SIGABRT": "abort_called",
        "SIGBUS": "bus_error",
        "SIGFPE": "arithmetic_error",
        "SIGILL": "illegal_instruction",
    }

    def __init__(self):
        self.groups: List[CrashGroup] = []
        self._signatures: Set[str] = set()

    def triage(self, crashes: List[CrashRecord]) -> List[CrashGroup]:
        """Deduplicate and triage a list of crashes.

        Returns deduplicated crash groups.
        """
        for crash in crashes:
            self._classify_and_insert(crash)
        return self.groups

    def deduplicate(self, crashes: List[CrashRecord]) -> List[CrashRecord]:
        """Return only unique crashes (one per group)."""
        groups = self.triage(crashes)
        return [g.representative for g in groups if g.representative]

    # ─── Core dedup and classification ────────────────────────

    def _classify_and_insert(self, crash: CrashRecord) -> None:
        """Classify a crash and insert into the appropriate group."""
        # Compute multi-factor dedup signature
        dedup_key = self._compute_dedup_key(crash)
        crash.triage_hash = dedup_key

        # Check if already seen
        if dedup_key in self._signatures:
            # Find existing group and add
            for group in self.groups:
                if group.group_id.hex[:16] in dedup_key or dedup_key in self._signatures:
                    for member in group.members:
                        if member.triage_hash == dedup_key:
                            group.members.append(crash)
                            group.last_seen = crash.timestamp
                            return

        # New unique crash
        root_cause = self.classify_root_cause(crash)
        severity = self._assess_severity(crash, root_cause)
        crash.root_cause_category = root_cause
        crash.severity = severity

        group = CrashGroup(
            representative=crash,
            members=[crash],
            root_cause=root_cause,
            severity=severity,
            first_seen=crash.timestamp,
            last_seen=crash.timestamp,
        )
        self.groups.append(group)
        self._signatures.add(dedup_key)

    def _compute_dedup_key(self, crash: CrashRecord) -> str:
        """Multi-factor dedup hash.

        Priority chain:
          stack_hash > crash_addr > signal+nf > asan_hash > input_hash
        """
        parts: List[str] = []

        # Layer 1: Stack hash (most reliable)
        if crash.stack_frames:
            stack_repr = json.dumps(
                [{
                    "addr": f.address,
                    "func": f.function_name,
                    "file": f.file_name,
                    "line": f.line_number,
                } for f in crash.stack_frames[:5]],
                sort_keys=True,
                default=str,
            )
            stack_hash = hashlib.sha256(stack_repr.encode()).hexdigest()[:16]
            parts.append(f"stack:{stack_hash}")

        # Layer 2: Crash address
        if crash.crash_address is not None:
            parts.append(f"addr:{crash.crash_address:#x}")

        # Layer 3: Signal + NF combination
        if crash.crash_signal and crash.target_nf:
            parts.append(f"sig:{crash.crash_signal}:{crash.target_nf.value}")

        # Layer 4: ASAN report hash
        if crash.asan_report:
            asan_hash = hashlib.sha256(
                crash.asan_report.encode()
            ).hexdigest()[:12]
            parts.append(f"asan:{asan_hash}")

        # Layer 5: Input proximity (simplified — use first 16 bytes)
        if crash.input_pdu and len(crash.input_pdu) > 8:
            input_hash = hashlib.sha256(
                crash.input_pdu[:64]
            ).hexdigest()[:12]
            parts.append(f"inp:{input_hash}")

        if not parts:
            parts.append(f"time:{crash.timestamp}")

        return "|".join(parts)

    def classify_root_cause(self, crash: CrashRecord) -> str:
        """Classify crash root cause using ASAN output and signal analysis.

        Priority:
          1. ASAN report parsing (most accurate)
          2. Signal type analysis
          3. Log message pattern matching
        """
        # Method 1: ASAN patterns
        if crash.asan_report:
            for category, pattern in self.ASAN_PATTERNS.items():
                if pattern.search(crash.asan_report):
                    return category

        # Method 2: Signal type
        if crash.crash_signal:
            return self.SIGNAL_CAUSE_MAP.get(crash.crash_signal, "unknown_crash")

        # Method 3: Fallback
        return "unknown"

    @staticmethod
    def _assess_severity(crash: CrashRecord, root_cause: str) -> CrashSeverity:
        """Assess crash severity based on root cause category."""
        critical_causes = {
            "use_after_free", "double_free", "buffer_overflow_heap",
            "buffer_overflow_global", "segmentation_fault",
        }
        high_causes = {
            "buffer_overflow_stack", "null_deref", "type_confusion",
            "use_after_return", "uninitialized_access",
        }
        medium_causes = {
            "integer_overflow", "memory_leak", "assertion_fail",
            "stack_exhaustion",
        }

        if root_cause in critical_causes:
            return CrashSeverity.CRITICAL
        elif root_cause in high_causes:
            return CrashSeverity.HIGH
        elif root_cause in medium_causes:
            return CrashSeverity.MEDIUM
        return CrashSeverity.LOW

    # ─── Statistics and reporting ──────────────────────────────

    def get_statistics(self) -> Dict[str, Any]:
        """Get crash statistics summary."""
        total_crashes = sum(g.count for g in self.groups)
        unique_crashes = len(self.groups)

        severity_dist: Dict[str, int] = defaultdict(int)
        cause_dist: Dict[str, int] = defaultdict(int)
        nf_dist: Dict[str, int] = defaultdict(int)

        for group in self.groups:
            severity_dist[group.severity.value] += 1
            cause_dist[group.root_cause] += 1
            for member in group.members:
                if member.target_nf:
                    nf_dist[member.target_nf.value] += 1

        return {
            "total_crashes": total_crashes,
            "unique_crashes": unique_crashes,
            "dedup_ratio": total_crashes / max(unique_crashes, 1),
            "severity_distribution": dict(severity_dist),
            "root_cause_distribution": dict(cause_dist),
            "nf_distribution": dict(nf_dist),
            "groups": [
                {
                    "id": str(g.group_id),
                    "root_cause": g.root_cause,
                    "severity": g.severity.value,
                    "count": g.count,
                    "first_seen": g.first_seen,
                    "affected_nfs": list(g.affected_nfs),
                }
                for g in self.groups
            ],
        }

    def generate_reproduce_script(self, group: CrashGroup) -> str:
        """Generate a Python script to reproduce a crash group."""
        crash = group.representative
        if not crash or not crash.input_pdu:
            return "# Cannot generate: no input PDU available"

        pdu_hex = crash.input_pdu.hex()

        script = f'''#!/usr/bin/env python3
"""Reproduction script for crash {group.group_id}
Root cause: {group.root_cause}
Severity: {group.severity.value}
Signal: {crash.crash_signal}
NF: {crash.target_nf.value if crash.target_nf else "unknown"}
"""

import socket
import struct

# Crash input PDU (hex encoded)
INPUT_PDU = bytes.fromhex("{pdu_hex}")

def reproduce():
    """Replay crash-triggering input."""
    # Connect to target NF
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)

    try:
        sock.connect(("172.23.0.20", 38412))  # AMF SCTP/N2
        sock.send(INPUT_PDU)
        response = sock.recv(4096)
        print(f"Response: {{response.hex()}}")
    except socket.timeout:
        print("No response — target may have crashed")
    except ConnectionRefusedError:
        print("Connection refused — target likely crashed")
    finally:
        sock.close()

if __name__ == "__main__":
    reproduce()
'''
        group.reproduce_script = script
        return script

    def reset(self) -> None:
        """Reset triage state for a new campaign."""
        self.groups.clear()
        self._signatures.clear()
