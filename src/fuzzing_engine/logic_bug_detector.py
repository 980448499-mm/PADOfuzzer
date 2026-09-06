"""Logic bug detector for memory-safe 5GC implementations (Go-based free5GC).

Unlike C/C++ where bugs manifest as crashes (SIGSEGV/SIGABRT), Go programs
exhibit bugs through:

  1. HTTP 500 with panic stack traces → caught panics (Go's recover())
  2. Response anomalies → unexpected status/body for given input
  3. State machine violations → FSM transition that shouldn't exist
  4. Resource anomalies → memory/goroutine growth over time
  5. Error message inconsistency → same input, different errors

This module extracts these signals from fuzzing data to flag potential bugs
in memory-safe targets.
"""

import json
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("logic_bug_detector")


@dataclass
class LogicBug:
    """A potential logic bug detected in a memory-safe target."""
    category: str  # "panic_caught", "state_violation", "response_anomaly",
                   # "resource_leak", "error_inconsistency"
    severity: str  # "high", "medium", "low"
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    reproduce_hint: Optional[str] = None


class LogicBugDetector:
    """Detects logic bugs from fuzzing response data.

    Works alongside the crash-based detector for C/C++ targets.
    """

    def __init__(self):
        self.bugs: List[LogicBug] = []
        # Tracking state
        self._response_history: Dict[str, List[Dict]] = defaultdict(list)
        self._error_counts: Dict[str, int] = defaultdict(int)
        self._panic_patterns: Set[str] = set()

    def analyze_response(self, status: int, body: str, path: str,
                         mutation: str, target_nf: str) -> Optional[LogicBug]:
        """Analyze a single response for logic bug signals."""
        bug = None

        # Signal 1: Caught panic (Go recover() → HTTP 500 with stack trace)
        if status == 500:
            bug = self._detect_caught_panic(body, path, target_nf)
            if not bug:
                bug = self._detect_json_parse_error(body, path, target_nf, mutation)

        # Signal 2: Response anomaly (200 with error body, or 4xx with success body)
        if not bug and status == 200:
            bug = self._detect_response_anomaly(status, body, path, target_nf)

        # Signal 3: Track for pattern-based detection
        self._response_history[target_nf].append({
            "status": status, "body": body[:500], "path": path,
            "mutation": mutation,
        })

        if bug:
            self.bugs.append(bug)
        return bug

    def analyze_logs(self, logs: str, nf_name: str) -> List[LogicBug]:
        """Parse container logs for panic traces and error patterns."""
        bugs = []

        # Go panic trace pattern
        panic_re = re.compile(
            r'panic:\s*(.+?)(?:\n\n|\ngoroutine \d+ \[.+\]:)', re.DOTALL)
        for match in panic_re.finditer(logs):
            panic_msg = match.group(1).strip()[:200]
            key = f"{nf_name}:{panic_msg[:80]}"
            if key not in self._panic_patterns:
                self._panic_patterns.add(key)
                bugs.append(LogicBug(
                    category="panic_caught",
                    severity="high",
                    description=f"Go panic in {nf_name}: {panic_msg}",
                    evidence={"nf": nf_name, "panic_message": panic_msg},
                    reproduce_hint=f"Check {nf_name} logs for full stack trace",
                ))

        # Goroutine leak
        goroutine_re = re.compile(r'goroutine (\d+) \[')
        goroutines = goroutine_re.findall(logs)
        if len(goroutines) > 100:
            bugs.append(LogicBug(
                category="resource_leak",
                severity="medium",
                description=f"{nf_name}: {len(goroutines)} goroutines (possible leak)",
                evidence={"nf": nf_name, "goroutine_count": len(goroutines)},
            ))

        return bugs

    def check_state_violation(self, fsm_state: str, expected_states: Set[str],
                               nf_name: str) -> Optional[LogicBug]:
        """Check if current FSM state is a protocol violation."""
        if fsm_state not in expected_states and fsm_state.startswith("INVALID"):
            return LogicBug(
                category="state_violation",
                severity="medium",
                description=f"{nf_name} reached invalid state: {fsm_state}",
                evidence={"nf": nf_name, "state": fsm_state,
                          "expected": list(expected_states)},
            )
        return None

    def check_error_consistency(self, target_nf: str) -> List[LogicBug]:
        """Check if the same input consistently produces errors."""
        bugs = []
        error_paths = defaultdict(set)
        for entry in self._response_history.get(target_nf, []):
            if entry["status"] >= 500:
                error_paths[entry["path"]].add(entry["status"])

        for path, statuses in error_paths.items():
            if len(statuses) > 1:
                bugs.append(LogicBug(
                    category="error_inconsistency",
                    severity="low",
                    description=f"{target_nf}: {path} returns inconsistent errors: {statuses}",
                    evidence={"nf": target_nf, "path": path,
                              "statuses": list(statuses)},
                ))

        return bugs

    # ─── Private detectors ──────────────────────────────────────

    @staticmethod
    def _detect_caught_panic(body: str, path: str, nf: str) -> Optional[LogicBug]:
        """Detect Go panic stack traces in HTTP response body."""
        panic_indicators = [
            "panic:", "goroutine ", "[recovered]", "runtime/",
            "runtime error:", "nil pointer", "index out of range",
            "slice bounds out of range",
        ]
        matches = [ind for ind in panic_indicators if ind in body.lower()]
        if len(matches) >= 2:  # Multiple indicators = real panic
            return LogicBug(
                category="panic_caught",
                severity="high",
                description=f"Go panic recovered in {nf} at {path}",
                evidence={"nf": nf, "path": path,
                          "indicators": matches, "body_preview": body[:300]},
                reproduce_hint=f"Replay request to {path} with same mutation",
            )
        return None

    @staticmethod
    def _detect_json_parse_error(body: str, path: str, nf: str,
                                  mutation: str) -> Optional[LogicBug]:
        """Detect JSON parse errors that may indicate input validation gaps."""
        if "json" in body.lower() and "error" in body.lower():
            if mutation in ("special_chars", "sql_injection", "null_required"):
                return LogicBug(
                    category="response_anomaly",
                    severity="low",
                    description=f"{nf}: JSON parse error at {path} with {mutation}",
                    evidence={"nf": nf, "path": path, "mutation": mutation,
                              "body": body[:200]},
                )
        return None

    @staticmethod
    def _detect_response_anomaly(status: int, body: str, path: str,
                                  nf: str) -> Optional[LogicBug]:
        """Detect anomalous 200 responses (success code but error content)."""
        error_keywords = ["error", "fail", "exception", "invalid", "panic"]
        matches = [kw for kw in error_keywords if kw in body.lower()]
        if len(matches) >= 2:
            return LogicBug(
                category="response_anomaly",
                severity="medium",
                description=f"{nf}: HTTP 200 but body contains errors: {matches}",
                evidence={"nf": nf, "path": path, "keywords": matches,
                          "body": body[:200]},
            )
        return None

    # ─── Summary ────────────────────────────────────────────────

    def summary(self) -> Dict[str, Any]:
        """Generate bug detection summary."""
        by_category = defaultdict(int)
        by_severity = defaultdict(int)
        by_nf = defaultdict(int)
        for bug in self.bugs:
            by_category[bug.category] += 1
            by_severity[bug.severity] += 1
            by_nf[bug.evidence.get("nf", "unknown")] += 1

        return {
            "total_logic_bugs": len(self.bugs),
            "by_category": dict(by_category),
            "by_severity": dict(by_severity),
            "by_nf": dict(by_nf),
            "details": [
                {
                    "category": b.category,
                    "severity": b.severity,
                    "description": b.description,
                    "evidence": b.evidence,
                }
                for b in self.bugs
            ],
        }
