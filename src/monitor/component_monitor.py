"""Multi-component monitoring orchestrator.

Collects logs, coverage, metrics, and crash data from all NFs in a deployment.

Sources per NF:
  1. Container stdout/stderr logs (via Docker API)
  2. File-based logs (e.g., /var/log/open5gs/smf.log)
  3. Prometheus metrics (exposed on :9090/:9091 per NF)
  4. Coverage instrumentation (gcov .gcda files)
  5. Health probes (HTTP GET /status)
"""

import asyncio
import logging
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from src import (
    CrashRecord,
    CrashSeverity,
    CoverageBitmap,
    LogEntry,
    MonitoringResult,
    NFType,
    ProtocolType,
    FiveGCImpl,
)
from src.deployment.orchestrator import Deployment
from src.fuzzing_engine.coverage.bitmap import CoverageBitmap

logger = logging.getLogger(__name__)


class ComponentMonitor:
    """Orchestrates monitoring across all NFs in a deployment.

    Collects from multiple sources and produces unified MonitoringResult.
    """

    def __init__(self, deployment: Deployment):
        self.deployment = deployment
        self.log_harvester = LogHarvester(deployment)
        self.coverage_collector = CoverageCollector(deployment)
        self.crash_detector = CrashDetector(deployment)
        self.metrics_collector = MetricsCollector(deployment)
        self._coverage_baseline: Optional[CoverageBitmap] = None

    async def collect_baseline(self) -> CoverageBitmap:
        """Collect coverage baseline before fuzzing starts."""
        baseline = await self.coverage_collector.collect()
        self._coverage_baseline = baseline
        return baseline

    async def monitor_iteration(self) -> MonitoringResult:
        """Collect all monitoring data for one fuzzing iteration."""
        logs = await self.log_harvester.collect()
        coverage = await self.coverage_collector.collect()
        metrics = await self.metrics_collector.collect()

        new_edges: Set[int] = set()
        if self._coverage_baseline is not None:
            new_edges = self._coverage_baseline.get_new_edges(coverage)
            self._coverage_baseline.merge(coverage)  # Update baseline

        nf_states = self._infer_nf_states(logs)

        return MonitoringResult(
            logs=logs,
            coverage_after=coverage,
            coverage_before=self._coverage_baseline,
            new_edges=new_edges,
            metrics=metrics,
            nf_states=nf_states,
        )

    def detect_crashes(self, logs: List[LogEntry]) -> List[CrashRecord]:
        """Detect crashes from log entries."""
        return self.crash_detector.detect(logs)

    @staticmethod
    def _infer_nf_states(logs: List[LogEntry]) -> Dict[str, str]:
        """Infer NF protocol states from log messages."""
        states: Dict[str, str] = {}
        state_patterns = {
            "REGISTERED": re.compile(r"(?:Registered|registration complete|REGISTRATION ACCEPT)", re.IGNORECASE),
            "PDU_ACTIVE": re.compile(r"(?:PDU session.*established|PDU SESSION ESTABLISHMENT ACCEPT)", re.IGNORECASE),
            "PFCP_ASSOCIATED": re.compile(r"(?:PFCP association.*established|PFCP Association Setup)", re.IGNORECASE),
            "AUTHENTICATED": re.compile(r"(?:authentication.*success|AUTHENTICATION SUCCESS)", re.IGNORECASE),
        }
        for entry in logs:
            for state, pattern in state_patterns.items():
                if pattern.search(entry.message):
                    nf_key = entry.nf_type.value if entry.nf_type else "unknown"
                    states[nf_key] = state
        return states


# ─── Log Harvester ────────────────────────────────────────────


class LogHarvester:
    """Harvest logs from Docker containers and file-based log sources.

    Uses Docker log API for stdout/stderr, and docker exec for
    file-based logs when needed.
    """

    KEY_PATTERNS: Dict[str, re.Pattern] = {
        "CRASH_SIGNAL": re.compile(r"SIGSEGV|SIGABRT|SIGBUS|SIGFPE"),
        "ASSERT_FAIL": re.compile(r"Assertion.*failed"),
        "SEGV": re.compile(r"segfault|general protection fault"),
        "OGS_ERROR": re.compile(r"\[ERROR\]"),
        "OGS_FATAL": re.compile(r"\[FATAL\]"),
        "ALLOC_FAIL": re.compile(r"out of memory|cannot allocate"),
        "NULL_DEREF": re.compile(r"null pointer|NULL.*dereference"),
        "STACK_TRACE": re.compile(r"#\d+\s+0x[0-9a-f]+"),
        "ASAN_ERROR": re.compile(
            r"(?:heap-buffer-overflow|stack-buffer-overflow|"
            r"heap-use-after-free|stack-use-after-return|"
            r"memory leak|double-free|invalid-free|"
            r"global-buffer-overflow|SEGV on unknown address)"
        ),
        "UBSAN_ERROR": re.compile(
            r"(?:undefined behavior|signed integer overflow|"
            r"division by zero|null pointer passed|"
            r"load of misaligned address)"
        ),
    }

    LOG_LEVEL_PATTERN = re.compile(
        r"(TRACE|DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|CRITICAL)", re.IGNORECASE
    )

    def __init__(self, deployment: Deployment):
        self.deployment = deployment
        self._last_timestamp: Dict[str, str] = {}

    async def collect(self, tail_lines: int = 100) -> List[LogEntry]:
        """Collect recent logs from all containers."""
        entries: List[LogEntry] = []

        for container_id, name in self.deployment.container_ids.items():
            container_entries = await self._collect_container_logs(
                container_id, name, tail_lines
            )
            entries.extend(container_entries)

        entries.sort(key=lambda e: e.timestamp)
        return entries

    async def _collect_container_logs(
        self, container_id: str, name: str, tail_lines: int
    ) -> List[LogEntry]:
        """Collect logs from a single Docker container."""
        cmd = [
            "docker", "logs", "--tail", str(tail_lines),
            "--timestamps", container_id,
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10
            )
            lines = result.stdout.strip().split("\n") if result.stdout else []
            stderr_lines = result.stderr.strip().split("\n") if result.stderr else []

            entries: List[LogEntry] = []
            for log_type, log_lines in [("stdout", lines), ("stderr", stderr_lines)]:
                for line in log_lines:
                    if line.strip():
                        entry = self._parse_docker_log_line(line, name)
                        if entry:
                            entries.append(entry)
            return entries
        except subprocess.TimeoutExpired:
            return []
        except subprocess.CalledProcessError:
            return []

    def _parse_docker_log_line(self, line: str, container_name: str) -> Optional[LogEntry]:
        """Parse a docker log line into a structured LogEntry."""
        # Docker timestamps are like "2024-01-15T10:30:45.123456789Z message"
        timestamp = time.time()
        msg = line

        # Try to parse docker timestamp
        ts_match = re.match(
            r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line
        )
        if ts_match:
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(ts_match.group(1))
                timestamp = dt.timestamp()
                msg = line[ts_match.end():].strip()
            except ValueError:
                pass

        # Determine log level
        level_match = self.LOG_LEVEL_PATTERN.search(msg)
        level = level_match.group(1).upper() if level_match else "INFO"

        # Infer NF type from container name
        from src.deployment.orchestrator import DeploymentManager
        nf_type = DeploymentManager._container_name_to_nf(container_name)

        return LogEntry(
            timestamp=timestamp,
            nf_type=nf_type or NFType.AMF,
            level=level,
            message=msg,
            raw=line,
        )

    def search_pattern(self, pattern: str, logs: List[LogEntry]) -> List[LogEntry]:
        """Search for a regex pattern across collected logs."""
        compiled = re.compile(pattern, re.IGNORECASE)
        return [entry for entry in logs if compiled.search(entry.message)]

    def extract_stack_trace(self, logs: List[LogEntry]) -> List[str]:
        """Extract stack trace frames from log entries."""
        frames: List[str] = []
        for entry in logs:
            matches = self.KEY_PATTERNS["STACK_TRACE"].findall(entry.message)
            frames.extend(matches)
        return frames


# ─── Crash Detector ───────────────────────────────────────────


class CrashDetector:
    """Detect crashes and anomalies from logs."""

    # Mapping from pattern key to severity
    SEVERITY_MAP: Dict[str, CrashSeverity] = {
        "CRASH_SIGNAL": CrashSeverity.CRITICAL,
        "SEGV": CrashSeverity.CRITICAL,
        "ASAN_ERROR": CrashSeverity.HIGH,
        "ASSERT_FAIL": CrashSeverity.MEDIUM,
        "NULL_DEREF": CrashSeverity.HIGH,
        "ALLOC_FAIL": CrashSeverity.MEDIUM,
        "OGS_FATAL": CrashSeverity.CRITICAL,
        "STACK_TRACE": CrashSeverity.MEDIUM,
        "UBSAN_ERROR": CrashSeverity.HIGH,
    }

    def __init__(self, deployment: Deployment):
        self.deployment = deployment
        self.harvester = LogHarvester(deployment)
        self._detected_hashes: Set[str] = set()

    def detect(self, logs: List[LogEntry]) -> List[CrashRecord]:
        """Detect crashes from log entries."""
        crashes: List[CrashRecord] = []

        for entry in logs:
            for pattern_key, pattern in self.harvester.KEY_PATTERNS.items():
                if pattern.search(entry.message):
                    severity = self.SEVERITY_MAP.get(pattern_key, CrashSeverity.LOW)
                    crash = CrashRecord(
                        target_nf=entry.nf_type,
                        crash_signal=pattern_key,
                        severity=severity,
                        crash_address=self._extract_address(entry.message),
                    )
                    crashes.append(crash)
                    break  # One crash per log entry

        return crashes

    def detect_from_container_health(self) -> List[CrashRecord]:
        """Detect crashes by checking container health."""
        from src.deployment.orchestrator import ContainerHealthMonitor

        health_monitor = ContainerHealthMonitor(self.deployment)
        crashed_containers = health_monitor.get_crashed_containers()

        crashes: List[CrashRecord] = []
        for name, status in crashed_containers:
            from src.deployment.orchestrator import DeploymentManager
            nf_type = DeploymentManager._container_name_to_nf(name)
            crash = CrashRecord(
                target_nf=nf_type,
                crash_signal=f"container_{status}",
                severity=(
                    CrashSeverity.CRITICAL if "OOM" in status
                    else CrashSeverity.HIGH
                ),
            )
            crashes.append(crash)

        return crashes

    @staticmethod
    def _extract_address(message: str) -> Optional[int]:
        """Extract faulting address from crash message."""
        addr_match = re.search(r"0x([0-9a-fA-F]{8,16})", message)
        if addr_match:
            return int(addr_match.group(1), 16)
        return None


# ─── Coverage Collector ───────────────────────────────────────


class CoverageCollector:
    """Collect code coverage from instrumented NFs.

    Option A: gcov (GCC --coverage flag)
      - After each fuzzing round, copy .gcda files from container
      - Merge with lcov/geninfo
      - Convert to edge coverage bitmap

    Option B: LLVM SanitizerCoverage
      - Uses shared memory bitmap (AFL-style)
      - Lower overhead, real-time coverage

    Currently implemented: gcov-based collection
    """

    def __init__(self, deployment: Deployment):
        self.deployment = deployment
        self.edge_bitmap = CoverageBitmap()

    async def collect(self) -> CoverageBitmap:
        """Collect current coverage from all instrumented NFs."""
        bitmap = CoverageBitmap()

        for container_id, name in self.deployment.container_ids.items():
            try:
                nf_bitmap = await self._collect_gcov_from_container(container_id)
                bitmap.merge(nf_bitmap)
            except Exception as e:
                logger.debug(f"Coverage collection failed for {name}: {e}")

        return bitmap

    async def _collect_gcov_from_container(self, container_id: str) -> CoverageBitmap:
        """Collect gcov coverage from a container.

        Three-tier strategy:
          1. Try lcov/geninfo for structured coverage (most precise)
          2. Fall back to gcov on individual .gcda files
          3. Fall back to raw .gcda edge hashing (always works)
        """
        import shutil
        import tempfile

        tmp_dir = tempfile.mkdtemp(prefix="5gfuzz_cov_")
        bitmap = CoverageBitmap()

        try:
            # Tier 1: copy .gcda files from container
            cmd_copy = [
                "docker", "cp",
                f"{container_id}:/var/log/open5gs/.",
                tmp_dir,
            ]
            subprocess.run(cmd_copy, capture_output=True, timeout=15)

            gcov_dir = Path(tmp_dir)
            gcda_files = list(gcov_dir.rglob("*.gcda"))

            if not gcda_files:
                return bitmap

            # Tier 2: try lcov if available (batch processing)
            lcov_ok = False
            try:
                info_file = Path(tmp_dir) / "coverage.info"
                result = subprocess.run(
                    ["lcov", "--capture", "--directory", tmp_dir,
                     "--output-file", str(info_file), "--rc", "lcov_branch_coverage=1"],
                    capture_output=True, text=True, timeout=60,
                )
                if result.returncode == 0 and info_file.exists():
                    lcov_ok = True
                    info_text = info_file.read_text(errors="replace")
                    # Parse DA (line) and BRDA (branch) records into edges
                    for line in info_text.split("\n"):
                        if line.startswith("DA:") or line.startswith("BRDA:"):
                            edge_id = hash(line) % 65536
                            bitmap.record_edge(edge_id)
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                pass

            # Tier 3: per-file gcov for branch coverage (if lcov unavailable)
            if not lcov_ok:
                for gcda_file in gcda_files:
                    try:
                        result = subprocess.run(
                            ["gcov", "-b", "-n", str(gcda_file)],
                            capture_output=True, text=True, timeout=15,
                            cwd=str(gcda_file.parent),
                        )
                        for line in result.stdout.split("\n"):
                            if "branch" in line or "taken" in line:
                                edge_id = hash(line) % 65536
                                bitmap.record_edge(edge_id)
                    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                        pass

            # Tier 4: fallback — hash raw .gcda data
            if not bitmap.total_edges:
                for gcda_file in gcda_files:
                    try:
                        data = gcda_file.read_bytes()
                        for i in range(0, len(data) - 3, 4):
                            edge_id = int.from_bytes(data[i:i + 4], "little") % 65536
                            bitmap.record_edge(edge_id)
                    except OSError:
                        pass

        except Exception:
            pass
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

        return bitmap

    def reset_baseline(self) -> None:
        self.edge_bitmap = CoverageBitmap()


# ─── Metrics Collector ────────────────────────────────────────


class MetricsCollector:
    """Collect Prometheus metrics from NFs.

    Open5GS and free5GC expose Prometheus metrics on configurable ports.
    Key metrics:
      - process_cpu_seconds_total
      - process_resident_memory_bytes
      - nf_sessions_active
      - nf_registration_total
      - nf_pdu_session_active
      - http_requests_total  (for SBI endpoints)
    """

    # Important 5GC-specific Prometheus metrics
    KEY_METRICS = [
        "amf_registration_total",
        "amf_registered_subscribers",
        "smf_pdu_session_active",
        "smf_pdu_session_total",
        "upf_session_active",
        "process_resident_memory_bytes",
        "process_cpu_seconds_total",
        "process_open_fds",
    ]

    def __init__(self, deployment: Deployment):
        self.deployment = deployment
        self._snapshots: List[Dict[str, float]] = []

    async def collect(self) -> Dict[str, float]:
        """Collect Prometheus metrics from all NFs."""
        metrics: Dict[str, float] = {}

        for nf_type, endpoint in self.deployment.endpoints.items():
            try:
                url = f"http://{endpoint.ip_address}:9090/metrics"
                nf_metrics = await self._scrape_metrics(url, nf_type.value)
                metrics.update(nf_metrics)
            except Exception:
                pass

        self._snapshots.append(metrics)
        return metrics

    async def _scrape_metrics(self, url: str, nf_name: str) -> Dict[str, float]:
        """Scrape Prometheus metrics endpoint."""
        import urllib.request
        import urllib.error

        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                text = resp.read().decode()
        except (urllib.error.URLError, urllib.error.HTTPError):
            return {}

        result: Dict[str, float] = {}
        for line in text.split("\n"):
            if line.startswith("#") or not line.strip():
                continue
            # Prometheus format: metric_name{labels} value timestamp
            parts = line.split()
            if len(parts) >= 2:
                name = f"{nf_name}_{parts[0]}"
                try:
                    result[name] = float(parts[1])
                except ValueError:
                    pass

        return result

    def get_memory_growth_rate(self, nf_name: str) -> float:
        """Compute memory growth rate from last two snapshots."""
        if len(self._snapshots) < 2:
            return 0.0
        key = f"{nf_name}_process_resident_memory_bytes"
        prev = self._snapshots[-2].get(key, 0)
        curr = self._snapshots[-1].get(key, 0)
        return curr - prev

    def reset(self) -> None:
        self._snapshots.clear()
