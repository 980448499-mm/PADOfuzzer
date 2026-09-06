"""Coverage collector for 5GC fuzz testing.

Supports:
  - gcov-based coverage for C/C++ targets (OAI, Open5GS)
  - go-cover-based coverage for Go targets (free5GC)

Usage:
  collector = CoverageCollector(container="oai-nrf", build_dir="/build")
  bitmap = collector.collect()  # Returns CoverageBitmap or None
"""

import json
import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("coverage_collector")


@dataclass
class CoverageSnapshot:
    """Accumulated coverage data for one collection point."""
    timestamp: float
    lines_total: int = 0
    lines_covered: int = 0
    branches_total: int = 0
    branches_covered: int = 0
    functions_total: int = 0
    functions_covered: int = 0
    files_covered: int = 0
    new_lines_since_last: int = 0
    new_branches_since_last: int = 0

    @property
    def line_coverage_pct(self) -> float:
        return (self.lines_covered / max(self.lines_total, 1)) * 100

    @property
    def branch_coverage_pct(self) -> float:
        return (self.branches_covered / max(self.branches_total, 1)) * 100

    @property
    def edge_coverage_pct(self) -> float:
        """Alias: branch coverage = edge coverage (AFL-style)."""
        return self.branch_coverage_pct

    @property
    def function_coverage_pct(self) -> float:
        return (self.functions_covered / max(self.functions_total, 1)) * 100


class CoverageCollector:
    """Collects gcov/go-cover data from Docker containers.

    For C/C++ (gcov):
      - Binary must be compiled with -fprofile-arcs -ftest-coverage
      - gcovr must be installed in the container
      - .gcno files must be present alongside the binary

    For Go (go-cover):
      - Binary must be built with 'go build -cover'
      - GOCOVERDIR env must be set
    """

    def __init__(
        self,
        container: str,
        source_dir: str = "/build",
        language: str = "c++",
        toolchain: str = "llvm",  # "llvm" | "gcov"
        gcov_executable: str = "gcov",
    ):
        self.container = container
        self.source_dir = source_dir
        self.language = language
        self.toolchain = toolchain
        self.gcov_executable = gcov_executable
        self._last_lines = 0
        self._last_branches = 0
        self._snapshots: List[CoverageSnapshot] = []
        self._available = None  # Lazily detected

    @property
    def available(self) -> bool:
        """Check if coverage collection is possible."""
        if self._available is None:
            self._available = self._check_available()
        return self._available

    def _check_available(self) -> bool:
        """Check if coverage tools exist in the container."""
        try:
            if self.toolchain == "llvm":
                result = subprocess.run(
                    ["docker", "exec", self.container, "which", "llvm-cov-14"],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode != 0:
                    result = subprocess.run(
                        ["docker", "exec", self.container, "which", "llvm-cov"],
                        capture_output=True, text=True, timeout=5,
                    )
                return result.returncode == 0
            else:
                result = subprocess.run(
                    ["docker", "exec", self.container, "which", "gcovr"],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode != 0:
                    return False
                result = subprocess.run(
                    ["docker", "exec", self.container, "find", self.source_dir,
                     "-name", "*.gcno", "-quit"],
                    capture_output=True, text=True, timeout=5,
                )
                return bool(result.stdout.strip())
        except subprocess.SubprocessError:
            return False

    def flush(self) -> bool:
        """Flush in-memory coverage data to disk.

        For gcov: sends SIGUSR1 to trigger __gcov_flush().
        For go-cover: no-op (Go writes continuously).
        """
        if self.language == "go":
            return True
        try:
            subprocess.run(
                ["docker", "exec", self.container,
                 "kill", "-USR1", "1"],
                capture_output=True, timeout=5,
            )
            import time; time.sleep(0.5)  # Let gcov write .gcda files
            return True
        except subprocess.SubprocessError:
            return False

    def collect(self) -> Optional[CoverageSnapshot]:
        """Collect current coverage data from the container."""
        if not self.available:
            return None

        self.flush()

        if self.language == "go":
            return self._collect_go()
        elif self.toolchain == "llvm":
            return self._collect_llvm()
        else:
            return self._collect_gcov()

    def _collect_llvm(self) -> Optional[CoverageSnapshot]:
        """Collect Clang source-based coverage via llvm-profdata + llvm-cov."""
        import time

        try:
            # Merge .profraw files
            subprocess.run(
                ["docker", "exec", self.container,
                 "llvm-profdata-14", "merge", "-sparse",
                 "/tmp/coverage", "-o", "/tmp/coverage/nrf.profdata"],
                capture_output=True, timeout=30,
            )
            # Generate JSON report
            result = subprocess.run(
                ["docker", "exec", self.container,
                 "llvm-cov-14", "export", "/usr/local/bin/oai_nrf",
                 "-instr-profile=/tmp/coverage/nrf.profdata",
                 "-format=text"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                return None

            # Parse llvm-cov JSON output
            data = json.loads(result.stdout)
            lines_total, lines_covered = 0, 0
            branches_total, branches_covered = 0, 0
            functions_total, functions_covered = 0, 0
            files_covered = 0

            for file_info in data.get("data", [])[0].get("files", []):
                summary = file_info.get("summary", {})
                lines = summary.get("lines", {})
                branches = summary.get("branches", {})
                funcs = summary.get("functions", {})

                lines_total += lines.get("count", 0)
                lines_covered += lines.get("covered", 0)
                branches_total += branches.get("count", 0)
                branches_covered += branches.get("covered", 0)
                functions_total += funcs.get("count", 0)
                functions_covered += funcs.get("covered", 0)
                if lines.get("covered", 0) > 0:
                    files_covered += 1

            new_lines = max(0, lines_covered - self._last_lines)
            new_branches = max(0, branches_covered - self._last_branches)

            snap = CoverageSnapshot(
                timestamp=time.time(),
                lines_total=lines_total, lines_covered=lines_covered,
                branches_total=branches_total, branches_covered=branches_covered,
                functions_total=functions_total, functions_covered=functions_covered,
                files_covered=files_covered,
                new_lines_since_last=new_lines,
                new_branches_since_last=new_branches,
            )
            self._last_lines = lines_covered
            self._last_branches = branches_covered
            self._snapshots.append(snap)
            return snap

        except (subprocess.SubprocessError, json.JSONDecodeError, KeyError, IndexError) as e:
            logger.debug("LLVM coverage collection failed: %s", e)
            return None

    def _collect_gcov(self) -> Optional[CoverageSnapshot]:
        """Collect gcov coverage via gcovr."""
        import time

        try:
            # Run gcovr inside the container
            cmd = [
                "docker", "exec", self.container,
                "gcovr",
                "--json",
                "-r", self.source_dir,
                "--gcov-executable", self.gcov_executable,
                "--object-directory", "/tmp/coverage",
                "--exclude", ".*test.*",
                "--exclude", ".*3gpp_specs.*",
            ]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30,
            )

            if result.returncode != 0 or not result.stdout.strip():
                return None

            data = json.loads(result.stdout)

            # Aggregate across all files
            lines_total = 0
            lines_covered = 0
            branches_total = 0
            branches_covered = 0
            functions_total = 0
            functions_covered = 0
            files_covered = 0

            for file_info in data.get("files", []):
                lines_total += file_info.get("lines", {}).get("total", 0)
                lines_covered += file_info.get("lines", {}).get("covered", 0)
                branches_total += file_info.get("branches", {}).get("total", 0)
                branches_covered += file_info.get("branches", {}).get("covered", 0)
                functions_total += file_info.get("functions", {}).get("total", 0)
                functions_covered += file_info.get("functions", {}).get("covered", 0)
                if file_info.get("lines", {}).get("covered", 0) > 0:
                    files_covered += 1

            new_lines = max(0, lines_covered - self._last_lines)
            new_branches = max(0, branches_covered - self._last_branches)

            snap = CoverageSnapshot(
                timestamp=time.time(),
                lines_total=lines_total,
                lines_covered=lines_covered,
                branches_total=branches_total,
                branches_covered=branches_covered,
                functions_total=functions_total,
                functions_covered=functions_covered,
                files_covered=files_covered,
                new_lines_since_last=new_lines,
                new_branches_since_last=new_branches,
            )

            self._last_lines = lines_covered
            self._last_branches = branches_covered
            self._snapshots.append(snap)

            return snap

        except (subprocess.SubprocessError, json.JSONDecodeError,
                KeyError) as e:
            logger.debug("gcov collection failed: %s", e)
            return None

    def _collect_go(self) -> Optional[CoverageSnapshot]:
        """Collect Go coverage data."""
        # Go cover produces a coverage profile file
        # This requires the binary to be built with -cover and
        # GOCOVERDIR to be set at runtime
        import time

        try:
            result = subprocess.run(
                ["docker", "exec", self.container,
                 "go", "tool", "covdata", "percent", "-i",
                 "/tmp/coverage"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                return None

            # Parse "total: XX.X% of statements"
            for line in result.stdout.strip().split("\n"):
                if "total" in line:
                    pct_str = line.split(":")[1].strip().replace("%", "")
                    pct = float(pct_str)

            snap = CoverageSnapshot(
                timestamp=time.time(),
                lines_total=100,
                lines_covered=int(pct),
                functions_covered=0,
            )
            self._snapshots.append(snap)
            return snap

        except (subprocess.SubprocessError, ValueError, IndexError):
            return None

    @property
    def snapshots(self) -> List[Dict[str, Any]]:
        """All coverage snapshots as serializable dicts."""
        return [
            {
                "timestamp": s.timestamp,
                "line_coverage_pct": round(s.line_coverage_pct, 2),
                "branch_coverage_pct": round(s.branch_coverage_pct, 2),
                "function_coverage_pct": round(s.function_coverage_pct, 2),
                "lines_covered": s.lines_covered,
                "lines_total": s.lines_total,
                "branches_covered": s.branches_covered,
                "files_covered": s.files_covered,
                "new_lines": s.new_lines_since_last,
                "new_branches": s.new_branches_since_last,
            }
            for s in self._snapshots
        ]

    @property
    def latest(self) -> Optional[CoverageSnapshot]:
        return self._snapshots[-1] if self._snapshots else None
