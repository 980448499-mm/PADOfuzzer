#!/usr/bin/env python3
"""Adaptive Parallel Fuzzing Runner — auto-tunes concurrency for max throughput.

Monitors CPU, memory, and swap in real-time. Adjusts the number of parallel
fuzzer instances to maximize hardware utilization without triggering OOM.

Algorithm:
  - Start with N = min(cores/4, remaining_jobs)
  - Every check_interval seconds:
      if cpu < target_low and mem < 70%:  spawn +1 worker
      if cpu > target_high or mem > 85%: kill -1 worker (soft)
      if swap_growth > threshold: reduce workers aggressively

Usage:
  python scripts/adaptive_runner.py --hours 1 --max-workers 30

Output:
  results/adaptive/ + worker utilization log
"""

import argparse
import asyncio
import json
import os
import random
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ─── System Monitor ────────────────────────────────────────────

@dataclass
class SystemState:
    cpu_percent: float
    mem_percent: float
    swap_used_mb: float
    load_1m: float
    timestamp: float = field(default_factory=time.time)


def get_system_state() -> SystemState:
    """Read current system resource usage."""
    import psutil
    return SystemState(
        cpu_percent=psutil.cpu_percent(interval=1),
        mem_percent=psutil.virtual_memory().percent,
        swap_used_mb=psutil.swap_memory().used / (1024 * 1024),
        load_1m=os.getloadavg()[0],
    )


# ─── Worker Pool ───────────────────────────────────────────────

@dataclass
class Worker:
    """A running fuzzer instance."""
    id: int
    target: str
    config: str
    process: asyncio.subprocess.Process
    start_time: float = field(default_factory=time.time)
    requests_sent: int = 0
    crashes_found: int = 0

    @property
    def elapsed(self) -> float:
        return time.time() - self.start_time


class AdaptiveParallelRunner:
    """Auto-tuning parallel fuzzing orchestrator.

    Maintains a pool of fuzzer workers, adjusting pool size based on
    real-time system resource availability.
    """

    def __init__(
        self,
        targets: List[str],
        configs: List[str],
        hours_per_test: float = 0.5,
        max_workers: int = 30,
        min_workers: int = 2,
        target_cpu_low: float = 50.0,
        target_cpu_high: float = 80.0,
        target_mem_high: float = 85.0,
        check_interval: float = 30.0,
        output_dir: Path = Path("./results/adaptive"),
    ):
        self.targets = targets
        self.configs = configs
        self.hours_per_test = hours_per_test
        self.max_workers = max_workers
        self.min_workers = min_workers
        self.target_cpu_low = target_cpu_low
        self.target_cpu_high = target_cpu_high
        self.target_mem_high = target_mem_high
        self.check_interval = check_interval
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.workers: Dict[int, Worker] = {}
        self._next_id = 0
        self._completed = 0
        self._total = len(targets) * len(configs)
        self._queue: List[tuple] = []  # (target, config)
        self._history: List[Dict] = []  # Utilization log
        self._stop = False
        self._last_swap = get_system_state().swap_used_mb

        # Build work queue: randomize to avoid configuration bias
        for target in targets:
            for config in configs:
                self._queue.append((target, config))
        random.shuffle(self._queue)

    # ─── Main Loop ─────────────────────────────────────────────

    async def run(self):
        """Run the adaptive parallel fuzzing campaign."""
        print(f"\n{'='*60}")
        print(f"ADAPTIVE PARALLEL FUZZING")
        print(f"{'='*60}")
        print(f"Workers: {self.min_workers}–{self.max_workers} (auto)")
        print(f"Queue: {len(self._queue)} jobs")
        print(f"Per job: {self.hours_per_test}h")
        print(f"Target CPU: {self.target_cpu_low}–{self.target_cpu_high}%")
        print(f"Target Mem: <{self.target_mem_high}%")
        print(f"{'='*60}\n")

        # Start initial workers
        initial = min(
            max(os.cpu_count() // 4, self.min_workers),
            len(self._queue),
            self.max_workers,
        )
        for _ in range(initial):
            await self._spawn_worker()

        # Monitor loop
        while self.workers or self._queue:
            await asyncio.sleep(self.check_interval)

            state = get_system_state()
            self._log_state(state)

            # Adaptive decisions
            await self._adapt(state)

            # Print status
            self._print_status(state)

            if self._stop:
                break

        # Cleanup
        await self._stop_all()
        self._save_report()

    # ─── Adaptation Logic ──────────────────────────────────────

    async def _adapt(self, state: SystemState):
        """Auto-tune worker count based on system state."""
        current = len(self.workers)

        # Aggressive reduction if swap is growing (memory pressure)
        swap_growth = state.swap_used_mb - self._last_swap
        self._last_swap = state.swap_used_mb
        if swap_growth > 100:  # 100MB swap growth → memory pressure
            to_kill = min(len(self.workers) // 3, len(self.workers) - 1)
            for _ in range(max(1, to_kill)):
                await self._stop_oldest_worker()
            print(f"  ⚠️  Swap +{swap_growth:.0f}MB → killed {to_kill} workers")
            return

        # Scale up: CPU under target range, memory OK, queue not empty
        if (state.cpu_percent < self.target_cpu_low and
                state.mem_percent < self.target_mem_high and
                self._queue and
                current < self.max_workers):
            await self._spawn_worker()
            print(f"  ⬆  CPU {state.cpu_percent:.0f}% < {self.target_cpu_low}% → spawn (now {current+1})")

        # Scale down: CPU over target or memory high
        elif (state.cpu_percent > self.target_cpu_high or
              state.mem_percent > self.target_mem_high):
            if current > self.min_workers:
                await self._stop_oldest_worker()
                reason = "CPU" if state.cpu_percent > self.target_cpu_high else "MEM"
                val = state.cpu_percent if reason == "CPU" else state.mem_percent
                print(f"  ⬇  {reason} {val:.0f}% > limit → kill (now {current-1})")

    # ─── Worker Management ─────────────────────────────────────

    async def _spawn_worker(self):
        """Start a new fuzzer worker if queue is not empty."""
        if not self._queue:
            return
        target, config = self._queue.pop(0)
        wid = self._next_id
        self._next_id += 1

        # Map config name to fuzzer args
        script = {"oai": "live_fuzz_oai.py",
                  "free5gc": "live_fuzz_free5gc.py",
                  "open5gs": "live_fuzz_open5gs.py"}[target]

        args = []
        if "no_fsm" in config:
            args.append("--no-fsm")
        if "no_cross" in config:
            args.append("--no-cross-protocol")

        out_dir = self.output_dir / target / config / f"w{wid}"
        out_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            sys.executable,
            str(Path(__file__).resolve().parent / script),
            "--hours", str(self.hours_per_test),
            "--output", str(out_dir),
        ] + args

        log_file = open(str(out_dir / "fuzzer.log"), "w")
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=log_file,
            stderr=asyncio.subprocess.STDOUT,
        )

        self.workers[wid] = Worker(
            id=wid, target=target, config=config, process=proc)

    async def _stop_oldest_worker(self):
        """Gracefully stop the longest-running worker."""
        if not self.workers:
            return
        oldest = min(self.workers.values(), key=lambda w: w.start_time)
        # Send SIGTERM, wait briefly, force kill if needed
        try:
            oldest.process.terminate()
            await asyncio.wait_for(oldest.process.wait(), timeout=5)
        except asyncio.TimeoutError:
            oldest.process.kill()
        except ProcessLookupError:
            pass
        # Re-queue the killed worker's job
        self._queue.insert(0, (oldest.target, oldest.config))
        self._completed += 1
        del self.workers[oldest.id]

    async def _stop_all(self):
        """Stop all workers."""
        for w in list(self.workers.values()):
            try:
                w.process.terminate()
            except ProcessLookupError:
                pass
        await asyncio.sleep(2)
        for w in list(self.workers.values()):
            try:
                w.process.kill()
            except ProcessLookupError:
                pass
        self.workers.clear()

    # ─── Logging ────────────────────────────────────────────────

    def _log_state(self, state: SystemState):
        self._history.append({
            "timestamp": state.timestamp,
            "workers": len(self.workers),
            "cpu": state.cpu_percent,
            "mem": state.mem_percent,
            "swap_mb": state.swap_used_mb,
            "queue_remaining": len(self._queue),
        })

    def _print_status(self, state: SystemState):
        w = len(self.workers)
        q = len(self._queue)
        done = self._completed

        # Collect worker progress by reading their output dirs
        total_reqs = 0
        total_crashes = 0
        try:
            for wid, worker in self.workers.items():
                out_dir = (self.output_dir / worker.target /
                           worker.config / f"w{wid}")
                reports = sorted(out_dir.glob("fuzz_report_*.json"),
                                 key=lambda p: p.stat().st_mtime,
                                 reverse=True)
                if reports:
                    try:
                        rpt = json.loads(reports[0].read_text())
                        total_reqs += rpt.get("campaign", {}).get(
                            "requests_sent", 0)
                        total_crashes += rpt.get("crashes", {}).get("total", 0)
                    except (json.JSONDecodeError, IOError):
                        pass
        except Exception:
            pass

        bar = "█" * int(w / 2) + "░" * (self.max_workers // 2 - int(w / 2))
        print(f"  [{time.strftime('%H:%M:%S')}] "
              f"workers={w:2d} {bar} "
              f"CPU={state.cpu_percent:4.0f}% MEM={state.mem_percent:4.0f}% "
              f"reqs={total_reqs:,} crashes={total_crashes} "
              f"queue={q} done={done}/{self._total}", flush=True)

    def _save_report(self):
        report = {
            "total_jobs": self._total,
            "completed": self._completed,
            "peak_workers": max(h["workers"] for h in self._history) if self._history else 0,
            "avg_cpu": sum(h["cpu"] for h in self._history) / max(len(self._history), 1),
            "peak_mem": max(h["mem"] for h in self._history) if self._history else 0,
            "utilization_log": self._history,
        }
        path = self.output_dir / "adaptive_runner_report.json"
        path.write_text(json.dumps(report, indent=2))


# ─── CLI ───────────────────────────────────────────────────────

async def main():
    parser = argparse.ArgumentParser(
        description="Adaptive Parallel Fuzzing Runner")
    parser.add_argument("--hours", type=float, default=0.5,
                        help="Hours per individual fuzz test")
    parser.add_argument("--max-workers", type=int, default=30)
    parser.add_argument("--min-workers", type=int, default=2)
    parser.add_argument("--targets", type=str, default="oai,free5gc,open5gs")
    parser.add_argument("--configs", type=str,
                        default="ours_full,ours_no_fsm,ours_no_cross_protocol,aflnet_like,random")
    parser.add_argument("--output", type=str, default="./results/adaptive")
    args = parser.parse_args()

    targets = [t.strip() for t in args.targets.split(",")]
    configs = [c.strip() for c in args.configs.split(",")]

    runner = AdaptiveParallelRunner(
        targets=targets,
        configs=configs,
        hours_per_test=args.hours,
        max_workers=args.max_workers,
        min_workers=args.min_workers,
        output_dir=Path(args.output),
    )
    await runner.run()


if __name__ == "__main__":
    asyncio.run(main())
