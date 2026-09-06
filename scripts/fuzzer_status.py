#!/usr/bin/env python3
"""Generate a comprehensive fuzzing status report."""
import re, sys, os
from pathlib import Path
from collections import defaultdict
from datetime import datetime

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
RESULTS = Path(os.environ.get("RESULTS_DIR", "/home/mm/桌面/5g-fuzzer/results/final-parallel-5h"))

def get_worker_progress():
    targets = defaultdict(lambda: {"workers": 0, "total_reqs": 0, "total_crashes": 0,
                                    "req_rate": 0, "fsm_states": set(), "deep_probes": 0})
    for log_path in RESULTS.rglob("fuzzer.log"):
        parts = log_path.parts
        if len(parts) < 4:
            continue
        target = parts[-4]
        t = targets[target]
        t["workers"] += 1
        try:
            lines = open(log_path).readlines()
            for line in reversed(lines):
                if "Deep probe" in line:
                    t["deep_probes"] += 1
                if "Batch" in line and "req/s" in line:
                    rm = re.search(r'(\d+)\s+reqs', line)
                    rm2 = re.search(r'(\d+)\s+crashes', line)
                    ratem = re.search(r'([\d.]+)\s+req/s', line)
                    fsmm = re.search(r'FSM states:\s*(\d+)', line)
                    if rm: t["total_reqs"] = max(t["total_reqs"], int(rm.group(1)))
                    if rm2: t["total_crashes"] = max(t["total_crashes"], int(rm2.group(1)))
                    if ratem: t["req_rate"] += float(ratem.group(1))
                    if fsmm: t["fsm_states"].add(int(fsmm.group(1)))
                    break
        except Exception:
            pass
    return targets

def get_runner_status():
    runner_log = RESULTS / "adaptive_runner.log"
    if not runner_log.exists():
        return {}
    lines = open(runner_log).readlines()
    for line in reversed(lines):
        if "workers=" in line and "CPU=" in line:
            wm = re.search(r'workers=(\d+)', line)
            cpum = re.search(r'CPU=([\d.]+)%', line)
            memm = re.search(r'MEM=([\d.]+)%', line)
            qm = re.search(r'queue=(\d+)', line)
            donem = re.search(r'done=(\d+)/(\d+)', line)
            if all([wm, cpum, memm]):
                return {
                    "workers": int(wm.group(1)),
                    "cpu": float(cpum.group(1)),
                    "mem": float(memm.group(1)),
                    "queue": int(qm.group(1)) if qm else 0,
                    "done": f"{donem.group(1)}/{donem.group(2)}" if donem else "?"
                }
    return {}

def main():
    targets = get_worker_progress()
    runner = get_runner_status()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"\n{'='*70}")
    print(f"  5G FUZZER — 实时状态  [{now}]")
    print(f"{'='*70}")

    if runner:
        print(f"\n  系统: CPU {runner['cpu']:.0f}% | MEM {runner['mem']:.0f}% | Workers {runner['workers']} | 完成 {runner['done']}")

    total_reqs = sum(t["total_reqs"] for t in targets.values())
    total_crashes = sum(t["total_crashes"] for t in targets.values())
    total_rate = sum(t["req_rate"] for t in targets.values())
    total_probes = sum(t["deep_probes"] for t in targets.values())

    print(f"\n  {'Target':<12} {'Workers':<8} {'请求':>10}  {'速率':>8}  {'崩溃':>5}  {'FSM':>6}")
    print(f"  {'-'*58}")
    for target in ["free5gc", "oai", "open5gs"]:
        t = targets.get(target, {})
        w = t.get("workers", 0)
        r = t.get("total_reqs", 0)
        rate = t.get("req_rate", 0)
        c = t.get("total_crashes", 0)
        fsm = max(t.get("fsm_states", {0})) if t.get("fsm_states") else 0
        p = t.get("deep_probes", 0)
        print(f"  {target:<12} {w:<8} {r:>8,}  {rate:>6.0f}/s  {c:>5}  {fsm:>4}  (🔍{p})")

    print(f"\n  {'总计':<12} {'':<8} {total_reqs:>8,}  {total_rate:>6.0f}/s  {total_crashes:>5}   🔍{total_probes}")

    # Crashes detail
    crash_files = list(RESULTS.rglob("crash_repro_*.py"))
    if crash_files:
        print(f"\n  🔴 崩溃: {len(crash_files)} 个复现脚本")
        for cf in crash_files[:5]:
            print(f"     {cf.relative_to(RESULTS)}")

    # Estimated
    elapsed_est = total_reqs / max(total_rate, 1)
    if total_rate > 0:
        print(f"\n  📊 预估 5h 总请求: ~{int(total_rate * 5 * 3600):,}")
        print(f"  ⏱  已发送: {total_reqs:,} (约 {elapsed_est:.0f}s)")

    print(f"\n{'='*70}\n")

if __name__ == "__main__":
    main()
