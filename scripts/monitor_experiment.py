#!/usr/bin/env python3
"""Monitor 250-trial experiment, auto-fix failures, print progress."""

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from glob import glob
from pathlib import Path

RESULTS_DIR = Path("/home/mm/桌面/5g-fuzzer/results/experiment_v2")
LOG_DIR = Path("/tmp")
LAUNCHER = "/home/mm/桌面/5g-fuzzer/scripts/experiment_v2_launcher.py"

# Expected targets and groups
ALL_TARGETS = [
    "free5gc-nrf","free5gc-amf","free5gc-smf","free5gc-ausf","free5gc-udm",
    "free5gc-udr","free5gc-pcf","free5gc-nssf",
    "oai-nrf","oai-amf","oai-ausf","oai-smf","oai-udm","oai-udr","oai-nssf","oai-pcf",
    "open5gs-nrf","open5gs-amf","open5gs-smf","open5gs-ausf","open5gs-udm",
    "open5gs-udr","open5gs-nssf","open5gs-bsf","open5gs-scp",
]
GROUPS = ["G0","G1","G2","G3","G4","G5"]
BASELINES = ["aflnet","stateafl","schemathesis","boofuzz"]


def get_running():
    """Count running experiment processes by type."""
    try:
        out = subprocess.check_output(
            ["ps", "aux"], text=True, timeout=5)
        ablation = len([l for l in out.split("\n") if "experiment_v2_launcher" in l and "--group" in l and "none" not in l])
        baseline = len([l for l in out.split("\n") if "experiment_v2_launcher" in l and "--baseline" in l])
        return ablation, baseline
    except:
        return 0, 0


def get_completed():
    """Count completed JSON result files."""
    jsons = list(RESULTS_DIR.glob("*/*.json"))
    ablation = len([j for j in jsons if "_G" in j.stem])
    baseline = len([j for j in jsons if "baseline" in j.stem])
    return ablation, baseline, jsons


def check_dead_trials():
    """Find processes that died and restart them."""
    restarted = []

    for target in ALL_TARGETS:
        for group in GROUPS:
            log_file = LOG_DIR / f"exp_{target}_{group}.log"
            # Check if process is running for this config
            cmd_check = subprocess.run(
                ["pgrep", "-f", f"launcher.py.*--target {target}.*--group {group}"],
                capture_output=True, text=True)

            if cmd_check.returncode != 0:
                # Process not running - check if it ever started
                if log_file.exists():
                    log_content = log_file.read_text()
                    if "Done." in log_content:
                        continue  # Completed normally

                    # Check if crashed with error
                    if "Traceback" in log_content or "Error" in log_content:
                        last_lines = log_content.strip().split("\n")[-5:]
                        error = "\n".join(last_lines)
                        print(f"  [DEAD] {target} {group}: crashed")
                        print(f"    {error[:200]}")

                        # Try restart
                        try:
                            subprocess.Popen(
                                ["nohup", "python3", LAUNCHER,
                                 "--target", target, "--group", group, "--hours", "24"],
                                stdout=open(str(log_file) + ".restart", "w"),
                                stderr=subprocess.STDOUT)
                            restarted.append(f"{target} {group}")
                        except Exception as e:
                            print(f"    Restart failed: {e}")
                else:
                    # Never started - launch it
                    try:
                        subprocess.Popen(
                            ["nohup", "python3", LAUNCHER,
                             "--target", target, "--group", group, "--hours", "24"],
                            stdout=open(str(log_file), "w"),
                            stderr=subprocess.STDOUT)
                        restarted.append(f"{target} {group}")
                    except Exception as e:
                        print(f"    Launch failed: {e}")

        for bl in BASELINES:
            log_file = LOG_DIR / f"exp_{target}_baseline_{bl}.log"
            cmd_check = subprocess.run(
                ["pgrep", "-f", f"launcher.py.*--target {target}.*--baseline {bl}"],
                capture_output=True, text=True)

            if cmd_check.returncode != 0:
                if log_file.exists():
                    log_content = log_file.read_text()
                    if "Done." in log_content:
                        continue
                    if "Traceback" in log_content or "Error" in log_content:
                        print(f"  [DEAD] {target} baseline_{bl}: crashed")
                        try:
                            subprocess.Popen(
                                ["nohup", "python3", LAUNCHER,
                                 "--target", target, "--group", "none",
                                 "--baseline", bl, "--hours", "24"],
                                stdout=open(str(log_file) + ".restart", "w"),
                                stderr=subprocess.STDOUT)
                            restarted.append(f"{target} baseline_{bl}")
                        except Exception as e:
                            print(f"    Restart failed: {e}")

    return restarted


def check_docker_health():
    """Check and fix unhealthy containers."""
    try:
        out = subprocess.check_output(
            ["docker", "ps", "--format", "{{.Names}}\t{{.Status}}"], text=True)
        unhealthy = []
        for line in out.strip().split("\n"):
            if "unhealthy" in line.lower() or "exited" in line.lower():
                name = line.split("\t")[0]
                unhealthy.append(name)

        if unhealthy:
            for name in unhealthy:
                if "oai" in name and "pcf" not in name:
                    subprocess.run(["docker", "restart", name], capture_output=True)
                    print(f"  [FIX] Restarted unhealthy container: {name}")
        return unhealthy
    except:
        return []


def print_results_summary():
    """Print key metrics from completed results."""
    ablation, baseline, all_jsons = get_completed()

    # Collect metrics from completed ablation results
    summary = []
    for jf in sorted(all_jsons):
        try:
            d = json.loads(jf.read_text())
            target = d.get("target", "?")
            group = d.get("group", "?")
            reqs = d.get("requests", 0)
            crashes = d.get("crashes", 0)
            fsm = d.get("fsm_state_count", len(d.get("fsm_states", {})))

            # Get regret
            rc = d.get("regret_curve", [])
            regret = 0
            if rc:
                lr = rc[-1]
                regret = lr.get("regret", lr) if isinstance(lr, dict) else lr

            summary.append({
                "target": target, "group": group,
                "reqs": reqs, "crashes": crashes,
                "fsm": fsm, "regret": int(regret),
            })
        except:
            pass

    if summary:
        print(f"\n  {'Target':<20s} {'Group':<14s} {'Reqs':>8s} {'Crash':>6s} {'FSM':>4s} {'Regret':>8s}")
        print(f"  {'-'*20} {'-'*14} {'-'*8} {'-'*6} {'-'*4} {'-'*8}")
        for s in sorted(summary, key=lambda x: (x["target"], x["group"]))[-20:]:
            print(f"  {s['target']:<20s} {s['group']:<14s} {s['reqs']:>8,d} {s['crashes']:>6,d} {s['fsm']:>4d} {s['regret']:>8,d}")


def main():
    print(f"\n{'='*60}")
    print(f"Experiment Monitor — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")

    # 1. Process counts
    ablation_running, baseline_running = get_running()
    ablation_done, baseline_done, _ = get_completed()

    print(f"\n  Processes: {ablation_running} ablation + {baseline_running} baseline = {ablation_running + baseline_running} running")
    print(f"  Completed: {ablation_done} ablation + {baseline_done} baseline = {ablation_done + baseline_done} / 250")

    # 2. Memory
    try:
        mem = subprocess.check_output(["free", "-m"], text=True).split("\n")[1].split()
        print(f"  Memory: {mem[2]} MB used / {mem[1]} MB total, {mem[6]} MB available")
    except:
        pass

    # 3. Docker health
    unhealthy = check_docker_health()
    if unhealthy:
        print(f"  Docker unhealthy: {len(unhealthy)} containers")

    # 4. Check for dead trials
    print(f"\n  Checking dead trials...")
    restarted = check_dead_trials()
    if restarted:
        print(f"  Restarted: {len(restarted)} trials")
    else:
        print(f"  No dead trials found.")

    # 5. Results
    if ablation_done > 0:
        print_results_summary()

    print(f"\n{'='*60}\n")


if __name__ == "__main__":
    main()
