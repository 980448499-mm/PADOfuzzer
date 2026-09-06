#!/usr/bin/env python3
"""Monitor all fuzzing experiments: original + JKSMPADO ablation. Auto-restart dead trials."""
import json, os, subprocess, sys, time
from datetime import datetime
from pathlib import Path

RESULTS_DIR = Path("/home/mm/桌面/5g-fuzzer/results/experiment_v2")
ABLATION_LOG_DIR = Path("/tmp/ablation_v3")
LAUNCHER = "/home/mm/桌面/5g-fuzzer/scripts/experiment_v2_launcher.py"
ORIG_LOG_DIR = Path("/tmp")

# Expected 5GC containers (must be running for valid fuzzing)
EXPECTED_CONTAINERS = {
    "free5gc": ["fuzzing-free5gc-nrf", "fuzzing-free5gc-amf", "fuzzing-free5gc-smf",
                 "fuzzing-free5gc-ausf", "fuzzing-free5gc-udm", "fuzzing-free5gc-udr",
                 "fuzzing-free5gc-pcf", "fuzzing-free5gc-nssf"],
    "oai": ["fuzzing-oai-nrf", "fuzzing-oai-amf", "fuzzing-oai-smf",
            "fuzzing-oai-ausf", "fuzzing-oai-udm", "fuzzing-oai-udr",
            "fuzzing-oai-nssf", "fuzzing-oai-pcf"],
    "open5gs": ["fuzzing-open5gs-nrf", "fuzzing-open5gs-amf", "fuzzing-open5gs-smf",
                "fuzzing-open5gs-ausf", "fuzzing-open5gs-udm", "fuzzing-open5gs-udr",
                "fuzzing-open5gs-nssf", "fuzzing-open5gs-bsf", "fuzzing-open5gs-scp"],
}

DEPLOY_DIRS = {
    "free5gc": "/home/mm/桌面/5g-fuzzer/src/deployment/free5gc",
    "oai": "/home/mm/桌面/5g-fuzzer/src/deployment/oai",
    "open5gs": "/home/mm/桌面/5g-fuzzer/src/deployment/open5gs",
}

ALL_TARGETS = [
    "free5gc-nrf","free5gc-amf","free5gc-smf","free5gc-ausf",
    "free5gc-udm","free5gc-udr","free5gc-pcf","free5gc-nssf",
    "oai-nrf","oai-amf","oai-ausf","oai-smf","oai-udm","oai-udr","oai-nssf","oai-pcf",
    "open5gs-nrf","open5gs-amf","open5gs-smf","open5gs-ausf","open5gs-udm",
    "open5gs-udr","open5gs-nssf","open5gs-bsf","open5gs-scp",
]
GROUPS = ["G0","G1","G2","G3","G4"]
BASELINES = ["aflnet","stateafl","schemathesis","boofuzz"]
ABLATION_FLAGS = [
    ("G5_nojksm", "--disable-jksm"),
    ("G6_nopado", "--disable-pado"),
]

def count_processes():
    """Count running processes by category."""
    try:
        out = subprocess.check_output(["ps", "aux"], text=True, timeout=5)
        original = len([l for l in out.split("\n") if "experiment_v2_launcher" in l
                        and "--disable-jksm" not in l and "--disable-pado" not in l])
        ablation = len([l for l in out.split("\n") if "experiment_v2_launcher" in l
                        and ("--disable-jksm" in l or "--disable-pado" in l)])
        return original, ablation
    except:
        return 0, 0

def check_containers():
    """Verify all 5GC containers are running. Start if not."""
    try:
        out = subprocess.check_output(["docker", "ps", "--format", "{{.Names}}"], text=True)
        running = set(out.strip().split("\n"))
    except:
        return ["docker ps failed"]

    missing = []
    for impl, containers in EXPECTED_CONTAINERS.items():
        for c in containers:
            if c not in running:
                missing.append((impl, c))

    if missing:
        print(f"  [CONTAINERS] {len(missing)} missing, attempting restart...")
        for impl, c in missing:
            # Try restart first
            r = subprocess.run(["docker", "restart", c], capture_output=True, text=True)
            if r.returncode != 0:
                # Container doesn't exist — need docker-compose up
                deploy_dir = DEPLOY_DIRS.get(impl)
                if deploy_dir:
                    print(f"  [DEPLOY] Starting {impl} containers via docker-compose...")
                    subprocess.run(
                        ["docker", "compose", "-f", f"{deploy_dir}/docker-compose.yml", "up", "-d"],
                        capture_output=True, text=True)
        return [f"{impl}/{c}" for impl, c in missing]
    return []

def check_ablation():
    """Check ablation trials, restart dead ones."""
    restarted = []
    for target in ALL_TARGETS:
        for gname, flag in ABLATION_FLAGS:
            log_file = ABLATION_LOG_DIR / f"{target}_{gname}.log"
            cmd_check = subprocess.run(
                ["pgrep", "-f", f"launcher.py.*--target {target}.*{flag}"],
                capture_output=True, text=True)
            if cmd_check.returncode != 0:
                if log_file.exists():
                    content = log_file.read_text()
                    if "Done." in content:
                        continue
                    if "Traceback" in content or "Error" in content:
                        last = content.strip().split("\n")[-3:]
                        print(f"  [DEAD ABLATION] {target} {gname}: {last[-1][:150]}")
                        try:
                            subprocess.Popen(
                                ["nohup", "python3", LAUNCHER,
                                 "--target", target, "--group", "G4", flag, "--hours", "24"],
                                stdout=open(str(log_file) + ".restart", "w"),
                                stderr=subprocess.STDOUT)
                            restarted.append(f"{target}_{gname}")
                        except Exception as e:
                            print(f"    Restart failed: {e}")
    return restarted

def check_original():
    """Check original experiment trials."""
    restarted = []
    for target in ALL_TARGETS:
        for group in GROUPS:
            log_file = ORIG_LOG_DIR / f"exp_{target}_{group}.log"
            cmd_check = subprocess.run(
                ["pgrep", "-f", f"launcher.py.*--target {target}.*--group {group}"],
                capture_output=True, text=True)
            if cmd_check.returncode != 0:
                if log_file.exists():
                    content = log_file.read_text()
                    if "Done." in content:
                        continue
                    if "Traceback" in content or "Error" in content:
                        print(f"  [DEAD] {target} {group}")
                        try:
                            subprocess.Popen(
                                ["nohup", "python3", LAUNCHER,
                                 "--target", target, "--group", group, "--hours", "24"],
                                stdout=open(str(log_file) + ".restart", "w"),
                                stderr=subprocess.STDOUT)
                            restarted.append(f"{target}_{group}")
                        except:
                            pass
    return restarted

def print_results():
    """Print summary of completed results."""
    jsons = list(RESULTS_DIR.glob("*/*.json"))
    ablation_jsons = list(ABLATION_LOG_DIR.glob("*.log"))
    
    ablation_done = len([j for j in jsons if "_G" in j.stem])
    baseline_done = len([j for j in jsons if "baseline" in j.stem])
    
    # Ablation v3 results (G5/G6)
    ablv3_done = 0
    ablv3_total = 0
    ablv3_data = []
    for logf in sorted(ablation_jsons):
        ablv3_total += 1
        content = logf.read_text()
        if "Done." in content:
            ablv3_done += 1
        # Extract key metrics
        for line in content.split("\n"):
            if "requests:" in line.lower() or "crashes:" in line.lower():
                ablv3_data.append(f"    {logf.stem}: {line.strip()[:100]}")
                break

    print(f"\n  Original: {ablation_done} ablation + {baseline_done} baseline done")
    print(f"  Ablation v3 (JKSMPADO): {ablv3_done}/{ablv3_total} done")
    if ablv3_data:
        for d in ablv3_data[-8:]:
            print(d)

def main():
    print(f"\n{'='*55}")
    print(f"Monitor — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*55}")

    orig, ablv3 = count_processes()
    total = orig + ablv3
    print(f"\n  Processes: {orig} original + {ablv3} ablation = {total} running")

    # Memory
    try:
        mem = subprocess.check_output(["free", "-m"], text=True).split("\n")[1].split()
        print(f"  Memory: {mem[2]} MB used / {mem[1]} MB total, {mem[6]} MB available")
    except:
        pass

    # Container health (check missing + unhealthy)
    missing = check_containers()
    if missing:
        print(f"  Containers restarted: {len(missing)}")
    try:
        out = subprocess.check_output(["docker", "ps", "--format", "{{.Names}}\t{{.Status}}"], text=True)
        unhealthy = [l.split("\t")[0] for l in out.strip().split("\n") if "unhealthy" in l.lower()]
        if unhealthy:
            for name in unhealthy:
                subprocess.run(["docker", "restart", name], capture_output=True)
            print(f"  Docker: restarted {len(unhealthy)} unhealthy containers")
    except:
        pass

    # Check dead trials
    print(f"\n  Checking original trials...")
    r1 = check_original()
    print(f"  Checking ablation trials...")
    r2 = check_ablation()
    total_r = len(r1) + len(r2)
    if total_r > 0:
        print(f"  Restarted: {total_r} trials ({len(r1)} original + {len(r2)} ablation)")
    else:
        print(f"  No dead trials.")

    # Results
    print_results()
    print(f"\n{'='*55}\n")

if __name__ == "__main__":
    main()
