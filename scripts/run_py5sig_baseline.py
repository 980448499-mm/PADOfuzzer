#!/usr/bin/env python3
"""Run py5sig as an external baseline fuzzer against 5GC targets.

py5sig (ANSSI-FR) is a 5GC-specific SBI fuzzer that uses OpenAPI specs
and wordlist-based value mutation. It acts as an NF consumer, registers
with the NRF, discovers target NFs, and sends fuzzed requests.

This wrapper:
  1. Runs py5sig against each target's NRF with --fuzzing
  2. Parses stdout for request counts and crash indicators
  3. Runs for a configurable duration (default 1h)
  4. Outputs results in our standard baseline JSON format
"""

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

# Target configuration
TARGETS = {
    "free5gc": {
        "nrf_url": "http://172.24.0.10:8000",
        "nf_types": ["NRF", "AMF", "SMF", "AUSF", "UDM", "UDR"],
        "proto": "http1.1",
    },
    "oai": {
        "nrf_url": "http://172.25.0.10:80",
        "nf_types": ["NRF", "AMF", "SMF", "AUSF", "UDM", "UDR"],
        "proto": "http1.1",
    },
    "open5gs": {
        "nrf_url": "http://172.23.0.10:7777",
        "nf_types": ["NRF", "AMF", "SMF", "AUSF", "UDM", "UDR", "SCP"],
        "proto": "http2",
    },
}


def count_output_metrics(output: str) -> Dict:
    """Parse py5sig stdout to count requests and detect crashes."""
    lines = output.split("\n")
    req_count = 0
    crash_count = 0
    status_codes = {}

    # py5sig prints "GET fuzzing", "POST fuzzing", etc. for each request
    for line in lines:
        if re.search(r"(GET|POST|PUT|DELETE|PATCH) fuzzing", line):
            req_count += 1
        # Look for HTTP status in the output
        # py5sig prints the reason_phrase which may be empty for crashes
        if "Exception connecting to" in line:
            crash_count += 1
        # Count status codes if present
        match = re.search(r"status[:_]\s*(\d{3})", line, re.IGNORECASE)
        if match:
            code = int(match.group(1))
            status_codes[code] = status_codes.get(code, 0) + 1

    # If no explicit request count from parsing, estimate from lines
    if req_count == 0:
        req_count = len([l for l in lines if "fuzzing" in l.lower()])

    return {
        "requests": req_count,
        "crashes": crash_count,
        "status_codes": status_codes,
    }


def run_py5sig(
    target_name: str,
    nf_type: str,
    nrf_url: str,
    duration_h: float,
    output_dir: Path,
) -> Dict:
    """Run py5sig against a specific target NF type."""
    nf_instance_id = str(uuid.uuid4())
    log_file = output_dir / f"{target_name}_py5sig_{nf_type}.log"

    cmd = [
        sys.executable, "-m", "py5sig",
        "--fuzzing",
        "--nfInstanceId", nf_instance_id,
        "--targetNfType", nf_type,
        "--nfType", "AMF" if nf_type != "NRF" else "NRF",
        "--nrf-fqdn", nrf_url,
        "--scope", "nnrf-nfm",
        nrf_url,
    ]

    print(f"[py5sig] {target_name}/{nf_type}: starting (1h)")
    print(f"  NRF: {nrf_url}")
    print(f"  NF Instance: {nf_instance_id}")

    start_time = time.time()
    deadline = start_time + duration_h * 3600

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        output_lines = []
        last_progress = start_time

        while proc.poll() is None and time.time() < deadline:
            try:
                line = proc.stdout.readline()
                if line:
                    output_lines.append(line)
                    now = time.time()
                    if now - last_progress >= 360:  # Log every 6 min
                        elapsed = (now - start_time) / 3600
                        metrics = count_output_metrics("".join(output_lines))
                        print(f"  [{elapsed:.1f}h] {metrics['requests']} reqs, "
                              f"{metrics['crashes']} crashes")
                        last_progress = now
            except Exception:
                break

        # Timeout reached
        if time.time() >= deadline:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()

        # Read remaining output
        remaining, _ = proc.communicate(timeout=10)
        if remaining:
            output_lines.append(remaining)

        full_output = "".join(output_lines)

        # Save log
        with open(log_file, "w") as f:
            f.write(full_output)

        metrics = count_output_metrics(full_output)
        elapsed_h = (time.time() - start_time) / 3600

        result = {
            "target": target_name,
            "nf_type": nf_type,
            "fuzzer": "py5sig",
            "nrf_url": nrf_url,
            "nf_instance_id": nf_instance_id,
            "duration_h": round(elapsed_h, 2),
            "started": datetime.fromtimestamp(start_time).isoformat(),
            "requests": metrics["requests"],
            "crashes": metrics["crashes"],
            "status_codes": metrics["status_codes"],
            "log_file": str(log_file),
        }

        print(f"  Done: {metrics['requests']} reqs, {metrics['crashes']} crashes")
        return result

    except Exception as e:
        print(f"  ERROR: {e}")
        return {
            "target": target_name,
            "nf_type": nf_type,
            "fuzzer": "py5sig",
            "error": str(e),
            "duration_h": (time.time() - start_time) / 3600,
        }


def main():
    parser = argparse.ArgumentParser(description="Run py5sig baseline experiments")
    parser.add_argument("--target", choices=list(TARGETS.keys()), required=True)
    parser.add_argument("--nf-type", dest="nf_type", default=None,
                        help="Specific NF type (default: all)")
    parser.add_argument("--hours", type=float, default=1.0)
    parser.add_argument("--output-dir", default="results/experiment_v2")
    args = parser.parse_args()

    target_cfg = TARGETS[args.target]
    output_dir = Path(args.output_dir) / args.target
    output_dir.mkdir(parents=True, exist_ok=True)

    nf_types = [args.nf_type] if args.nf_type else target_cfg["nf_types"]

    results = []
    for nf_type in nf_types:
        result = run_py5sig(
            args.target, nf_type, target_cfg["nrf_url"],
            args.hours, output_dir,
        )
        results.append(result)

    # Aggregate across NF types
    total_reqs = sum(r.get("requests", 0) for r in results)
    total_crashes = sum(r.get("crashes", 0) for r in results)

    summary = {
        "target": args.target,
        "fuzzer": "py5sig",
        "duration_h": args.hours,
        "total_requests": total_reqs,
        "total_crashes": total_crashes,
        "nf_results": results,
    }

    summary_path = output_dir / f"{args.target}_baseline_py5sig.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\n[py5sig] {args.target}: {total_reqs} reqs, {total_crashes} crashes")
    print(f"  Summary: {summary_path}")


if __name__ == "__main__":
    main()
