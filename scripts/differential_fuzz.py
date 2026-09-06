#!/usr/bin/env python3
"""Differential fuzzing: same SBI request → free5GC + OAI + Open5GS → compare.

Usage: python3 scripts/differential_fuzz.py --minutes 30
"""

import argparse
import json
import logging
import random
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.fuzzing_engine.novel_algorithms import DifferentialFuzzer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("differential_fuzz")

# ─── Endpoints ───────────────────────────────────────────────────

ENDPOINTS = {
    "free5gc": ("172.24.0.10", 8000),
    "oai":     ("172.25.0.10", 80),
    "open5gs": ("172.23.0.10", 7777),
}

# ─── SBI Templates (common across all three targets) ─────────────

SBI_TEMPLATES = {
    "NFRegister": {
        "method": "PUT",
        "path": "/nnrf-nfm/v1/nf-instances/{nfInstanceId}",
        "body": {"nfInstanceId": "AMF-instance-001", "nfType": "AMF",
                 "nfStatus": "REGISTERED", "ipv4Addresses": ["172.25.0.20"],
                 "fqdn": "amf.local", "priority": 1, "capacity": 100, "load": 0,
                 "nfServices": [{"serviceInstanceId": "ns-001",
                                 "serviceName": "namf-comm",
                                 "versions": [{"apiVersionInUri": "v1",
                                               "apiFullVersion": "1.0.0"}],
                                 "scheme": "http",
                                 "nfServiceStatus": "REGISTERED"}]},
    },
    "NFUpdate": {
        "method": "PATCH",
        "path": "/nnrf-nfm/v1/nf-instances/{nfInstanceId}",
        "body": {"nfStatus": "REGISTERED", "load": 50, "capacity": 200},
    },
    "NFDeregister": {
        "method": "DELETE",
        "path": "/nnrf-nfm/v1/nf-instances/{nfInstanceId}",
        "body": None,
    },
    "NFDiscover": {
        "method": "GET",
        "path": "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=SMF",
        "body": None,
    },
    "NFAccessToken": {
        "method": "POST",
        "path": "/nnrf-nfm/v1/oauth2/token",
        "body": {"grant_type": "client_credentials",
                 "nfInstanceId": "AMF-instance-001",
                 "scope": "namf-comm"},
    },
    "UEAuthenticate": {
        "method": "POST",
        "path": "/nausf-auth/v1/ue-authentications",
        "body": {"supiOrSuci": "imsi-901700000000001",
                 "servingNetworkName": "5G:mnc070.mcc901.3gppnetwork.org",
                 "authType": "5G_AKA"},
    },
    "NFProfile": {
        "method": "GET", "path": "/nnrf-nfm/v1/nf-instances/{nfInstanceId}", "body": None,
    },
    "NFList": {
        "method": "GET", "path": "/nnrf-nfm/v1/nf-instances", "body": None,
    },
    "NFSubscribe": {
        "method": "POST", "path": "/nnrf-nfm/v1/subscriptions",
        "body": {"nfStatusNotifyUri": "http://127.0.0.1:8080/callback",
                 "reqNotifEvents": ["NF_REGISTERED"], "validityTime": "3600"},
    },
    "NFUnsubscribe": {
        "method": "DELETE", "path": "/nnrf-nfm/v1/subscriptions/{nfInstanceId}", "body": None,
    },
}

# ─── Mutation helpers ────────────────────────────────────────────

MUTATIONS = [
    "none", "type_confusion", "boundary_ints", "null_required",
    "empty_values", "oversized", "extra_fields",
    "sql_injection", "special_chars", "path_traversal_uri",
]

def mutate(op_name: str, body: dict, mutation: str) -> dict:
    """Apply a mutation to the request body."""
    if body is None:
        return None
    b = json.loads(json.dumps(body))  # deep copy

    if mutation == "none":
        return b
    elif mutation == "type_confusion":
        for k in list(b.keys()):
            v = b[k]
            if isinstance(v, bool): b[k] = "TRUE"
            elif isinstance(v, int): b[k] = str(v)
            elif isinstance(v, str) and v: b[k] = 99999
    elif mutation == "boundary_ints":
        for k, v in b.items():
            if isinstance(v, int):
                b[k] = random.choice(
                    [-1, 0, 1, 255, 65535, 2**31-1, -2**31])
    elif mutation == "null_required":
        if b:
            b[list(b.keys())[0]] = None
    elif mutation == "empty_values":
        for k, v in b.items():
            if isinstance(v, str): b[k] = ""
            elif isinstance(v, list): b[k] = []
    elif mutation == "oversized":
        for k, v in b.items():
            if isinstance(v, str): b[k] = "A" * 100000
    elif mutation == "extra_fields":
        b["\x00null_byte"] = "injected"
        b["../../../etc/passwd"] = "path_traversal"
    elif mutation == "sql_injection":
        for k in list(b.keys()):
            if isinstance(b[k], str):
                b[k] = "'; DROP TABLE subscribers; --"
    elif mutation == "special_chars":
        for k in list(b.keys()):
            if isinstance(b[k], str):
                b[k] += "\x00\x01\xff\r\n\r\n"
    return b

def build_request(op_name: str, mutation: str) -> Tuple[str, str, Dict]:
    t = SBI_TEMPLATES[op_name]
    method = t["method"]
    path = t["path"]
    body = t["body"]
    if body and mutation != "none":
        body = mutate(op_name, body, mutation)
    if "{nfInstanceId}" in path:
        path = path.replace("{nfInstanceId}",
                            f"{random.choice(['AMF','SMF','NRF'])}-{random.randint(1,999):04d}")
    return method, path, body

# ─── Main ────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Differential 5G Core Fuzzer")
    parser.add_argument("--minutes", type=float, default=30,
                        help="Duration in minutes")
    parser.add_argument("--output", type=str, default="./results/differential",
                        help="Output directory")
    args = parser.parse_args()

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)

    logger.info("=" * 60)
    logger.info("Differential Fuzzer — %s", ", ".join(ENDPOINTS.keys()))
    logger.info("Duration: %.0f min | Output: %s", args.minutes, output)
    logger.info("=" * 60)

    fuzzer = DifferentialFuzzer(ENDPOINTS, list(SBI_TEMPLATES.keys()), build_request)

    deadline = time.time() + args.minutes * 60
    operations = list(SBI_TEMPLATES.keys())
    batch = 0
    start = time.time()

    while time.time() < deadline:
        batch += 1
        op = random.choice(operations)
        mut = random.choice(MUTATIONS)

        result = fuzzer.run_one(op, mut)

        if batch % 50 == 0:
            elapsed = time.time() - start
            rate = batch / max(elapsed, 1)
            div_rate = fuzzer.get_divergence_rate()
            logger.info("Batch %d | %d tests | %.1f/min | %.1f%% divergent",
                        batch, fuzzer.total_tests, rate * 60, div_rate * 100)

    # ── Final report ──
    elapsed = time.time() - start
    summary = fuzzer.summary()
    summary["duration_minutes"] = round(elapsed / 60, 1)
    summary["requests_per_second"] = round(batch / max(elapsed, 1), 1)

    report_file = output / f"diff_report_{time.strftime('%Y%m%d_%H%M%S')}.json"
    report = {
        "summary": summary,
        "divergences": fuzzer.divergences[:200],  # top 200
        "top_divergent_ops": fuzzer.get_top_divergent_ops(10),
    }
    report_file.write_text(json.dumps(report, indent=2, default=str))

    print("\n" + "=" * 60)
    print("DIFFERENTIAL FUZZING COMPLETE")
    print("=" * 60)
    print(f"Duration:     {elapsed/60:.1f} min")
    print(f"Tests:        {fuzzer.total_tests}")
    print(f"Divergences:  {fuzzer.total_divergences} "
          f"({fuzzer.get_divergence_rate()*100:.1f}%)")
    print(f"\nTop divergent operations:")
    for op, count, total in fuzzer.get_top_divergent_ops(5):
        print(f"  {op}: {count}/{total} divergences")
    print(f"\nFull report: {report_file}")


if __name__ == "__main__":
    main()
