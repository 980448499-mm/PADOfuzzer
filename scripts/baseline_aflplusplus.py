#!/usr/bin/env python3
"""Baseline 2: AFL++ coverage-guided fuzzer harness.

Uses AFL++ (industry-standard fuzzer) to mutate JSON SBI requests.
AFL++ mutates the raw bytes of seed inputs — including potentially key names,
but without any JSON-structure awareness. This represents the generic-fuzzer baseline.

Architecture: Python harness reads AFL++ mutated input from stdin,
sends as HTTP request, reports exit code for crash detection.

Usage:
  export AFL_SKIP_CPUFREQ=1
  afl-fuzz -i seeds/ -o afl_out/ -- python3 baseline_aflplusplus.py @@
"""

import json, sys, os, http.client

TARGET_HOST = os.environ.get("AFL_TARGET_HOST", "172.24.0.10")
TARGET_PORT = int(os.environ.get("AFL_TARGET_PORT", "8000"))

# Valid SBI request templates (used as seeds)
SBI_ENDPOINTS = [
    ("PUT", "/nnrf-nfm/v1/nf-instances/AMF-fuzz-0001"),
    ("PATCH", "/nnrf-nfm/v1/nf-instances/AMF-fuzz-0001"),
    ("DELETE", "/nnrf-nfm/v1/nf-instances/AMF-fuzz-0001"),
    ("GET", "/nnrf-disc/v1/nf-instances?target-nf-type=AMF"),
    ("POST", "/nnrf-nfm/v1/nf-instances/AMF-fuzz-0001/access-token"),
    ("POST", "/nausf-auth/v1/ue-authentications"),
    ("POST", "/namf-comm/v1/ue-contexts/ue-001/n1-n2-messages"),
    ("GET", "/nudm-sdm/v1/imsi-901700000000001/am-data"),
]

SEED_BODIES = [
    b'{"nfInstanceId":"AMF-fuzz-0001","nfType":"AMF","nfStatus":"REGISTERED"}',
    b'{"supiOrSuci":"imsi-901700000000001","servingNetworkName":"5G:mnc001.mcc001.3gppnetwork.org"}',
    b'{"nfInstanceId":"AMF-fuzz-0001","grant_type":"client_credentials","scope":"nnrf-nfm"}',
    b'{}',
    b'{"nfStatus":"REGISTERED","heartBeatTimer":10}',
]


def send_http(method: str, path: str, body: bytes) -> int:
    """Send HTTP request. Returns status code or 0 on crash/error."""
    try:
        conn = http.client.HTTPConnection(TARGET_HOST, TARGET_PORT, timeout=5)
        headers = {}
        if body:
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        status = resp.status
        resp.read()
        conn.close()
        return status
    except Exception:
        return 0


def main():
    """AFL++ harness: read mutated input, send as HTTP."""
    if len(sys.argv) > 1 and sys.argv[1] == "@@":
        # AFL++ file-based mode: read from the temp file
        input_file = sys.argv[2] if len(sys.argv) > 2 else sys.argv[1]
        with open(input_file, "rb") as f:
            data = f.read()
    else:
        # stdin mode
        data = sys.stdin.buffer.read()

    if len(data) < 2:
        return 0  # Skip empty inputs

    # Use first byte to select endpoint, remaining bytes as body mutation
    ep_idx = data[0] % len(SBI_ENDPOINTS)
    method, path = SBI_ENDPOINTS[ep_idx]

    # Use remaining bytes as body (try to parse as JSON modifier)
    body_bytes = data[1:]
    if not body_bytes:
        body_idx = data[0] % len(SEED_BODIES)
        body_bytes = SEED_BODIES[body_idx]

    status = send_http(method, path, body_bytes)

    # AFL++ interprets non-zero exit as crash. We map HTTP 5xx ≠ crash.
    # Only connection failures (status=0) are potential crashes.
    if status == 0:
        sys.exit(1)  # Report as crash to AFL++
    sys.exit(0)


if __name__ == "__main__":
    main()
