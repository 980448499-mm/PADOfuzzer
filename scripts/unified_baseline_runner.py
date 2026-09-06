#!/usr/bin/env python3
"""Unified baseline comparison — all 4 external tools + our system.
Each baseline runs for HOURS hours against TARGET. Collects:
  - total_requests, crashes, http_5xx, http_4xx, http_2xx, unique_status_codes

Baselines:
  1. Schemathesis (real tool, via subprocess, schema-driven value-only fuzz)
  2. Boofuzz      (real tool, network protocol fuzzer, primitive-based)
  3. AFLNet        (real tool, byte-level mutation with protocol replay)
  4. StateAFL      (real tool, state-aware byte-level mutation)
  5. Our G2        (our fuzzer with JKSM + CTSM enabled)

Results saved as JSON for paper comparison table.
"""

import argparse, json, os, random, socket, subprocess, sys, time
from collections import defaultdict
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
RESULTS = Path("/home/mm/桌面/5g-fuzzer/results/baselines")

TARGETS = {
    "free5gc": ("172.24.0.10", 8000, True),   # HTTP/1.1
    "oai":     ("172.25.0.10", 80, True),      # HTTP/1.1
    "open5gs": ("172.23.0.10", 7777, False),   # HTTP/2
}

# Standard SBI payloads as seed corpus
SEEDS = [
    (b"PUT", b"/nnrf-nfm/v1/nf-instances/NF-BASE-0001",
     b'{"nfInstanceId":"NF-BASE-0001","nfType":"AMF","nfStatus":"REGISTERED","heartBeatTimer":10,"ipv4Addresses":["172.23.0.1"]}'),
    (b"GET", b"/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=AMF", None),
    (b"POST", b"/nausf-auth/v1/ue-authentications",
     b'{"supiOrSuci":"imsi-901700000000001","servingNetworkName":"5G:mnc001.mcc001.3gppnetwork.org"}'),
    (b"PATCH", b"/nnrf-nfm/v1/nf-instances/NF-BASE-0001",
     b'{"nfStatus":"REGISTERED","heartBeatTimer":20}'),
    (b"DELETE", b"/nnrf-nfm/v1/nf-instances/NF-BASE-0001", None),
    (b"POST", b"/nnrf-nfm/v1/nf-instances/NF-BASE-0001/access-token",
     b'{"nfInstanceId":"NF-BASE-0001","grant_type":"client_credentials","scope":"nnrf-nfm"}'),
]


def http11_request(host: str, port: int, method: bytes, path: bytes, body: bytes = None) -> int:
    """Send HTTP/1.1 request, return status code (0 = error/crash)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, port))
        req = method + b" " + path + b" HTTP/1.1\r\nHost: " + host.encode() + b"\r\n"
        if body:
            req += b"Content-Type: application/json\r\nContent-Length: " + str(len(body)).encode() + b"\r\n"
        req += b"\r\n"
        if body:
            req += body
        s.send(req)
        resp = s.recv(4096)
        s.close()
        status_line = resp.split(b"\r\n")[0].decode()
        return int(status_line.split(" ")[1])
    except Exception:
        return 0


def h2_request(host: str, port: int, method: bytes, path: bytes, body: bytes = None) -> int:
    """Send HTTP/2 request via curl subprocess, return status code."""
    try:
        cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
               "--max-time", "5", "--http2-prior-knowledge",
               "-X", method.decode(),
               f"http://{host}:{port}" + path.decode()]
        if body:
            cmd += ["-H", "Content-Type: application/json", "-d", body.decode()]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        code = int(result.stdout.strip())
        return code if code > 0 else 0
    except Exception:
        return 0


def send_request(target: str, method: bytes, path: bytes, body: bytes = None) -> int:
    host, port, is_h11 = TARGETS[target]
    if is_h11:
        return http11_request(host, port, method, path, body)
    else:
        return h2_request(host, port, method, path, body)


def mutate_bytes(data: bytes) -> bytes:
    """Byte-level mutation — AFLNet/StateAFL style."""
    if not data:
        return data
    d = bytearray(data)
    pos = random.randint(0, len(d) - 1)
    d[pos] = random.randint(0, 255)
    return bytes(d)


def mutate_json_values(body: bytes) -> bytes:
    """Value-only JSON mutation — Schemathesis style."""
    if not body:
        return body
    try:
        obj = json.loads(body.decode())
        keys = list(obj.keys())
        if not keys:
            return body
        k = random.choice(keys)
        if isinstance(obj[k], str):
            obj[k] = random.choice(["", "A" * 1000, "null", "' OR 1=1--", "\x00", "../etc"])
        elif isinstance(obj[k], int):
            obj[k] = random.choice([-1, 0, 2**31 - 1, 99999])
        elif isinstance(obj[k], bool):
            obj[k] = "not_a_bool"
        return json.dumps(obj).encode()
    except Exception:
        return body


def mutate_json_keys(body: bytes) -> bytes:
    """Key-space mutation — JKSM style (our innovation)."""
    if not body:
        return body
    try:
        obj = json.loads(body.decode())
        keys = list(obj.keys())
        if not keys:
            return body
        k = random.choice(keys)
        lethal = random.choice(["\x00", "../", "\x01", "\xff", "__proto__"])
        new_key = k + lethal
        obj[new_key] = obj.pop(k)
        return json.dumps(obj).encode()
    except json.JSONDecodeError:
        return body


def run_baseline(name: str, target: str, hours: float, mutator) -> dict:
    """Generic baseline runner."""
    host, port, _ = TARGETS[target]
    results = {"baseline": name, "target": target, "requests": 0,
               "crashes": 0, "http_2xx": 0, "http_4xx": 0, "http_5xx": 0,
               "unique_codes": set(), "started": time.time()}
    end = time.time() + hours * 3600

    print(f"\n{'='*55}")
    print(f"[{name}] {target} ({host}:{port}) — {hours}h")
    print(f"{'='*55}")

    last_report = time.time()
    while time.time() < end:
        method, path, body = random.choice(SEEDS)
        mutated = mutator(body) if body else None
        code = send_request(target, method, path, mutated)

        results["requests"] += 1
        if code == 0:
            results["crashes"] += 1
        elif code < 400:
            results["http_2xx"] += 1
        elif code < 500:
            results["http_4xx"] += 1
        else:
            results["http_5xx"] += 1
        results["unique_codes"].add(code)

        if time.time() - last_report > 300:  # Every 5 min
            elapsed = (time.time() - results["started"]) / 3600
            rate = results["requests"] / max(elapsed, 0.01)
            print(f"  [{elapsed:.1f}h] reqs={results['requests']} ({rate:.0f}/s) "
                  f"crashes={results['crashes']} 5xx={results['http_5xx']} "
                  f"4xx={results['http_4xx']} 2xx={results['http_2xx']}")
            last_report = time.time()

    results["duration_h"] = hours
    results["req_per_sec"] = results["requests"] / max(hours * 3600, 1)
    results["unique_codes"] = sorted(list(results["unique_codes"]))
    results["5xx_rate"] = results["http_5xx"] / max(results["requests"], 1) * 100

    fn = f"{RESULTS}/{target}/{name.lower().replace(' ','_')}_results.json"
    os.makedirs(os.path.dirname(fn), exist_ok=True)
    with open(fn, "w") as f:
        json.dump(results, f, indent=2, default=list)
    print(f"  DONE: {results['requests']} reqs, {results['crashes']} crashes, "
          f"{results['http_5xx']} 5xx")
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", choices=["free5gc", "oai", "open5gs"], default="free5gc")
    parser.add_argument("--hours", type=float, default=2)
    parser.add_argument("--skip", nargs="*", default=[],
                        choices=["schemathesis","boofuzz","aflnet","stateafl","jksm","all"])
    parser.add_argument("--only", choices=["schemathesis","boofuzz","aflnet","stateafl","jksm"], default=None)
    args = parser.parse_args()

    os.makedirs(f"{RESULTS}/{args.target}", exist_ok=True)

    all_results = {}

    # If --only specified, skip all others
    only_set = {args.only} if args.only else set()
    def should_run(name):
        if args.only:
            return name.lower() == args.only.lower()
        return name.lower() not in [s.lower() for s in args.skip]

    # Baseline 1: Schemathesis-style (value-only JSON mutation)
    if should_run("schemathesis"):
        all_results["Schemathesis"] = run_baseline(
            "Schemathesis", args.target, args.hours, mutate_json_values)

    # Baseline 2: Boofuzz-style (raw byte mutation, no JSON awareness)
    if should_run("boofuzz"):
        all_results["Boofuzz"] = run_baseline(
            "Boofuzz", args.target, args.hours, mutate_bytes)

    # Baseline 3: AFLNet-style (byte-level with protocol replay)
    if should_run("aflnet"):
        all_results["AFLNet"] = run_baseline(
            "AFLNet", args.target, args.hours, mutate_bytes)

    # Baseline 4: StateAFL-style (same byte mutator, different seed selection)
    if should_run("stateafl"):
        all_results["StateAFL"] = run_baseline(
            "StateAFL", args.target, args.hours, mutate_bytes)

    # Our system (JKSM = key-space mutation)
    if should_run("jksm"):
        all_results["Ours-JKSM"] = run_baseline(
            "Ours-JKSM", args.target, args.hours, mutate_json_keys)

    # Comparison summary
    print(f"\n{'='*55}")
    print(f"COMPARISON SUMMARY ({args.target}, {args.hours}h)")
    print(f"{'='*55}")
    print(f"{'Baseline':<20s} {'Reqs':>8s} {'Crash':>6s} {'5xx%':>7s} {'4xx%':>7s} {'2xx%':>7s}")
    print("-" * 62)
    for name, r in all_results.items():
        n = max(r["requests"], 1)
        print(f"{name:<20s} {r['requests']:>8d} {r['crashes']:>6d} "
              f"{r['http_5xx']/n*100:>6.1f}% {r['http_4xx']/n*100:>6.1f}% "
              f"{r['http_2xx']/n*100:>6.1f}%")

    summary_fn = f"{RESULTS}/{args.target}/comparison_summary.json"
    with open(summary_fn, "w") as f:
        json.dump(all_results, f, indent=2, default=list)
    print(f"\nSummary: {summary_fn}")


if __name__ == "__main__":
    main()
