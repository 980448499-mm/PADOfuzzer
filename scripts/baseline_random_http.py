#!/usr/bin/env python3
"""Baseline 2: Random HTTP Fuzzer (RHF).

No knowledge of 3GPP SBI templates. Mutates raw HTTP requests (method, path, body)
randomly — representing a "dumb" network fuzzer baseline.

Usage: python3 baseline_random_http.py --target free5gc --hours 2
"""
import argparse, json, random, sys, time, string
from pathlib import Path
import http.client

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# SBI paths (known valid endpoints — but fuzzed randomly)
SBI_PREFIXES = [
    "/nnrf-nfm/v1/nf-instances/",
    "/nnrf-disc/v1/nf-instances",
    "/nausf-auth/v1/ue-authentications",
    "/namf-comm/v1/ue-contexts/",
    "/nudm-sdm/v1/",
    "/nudr-dr/v1/subscription-data/",
]

METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

TARGETS = {
    "free5gc": ("172.24.0.10", 8000),
    "oai": ("172.25.0.10", 80),
    "open5gs": ("172.23.0.50", 7777),
}


def random_path():
    prefix = random.choice(SBI_PREFIXES)
    suffix = ''.join(random.choices(string.ascii_lowercase + string.digits + "/_-", k=random.randint(0, 30)))
    return prefix + suffix


def random_body() -> dict:
    """Generate a random JSON-ish body."""
    body_type = random.choice(["empty", "valid_json", "random_bytes", "deep_nested", "array"])
    if body_type == "empty":
        return {}
    if body_type == "valid_json":
        return {random.choice(["nfType", "nfStatus", "supi", "id", "value"]):
                random.choice(["AMF", "REGISTERED", "imsi-123", 42, None, True, -1])}
    if body_type == "random_bytes":
        return {"data": ''.join(random.choices(string.printable, k=random.randint(1, 5000)))}
    if body_type == "deep_nested":
        d = {}
        curr = d
        for _ in range(random.randint(3, 20)):
            k = random.choice(["a", "B", "c", "d", "E"])
            curr[k] = {}
            curr = curr[k]
        return d
    if body_type == "array":
        return [random.randint(0, 2**31-1) for _ in range(random.randint(0, 100))]
    return {}


def random_headers():
    h = {"Content-Type": random.choice(
        ["application/json", "text/plain", "application/xml",
         "application/x-www-form-urlencoded", ""])}
    if random.random() < 0.3:
        h["Content-Length"] = str(random.randint(-1, 100000))
    if random.random() < 0.2:
        h["Authorization"] = f"Bearer {random.randint(0, 999999)}"
    return h


def send_request(target: str, method: str, path: str, body, headers: dict):
    host, port = TARGETS[target]
    body_bytes = None
    if body and random.random() < 0.8:
        try:
            body_bytes = json.dumps(body).encode()
        except (TypeError, ValueError):
            body_bytes = str(body).encode()[:random.randint(1, 10000)]

    try:
        conn = http.client.HTTPConnection(host, port, timeout=10)
        conn.request(method, path, body=body_bytes, headers=headers)
        resp = conn.getresponse()
        status = resp.status
        resp.read()
        conn.close()
        return status
    except Exception:
        return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", choices=["free5gc", "oai", "open5gs"], required=True)
    parser.add_argument("--hours", type=float, default=2)
    parser.add_argument("--output", type=str, default=None)
    args = parser.parse_args()
    args.output = args.output or f"baseline_rhf_{args.target}.json"

    start = time.time()
    end = start + args.hours * 3600
    results = {"target": args.target, "baseline": "Random HTTP Fuzzer",
               "mutations_applied": 0, "crashes": 0, "http_5xx": 0,
               "http_4xx": 0, "http_2xx": 0}

    print(f"[RHF] Starting {args.hours}h run against {args.target}...")
    while time.time() < end:
        method = random.choice(METHODS)
        path = random_path()
        body = random_body()
        headers = random_headers()
        status = send_request(args.target, method, path, body, headers)

        results["mutations_applied"] += 1
        if status == 0:
            results["crashes"] += 1
        elif status >= 500:
            results["http_5xx"] += 1
        elif status >= 400:
            results["http_4xx"] += 1
        else:
            results["http_2xx"] += 1

        if results["mutations_applied"] % 1000 == 0:
            elapsed = time.time() - start
            print(f"  [{elapsed/3600:.1f}h] {results['mutations_applied']} reqs, "
                  f"crashes={results['crashes']}, 5xx={results['http_5xx']}")

    results["duration_hours"] = args.hours
    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[RHF] Done. {args.output}")
    print(f"  Total: {results['mutations_applied']} requests")
    print(f"  Crashes: {results['crashes']}, 5xx: {results['http_5xx']}, "
          f"4xx: {results['http_4xx']}, 2xx: {results['http_2xx']}")


if __name__ == "__main__":
    main()
