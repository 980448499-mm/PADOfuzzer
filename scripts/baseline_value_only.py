#!/usr/bin/env python3
"""Baseline 1: Value-Only Mutation Fuzzer (VOMF).

Same 12 SBI templates as our fuzzer, but ONLY value-space mutations.
Never mutates JSON key names. Used to isolate JKSM's contribution.

Usage: python3 baseline_value_only.py --target free5gc --hours 2
"""
import argparse, json, random, sys, time
from pathlib import Path
import http.client

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# 12 SBI templates (same as live fuzzer)
SBI_TEMPLATES = [
    {"method": "PUT", "path": "/nnrf-nfm/v1/nf-instances/{nfInstanceId}",
     "body": {"nfInstanceId": "TEMPLATE", "nfType": "AMF", "nfStatus": "REGISTERED",
              "heartBeatTimer": 10, "ipv4Addresses": ["172.23.0.1"]}, "op": "NFRegister"},
    {"method": "PATCH", "path": "/nnrf-nfm/v1/nf-instances/{nfInstanceId}",
     "body": {"nfStatus": "REGISTERED", "heartBeatTimer": 20}, "op": "NFUpdate"},
    {"method": "DELETE", "path": "/nnrf-nfm/v1/nf-instances/{nfInstanceId}",
     "body": {}, "op": "NFDeregister"},
    {"method": "GET", "path": "/nnrf-disc/v1/nf-instances?target-nf-type=AMF",
     "body": None, "op": "NFDiscover"},
    {"method": "POST", "path": "/nnrf-nfm/v1/nf-instances/{nfInstanceId}/access-token",
     "body": {"grant_type": "client_credentials", "nfInstanceId": "TEMPLATE",
              "scope": "nnrf-nfm"}, "op": "NFAccessToken"},
    {"method": "GET", "path": "/nnrf-nfm/v1/nf-instances/{nfInstanceId}",
     "body": None, "op": "NFProfile"},
    {"method": "GET", "path": "/nnrf-nfm/v1/nf-instances",
     "body": None, "op": "NFList"},
    {"method": "POST", "path": "/nnrf-nfm/v1/subscriptions",
     "body": {"nfInstanceId": "TEMPLATE", "subscriptionId": "sub-1",
              "notificationUri": "http://172.23.0.1:8080/notify"}, "op": "NFSubscribe"},
    {"method": "POST", "path": "/nausf-auth/v1/ue-authentications",
     "body": {"supiOrSuci": "imsi-901700000000001",
              "servingNetworkName": "5G:mnc001.mcc001.3gppnetwork.org"}, "op": "UEAuthenticate"},
    {"method": "POST", "path": "/namf-comm/v1/ue-contexts/{ueCtxId}/n1-n2-messages",
     "body": {"n1MessageContainer": {"n1MessageClass": "5GMM",
              "n1MessageContent": {"contentId": "msg-1"}}}, "op": "N1N2MessageTransfer"},
    {"method": "GET", "path": "/nudm-sdm/v1/imsi-901700000000001/am-data",
     "body": None, "op": "SDMGetAmData"},
    {"method": "GET", "path": "/nudr-dr/v1/subscription-data/imsi-901700000000001",
     "body": None, "op": "UDRQuery"},
]

# 10 value-space-only mutation strategies (NO key mutations)
VALUE_MUTATIONS = [
    "type_confusion",     # int→string, string→int
    "boundary_ints",      # MAX_INT, MIN_INT, -1
    "null_required",      # set required field to null
    "empty_values",       # "" for string fields
    "oversized",          # 10K-length strings
    "extra_fields",       # add random extra JSON fields
    "sql_injection",      # '; DROP TABLE in values
    "special_chars",      # \\x00\\xff in values (NOT keys)
    "path_traversal_uri", # ../../../etc in URL values
    "grammar_aware",      # swap field order, duplicate fields
]

TARGETS = {
    "free5gc": ("172.24.0.10", 8000),
    "oai": ("172.25.0.10", 80),
    "open5gs": ("172.23.0.50", 7777),
}

C_LEthal = ["\x00", "../", "\x01", "\xff", "__proto__"]  # JKSM chars — NOT used here


def mutate_value_only(body: dict) -> dict:
    """Apply a value-space-only mutation. Key names are NEVER modified."""
    if not body:
        return body
    b = json.loads(json.dumps(body))  # deep copy

    strategy = random.choice(VALUE_MUTATIONS)
    keys = list(b.keys())

    if strategy == "type_confusion" and keys:
        k = random.choice(keys)
        if isinstance(b[k], int):
            b[k] = "not_an_integer"
        elif isinstance(b[k], str):
            b[k] = 99999
        elif isinstance(b[k], list):
            b[k] = "not_a_list"

    elif strategy == "boundary_ints" and keys:
        for k in keys:
            if isinstance(b[k], int):
                b[k] = random.choice([-1, 0, 2**31-1, -2**31])

    elif strategy == "null_required" and keys:
        b[random.choice(keys)] = None

    elif strategy == "empty_values" and keys:
        k = random.choice(keys)
        if isinstance(b[k], str):
            b[k] = ""

    elif strategy == "oversized" and keys:
        k = random.choice(keys)
        b[k] = "A" * 10000

    elif strategy == "extra_fields":
        b[f"__extra_field_{random.randint(0,9999)}"] = random.choice(
            ["test", 0, None, {"nested": "data"}, [1, 2, 3]])

    elif strategy == "sql_injection" and keys:
        k = random.choice(keys)
        if isinstance(b[k], str):
            b[k] = random.choice([
                "'; DROP TABLE nf_instances; --",
                "1' OR '1'='1",
                "' UNION SELECT * FROM users--",
            ])

    elif strategy == "special_chars" and keys:
        k = random.choice(keys)
        if isinstance(b[k], str):
            chars = ["\x00", "\xff", "\r\n", "%00", "{{", "}}"]
            b[k] = b[k][:len(b[k])//2] + random.choice(chars)

    elif strategy == "path_traversal_uri" and keys:
        k = random.choice(keys)
        if isinstance(b[k], str):
            b[k] = "../../../etc/passwd%00"

    elif strategy == "grammar_aware" and len(keys) >= 2:
        # Swap field ordering
        items = list(b.items())
        random.shuffle(items)
        return dict(items)

    return b


def send_request(target: str, method: str, path: str, body: dict):
    """Send HTTP request."""
    host, port = TARGETS[target]
    body_bytes = json.dumps(body).encode() if body else None
    headers = {"Content-Type": "application/json"} if body else {}

    try:
        conn = http.client.HTTPConnection(host, port, timeout=10)
        conn.request(method, path, body=body_bytes, headers=headers)
        resp = conn.getresponse()
        status = resp.status
        resp.read()
        conn.close()
        return status
    except Exception as e:
        return 0  # Crash/timeout/refused


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", choices=["free5gc", "oai", "open5gs"], required=True)
    parser.add_argument("--hours", type=float, default=2)
    parser.add_argument("--output", type=str, default=None)
    args = parser.parse_args()
    args.output = args.output or f"baseline_vomf_{args.target}.json"

    start = time.time()
    end = start + args.hours * 3600
    results = {"target": args.target, "baseline": "Value-Only Mutation Fuzzer",
               "mutations_applied": 0, "crashes": 0, "http_5xx": 0,
               "http_4xx": 0, "http_2xx": 0, "5xx_by_strategy": {}}

    print(f"[VOMF] Starting {args.hours}h run against {args.target}...")
    while time.time() < end:
        tmpl = random.choice(SBI_TEMPLATES)
        body = mutate_value_only(tmpl["body"])
        status = send_request(args.target, tmpl["method"], tmpl["path"], body)

        results["mutations_applied"] += 1
        if status == 0:
            results["crashes"] += 1
        elif status >= 500:
            results["http_5xx"] += 1
        elif status >= 400:
            results["http_4xx"] += 1
        else:
            results["http_2xx"] += 1

        if results["mutations_applied"] % 500 == 0:
            elapsed = time.time() - start
            print(f"  [{elapsed/3600:.1f}h] {results['mutations_applied']} reqs, "
                  f"crashes={results['crashes']}, 5xx={results['http_5xx']}")

    results["duration_hours"] = args.hours
    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[VOMF] Done. Results saved to {args.output}")
    print(f"  Total: {results['mutations_applied']} requests")
    print(f"  Crashes: {results['crashes']}")
    print(f"  5xx: {results['http_5xx']}, 4xx: {results['http_4xx']}, 2xx: {results['http_2xx']}")


if __name__ == "__main__":
    main()
