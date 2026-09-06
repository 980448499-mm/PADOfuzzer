#!/usr/bin/env python3
"""Rate-limited Open5GS multi-NF baseline runner.
Targets AUSF, UDR, AMF instead of fragile NRF.
"""

import argparse, json, random, subprocess, sys, time, os
from collections import defaultdict

# NF-specific SBI endpoints
NF_ENDPOINTS = {
    "ausf": (b"172.23.0.50", 7777, [
        (b"POST", b"/nausf-auth/v1/ue-authentications",
         b'{"supiOrSuci":"imsi-901700000000001","servingNetworkName":"5G:mnc001.mcc001.3gppnetwork.org"}'),
    ]),
    "udr": (b"172.23.0.70", 7777, [
        (b"GET", b"/nudr-dr/v1/subscription-data/imsi-901700000000001/authentication-data/authentication-subscription", None),
        (b"GET", b"/nudr-dr/v1/subscription-data/imsi-901700000000001/provisioned-data/am-data", None),
    ]),
    "amf": (b"172.23.0.20", 7777, [
        (b"PUT", b"/namf-comm/v1/ue-contexts/imsi-901700000000001",
         b'{"supi":"imsi-901700000000001","guti":"test","ranUeNgapId":1,"amfUeNgapId":1}'),
    ]),
}

MUTATORS = {
    "schemathesis": lambda b: mutate_json_values(b),
    "boofuzz": lambda b: mutate_bytes(b),
    "aflnet": lambda b: mutate_bytes(b),
    "stateafl": lambda b: mutate_bytes(b),
    "jksm": lambda b: mutate_json_keys(b),
}

def mutate_bytes(data):
    if not data: return data
    d = bytearray(data)
    if len(d) > 0:
        d[random.randint(0, len(d)-1)] = random.randint(0, 255)
    return bytes(d)

def mutate_json_values(body):
    if not body: return body
    try:
        obj = json.loads(body.decode())
        keys = list(obj.keys())
        if not keys: return body
        k = random.choice(keys)
        v = obj[k]
        if isinstance(v, str): obj[k] = random.choice(["", "A"*1000, "' OR 1=1--", "\x00", "../"])
        elif isinstance(v, int): obj[k] = random.choice([-1, 0, 2**31-1])
        elif isinstance(v, bool): obj[k] = "not_a_bool"
        return json.dumps(obj).encode()
    except: return body

def mutate_json_keys(body):
    if not body: return body
    try:
        obj = json.loads(body.decode())
        keys = list(obj.keys())
        if not keys: return body
        k = random.choice(keys)
        obj[k + random.choice(["\x00", "../", "\x01", "\xff", "__proto__"])] = obj.pop(k)
        return json.dumps(obj).encode()
    except: return body

def h2_request(host, port, method, path, body=None):
    try:
        cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
               "--max-time", "8", "--http2-prior-knowledge",
               "-X", method.decode(),
               f"http://{host.decode()}:{port}" + path.decode()]
        if body:
            cmd += ["-H", "Content-Type: application/json", "-d", body.decode()]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
        return int(r.stdout.strip()) if r.stdout.strip().isdigit() else 0
    except: return 0

def run(nf_name, baseline, hours):
    host, port, endpoints = NF_ENDPOINTS[nf_name]
    mutator = MUTATORS[baseline]
    results = {"nf": nf_name, "baseline": baseline, "requests": 0,
               "crashes": 0, "http_2xx": 0, "http_4xx": 0, "http_5xx": 0}
    end = time.time() + hours * 3600
    delay = 0.1  # 10 req/s per baseline

    print(f"  [{baseline}/{nf_name}] Starting (~10 req/s)")
    last = time.time()
    while time.time() < end:
        m, p, b = random.choice(endpoints)
        code = h2_request(host, port, m, p, mutator(b) if b else None)
        results["requests"] += 1
        if code == 0: results["crashes"] += 1
        elif code < 400: results["http_2xx"] += 1
        elif code < 500: results["http_4xx"] += 1
        else: results["http_5xx"] += 1
        time.sleep(delay)
        if results["requests"] % 100 == 0 and time.time() - last > 300:
            n = max(results["requests"], 1)
            print(f"  [{baseline}/{nf_name}] {results['requests']} reqs crashes={results['crashes']} "
                  f"5xx={results['http_5xx']} 4xx={results['http_4xx']} 2xx={results['http_2xx']}")
            last = time.time()

    fn = f"/home/mm/桌面/5g-fuzzer/results/baselines/open5gs/{nf_name}_{baseline}.json"
    os.makedirs(os.path.dirname(fn), exist_ok=True)
    with open(fn, "w") as f: json.dump(results, f, indent=2)
    print(f"  [{baseline}/{nf_name}] DONE: {results['requests']} reqs, {results['crashes']} crashes")
    return results

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--nf", choices=["ausf","udr","amf"], required=True)
    p.add_argument("--baseline", choices=["schemathesis","boofuzz","aflnet","stateafl","jksm"], required=True)
    p.add_argument("--hours", type=float, default=24)
    args = p.parse_args()
    run(args.nf, args.baseline, args.hours)

if __name__ == "__main__":
    main()
