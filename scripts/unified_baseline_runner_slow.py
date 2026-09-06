#!/usr/bin/env python3
"""Rate-limited variant for Open5GS — avoids overwhelming C-based targets."""
import argparse, json, os, random, socket, subprocess, sys, time
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
RESULTS = Path("/home/mm/桌面/5g-fuzzer/results/baselines")

TARGETS = {
    "open5gs": ("172.23.0.10", 7777, False),
}

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

def h2_request(host, port, method, path, body=None):
    try:
        cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
               "--max-time", "8", "--http2-prior-knowledge",
               "-X", method.decode(), f"http://{host}:{port}" + path.decode()]
        if body:
            cmd += ["-H", "Content-Type: application/json", "-d", body.decode()]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
        code = int(r.stdout.strip())
        return code if code > 0 else 0
    except:
        return 0

def mutate_bytes(data):
    if not data: return data
    d = bytearray(data)
    d[random.randint(0, len(d)-1)] = random.randint(0, 255)
    return bytes(d)

def mutate_json_values(body):
    if not body: return body
    try:
        obj = json.loads(body.decode())
        keys = list(obj.keys())
        if not keys: return body
        k = random.choice(keys)
        if isinstance(obj[k], str): obj[k] = random.choice(["", "A"*1000, "' OR 1=1--", "\x00"])
        elif isinstance(obj[k], int): obj[k] = random.choice([-1, 0, 2**31-1])
        elif isinstance(obj[k], bool): obj[k] = "not_a_bool"
        return json.dumps(obj).encode()
    except: return body

def mutate_json_keys(body):
    if not body: return body
    try:
        obj = json.loads(body.decode())
        keys = list(obj.keys())
        if not keys: return body
        k = random.choice(keys)
        lethal = random.choice(["\x00", "../", "\x01", "\xff", "__proto__"])
        new_key = k + lethal
        obj[new_key] = obj.pop(k)
        return json.dumps(obj).encode()
    except: return body

def run(name, target, hours, mutator):
    host, port, _ = TARGETS[target]
    results = {"baseline": name, "target": target, "requests": 0,
               "crashes": 0, "http_2xx": 0, "http_4xx": 0, "http_5xx": 0,
               "unique_codes": set()}
    end = time.time() + hours * 3600
    delay = 0.05  # 20 req/s — gentle enough for C-based target

    print(f"\n{'='*50}")
    print(f"[{name}] {target} — {hours}h (rate-limited, {1/delay:.0f} req/s)")
    print(f"{'='*50}")

    last_report = time.time()
    while time.time() < end:
        method, path, body = random.choice(SEEDS)
        mutated = mutator(body) if body else None
        code = h2_request(host, port, method, path, mutated)

        results["requests"] += 1
        if code == 0: results["crashes"] += 1
        elif code < 400: results["http_2xx"] += 1
        elif code < 500: results["http_4xx"] += 1
        else: results["http_5xx"] += 1
        results["unique_codes"].add(code)

        time.sleep(delay)

        if time.time() - last_report > 300:
            elapsed = (time.time() - results.get("started", time.time())) / 3600
            n = max(results["requests"], 1)
            print(f"  [{time.strftime('%H:%M')}] reqs={results['requests']} crashes={results['crashes']} "
                  f"5xx={results['http_5xx']} 5xx%={results['http_5xx']/n*100:.1f}% "
                  f"4xx={results['http_4xx']} 2xx={results['http_2xx']}")
            results["started"] = results.get("started", time.time())
            last_report = time.time()

    results["duration_h"] = hours
    results["unique_codes"] = sorted(list(results["unique_codes"]))
    fn = f"{RESULTS}/{target}/{name.lower()}_results.json"
    os.makedirs(os.path.dirname(fn), exist_ok=True)
    with open(fn, "w") as f: json.dump(results, f, indent=2, default=list)
    print(f"  DONE: {results['requests']} reqs, crashes={results['crashes']}")
    return results

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--hours", type=float, default=24)
    p.add_argument("--only", choices=["schemathesis","boofuzz","aflnet","stateafl","jksm"], required=True)
    args = p.parse_args()

    mutators = {
        "schemathesis": mutate_json_values, "boofuzz": mutate_bytes,
        "aflnet": mutate_bytes, "stateafl": mutate_bytes, "jksm": mutate_json_keys
    }

    os.makedirs(f"{RESULTS}/open5gs", exist_ok=True)
    run(args.only, "open5gs", args.hours, mutators[args.only])

if __name__ == "__main__":
    main()
