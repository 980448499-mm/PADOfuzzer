#!/usr/bin/env python3
"""24 小时持续三向差分 fuzzing：对指定 NF，持续变异并记录三个实现的响应差异。

用法：
    python3 scripts/long_run_differential.py --nf nrf --hours 24
"""
import argparse
import json
import random
import sys
import time
import uuid
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from experiment_v2_launcher import (
    TARGETS, ALL_MUTATIONS, apply_mutation, http11_request, h2_request,
)
from full_differential_audit import NF_OPS, classify


def impl_addr(impl: str, nf: str):
    key = f"{impl}-{nf}"
    if key in TARGETS:
        t = TARGETS[key]
        return t["host"], t["port"], t["proto"]
    return None


def send_to(impl: str, addr, method: str, path: str, body):
    if addr is None:
        return None
    host, port, proto = addr
    if proto == "http2":
        return h2_request(host, port, method, path, body)
    return http11_request(host, port, method, path, body)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--nf", required=True)
    parser.add_argument("--hours", type=float, default=24)
    args = parser.parse_args()

    nf = args.nf
    if nf not in NF_OPS:
        print(f"未知 NF: {nf}，可用: {list(NF_OPS.keys())}")
        sys.exit(1)

    random.seed()
    nid = str(uuid.uuid4())
    ops = NF_OPS[nf]

    f5gc_addr = impl_addr("free5gc", nf)
    oai_addr = impl_addr("oai", nf)
    o5gs_addr = impl_addr("open5gs", nf)

    # 只对三个实现都存在的 NF 做三向
    if f5gc_addr is None or oai_addr is None or o5gs_addr is None:
        print(f"{nf}: 三个实现不全（free5gc={f5gc_addr}, oai={oai_addr}, open5gs={o5gs_addr}），跳过")
        sys.exit(0)

    counter = Counter()
    samples = []
    total = 0
    divergent = 0

    start = time.time()
    end = start + args.hours * 3600
    out_dir = Path("/home/mm/桌面/5g-fuzzer/results/long_run_diff")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_fn = out_dir / f"{nf}_24h.json"

    print(f"[{nf}] 启动 24h 三向差分 fuzzing：free5gc={f5gc_addr[:2]}, oai={oai_addr[:2]}, open5gs={o5gs_addr[:2]}")
    print(f"[{nf}] 输出: {out_fn}", flush=True)

    last_report = start
    while time.time() < end:
        tmpl = random.choice(ops)
        method = tmpl["method"]
        path = tmpl["path"].replace("{id}", nid)
        body_dict = tmpl["body"]

        body = None
        if body_dict is not None:
            body_str = json.dumps(body_dict).replace("{id}", nid)
            body = apply_mutation(body_str.encode(), random.choice(ALL_MUTATIONS))

        f = send_to("free5gc", f5gc_addr, method, path, body)
        o = send_to("oai", oai_addr, method, path, body)
        p = send_to("open5gs", o5gs_addr, method, path, body)

        total += 1
        cls = classify(f, o, p)
        if cls != "uniform":
            divergent += 1
            key = f"{tmpl['op']}|{f}|{o}|{p}|{cls}"
            counter[key] += 1
            if len(samples) < 200:
                samples.append({"op": tmpl["op"], "free5gc": f, "oai": o, "open5gs": p, "class": cls})

        if time.time() - last_report > 300:  # 每 5 分钟报告一次
            elapsed = (time.time() - start) / 3600
            rate = divergent / max(total, 1) * 100
            print(f"  [{elapsed:.1f}h] {total} reqs, {divergent} divergences ({rate:.1f}%), "
                  f"{len(counter)} unique combos", flush=True)
            last_report = time.time()

    # 保存
    out = {
        "nf": nf, "hours": args.hours, "total_requests": total,
        "divergences": divergent, "divergence_rate": round(divergent / max(total, 1) * 100, 1),
        "unique_combos": len(counter),
        "counter": dict(counter),
        "samples": samples,
        "started": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(start)),
        "completed": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
    }
    out_fn.write_text(json.dumps(out, indent=2))
    print(f"[{nf}] 完成: {total} reqs, {divergent} divergences -> {out_fn}")


if __name__ == "__main__":
    main()
