#!/usr/bin/env python3
"""全组件差分审计：对三个 5GC 实现的每个共同 NF，对每个 SBI 操作，
发送相同的（变异后）请求，记录三向响应差异。

用途：找到语义违规（2xx vs 4xx）和协议违规（违反 3GPP 规范的行为）。

用法：
    python3 scripts/full_differential_audit.py
"""
import json
import random
import subprocess
import sys
import uuid
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import http.client as hc

# ── 三个实现每个 NF 的 (host, port) ────────────────────────
# 从 TARGETS 提取（与 experiment_v2_launcher 一致）
IMPL_NF = {
    "free5gc": {
        "nrf": ("172.24.0.10", 8000), "amf": ("172.24.0.20", 8000),
        "smf": ("172.24.0.30", 8000), "ausf": ("172.24.0.50", 8000),
        "udm": ("172.24.0.60", 8000), "udr": ("172.24.0.70", 8000),
        "pcf": ("172.24.0.80", 8000), "nssf": ("172.24.0.90", 8000),
    },
    "oai": {
        "nrf": ("172.25.0.10", 80), "amf": ("172.25.0.20", 80),
        "ausf": ("172.25.0.50", 80), "smf": ("172.25.0.30", 80),
        "udm": ("172.25.0.60", 80), "udr": ("172.25.0.70", 80),
        "nssf": ("172.25.0.90", 80), "pcf": ("172.25.0.100", 80),
    },
    "open5gs": {
        "nrf": ("172.23.0.10", 7777), "amf": ("172.23.0.20", 7777),
        "smf": ("172.23.0.30", 7777), "ausf": ("172.23.0.50", 7777),
        "udm": ("172.23.0.60", 7777), "udr": ("172.23.0.70", 7777),
        "nssf": ("172.23.0.90", 7777), "bsf": ("172.23.0.100", 7777),
        "scp": ("172.23.0.110", 7777),
    },
}

PROTO = {"free5gc": "http1.1", "oai": "http1.1", "open5gs": "http2"}

# ── 每个 NF 的操作模板（三个实现的并集，key=op 名）────────
NF_OPS = {
    "nrf": [
        {"method": "PUT", "path": "/nnrf-nfm/v1/nf-instances/{id}", "op": "NFRegister",
         "body": {"nfInstanceId": "{id}", "nfType": "AMF", "nfStatus": "REGISTERED",
                  "heartBeatTimer": 10, "ipv4Addresses": ["172.23.0.1"]}},
        {"method": "PATCH", "path": "/nnrf-nfm/v1/nf-instances/{id}", "op": "NFUpdate",
         "body": {"nfStatus": "REGISTERED", "heartBeatTimer": 20}},
        {"method": "GET", "path": "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=AMF",
         "op": "NFDiscover", "body": None},
        {"method": "GET", "path": "/nnrf-nfm/v1/nf-instances", "op": "NFList", "body": None},
    ],
    "amf": [
        {"method": "PUT", "path": "/namf-comm/v1/ue-contexts/{id}", "op": "UEContextCreate",
         "body": {"supi": "imsi-901700000000001", "guti": "test-guti",
                  "ranUeNgapId": 1, "amfUeNgapId": 1}},
        {"method": "POST", "path": "/namf-comm/v1/ue-contexts/{id}/n1-n2-messages", "op": "N1N2Message",
         "body": {"n1MessageContainer": {"n1MessageClass": "5GMM",
                  "n1MessageContent": {"contentId": "msg-1"}}}},
    ],
    "smf": [
        {"method": "POST", "path": "/nsmf-pdusession/v1/sm-contexts", "op": "PDUSessionCreate",
         "body": {"supi": "imsi-901700000000001", "dnn": "internet", "sNssai": {"sst": 1}}},
    ],
    "ausf": [
        {"method": "POST", "path": "/nausf-auth/v1/ue-authentications", "op": "UEAuthenticate",
         "body": {"supiOrSuci": "imsi-901700000000001",
                  "servingNetworkName": "5G:mnc001.mcc001.3gppnetwork.org"}},
    ],
    "udm": [
        {"method": "GET", "path": "/nudm-sdm/v2/imsi-901700000000001/am-data", "op": "SDMGetAmData", "body": None},
        {"method": "GET", "path": "/nudm-sdm/v2/imsi-901700000000001/sm-data", "op": "SDMGetSmData", "body": None},
    ],
    "udr": [
        {"method": "GET", "path": "/nudr-dr/v1/subscription-data/imsi-901700000000001/authentication-data/authentication-subscription",
         "op": "UDRGetAuth", "body": None},
        {"method": "GET", "path": "/nudr-dr/v1/subscription-data/imsi-901700000000001/provisioned-data/am-data",
         "op": "UDRGetAM", "body": None},
    ],
    "nssf": [
        {"method": "GET", "path": "/nnssf-nsselection/v1/network-slice-information?nf-type=AMF",
         "op": "SliceSelect", "body": None},
    ],
    "pcf": [
        {"method": "POST", "path": "/npcf-am-policy-control/v1/policies", "op": "AMPolicyCreate",
         "body": {"supi": "imsi-901700000000001", "notificationUri": "http://172.23.0.1:8080/callback"}},
    ],
    "bsf": [
        {"method": "GET", "path": "/nbsf-management/v1/pcfBindings", "op": "BSFListBindings", "body": None},
    ],
    "scp": [
        {"method": "GET", "path": "/nnrf-disc/v1/nf-instances?target-nf-type=AMF", "op": "SCPDiscover", "body": None},
    ],
}

# ── 变异策略 ────────────────────────────────────────────────
def apply_mutation(body: dict, strat: str) -> dict:
    """返回变异后的 body（深拷贝）。"""
    import copy
    obj = copy.deepcopy(body)
    if obj is None:
        return obj
    keys = list(obj.keys())
    if not keys:
        return obj
    k = random.choice(keys)
    v = obj[k]
    if strat == "missing_required":
        if len(keys) > 1:
            del obj[k]
    elif strat == "type_confusion":
        if isinstance(v, str):
            obj[k] = 0
        elif isinstance(v, (int, float)):
            obj[k] = "not_an_int"
    elif strat == "null_required":
        obj[k] = None
    elif strat == "empty_values":
        if isinstance(v, str):
            obj[k] = ""
        elif isinstance(v, list):
            obj[k] = []
        elif isinstance(v, dict):
            obj[k] = {}
    elif strat == "nul_value":  # 值空间 NUL 注入
        if isinstance(v, str):
            obj[k] = v + "\x00"
    elif strat == "nul_key":  # 键空间 NUL 注入
        if isinstance(v, (str, int, float, list, dict)):
            new_key = k + "\x00"
            if new_key not in obj:
                obj[new_key] = obj.pop(k)
    return obj


# ── 发送逻辑 ────────────────────────────────────────────────
def send(impl: str, host: int, port: int, method: str, path: str, body) -> int:
    proto = PROTO[impl]
    body_bytes = json.dumps(body).encode() if body is not None else None
    if proto == "http2":
        url = f"http://{host}:{port}{path}"
        cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
               "--max-time", "8", "--http2-prior-knowledge", "-X", method, url]
        if body_bytes:
            cmd += ["-H", "Content-Type: application/json", "-d", body_bytes.decode(errors="replace")]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
            c = r.stdout.strip()
            return int(c) if c.isdigit() and int(c) > 0 else 0
        except Exception:
            return 0
    else:
        try:
            conn = hc.HTTPConnection(host, port, timeout=10)
            headers = {"Content-Type": "application/json"} if body_bytes else {}
            conn.request(method, path, body=body_bytes, headers=headers)
            resp = conn.getresponse()
            resp.read()
            conn.close()
            return resp.status
        except Exception:
            return 0


def classify(f, o, p):
    """三向分类。"""
    statuses = [f, o, p]
    unique = set(statuses)
    if len(unique) <= 1:
        return "uniform"
    has_crash = 0 in unique
    has_alive = any(s > 0 for s in statuses)
    if has_crash and has_alive:
        return "crash_vs_alive"
    has_2xx = any(200 <= s < 300 for s in statuses)
    has_4xx = any(400 <= s < 500 for s in statuses)
    has_5xx = any(s >= 500 for s in statuses)
    if has_2xx and has_4xx:
        return "validation_diff"
    if has_2xx and has_5xx:
        return "success_vs_failure"
    if len({s // 100 for s in statuses}) >= 3:
        return "all_different"
    return "status_mismatch"


def main():
    random.seed(42)
    results = []
    nid = str(uuid.uuid4())  # 用 UUID 避免 nfInstanceId 格式差异干扰

    for nf, ops in NF_OPS.items():
        for tmpl in ops:
            op = tmpl["op"]
            method = tmpl["method"]
            path_t = tmpl["path"].replace("{id}", nid)
            base_body = tmpl["body"]

            # 1) 基线（无变异）
            bodies = [("baseline", base_body)]
            # 2) 关键变异
            for strat in ["missing_required", "type_confusion", "null_required",
                          "empty_values", "nul_value", "nul_key"]:
                if base_body is not None:
                    bodies.append((strat, apply_mutation(base_body, strat)))

            for strat, body in bodies:
                f = send("free5gc", *IMPL_NF["free5gc"].get(nf, (None, None)), method, path_t, body) if nf in IMPL_NF["free5gc"] else None
                o = send("oai", *IMPL_NF["oai"].get(nf, (None, None)), method, path_t, body) if nf in IMPL_NF["oai"] else None
                p = send("open5gs", *IMPL_NF["open5gs"].get(nf, (None, None)), method, path_t, body) if nf in IMPL_NF["open5gs"] else None

                if f is None or o is None or p is None:
                    continue
                cls = classify(f, o, p)
                results.append({"nf": nf, "op": op, "strat": strat,
                                "free5gc": f, "oai": o, "open5gs": p, "class": cls})

    # 输出
    print(f"共 {len(results)} 条 (NF×操作×变异) 三向记录\n")

    # 按 class 分组
    by_class = defaultdict(list)
    for r in results:
        by_class[r["class"]].append(r)
    for cls in ["validation_diff", "success_vs_failure", "crash_vs_alive",
                "all_different", "status_mismatch", "uniform"]:
        if by_class[cls]:
            print(f"{cls}: {len(by_class[cls])} 条")

    # 详细列出所有非 uniform 的差异
    print("\n" + "=" * 80)
    print("所有三向差异明细（非 uniform）")
    print("=" * 80)
    for r in results:
        if r["class"] != "uniform":
            print(f"[{r['class']:20s}] {r['nf']:6s} {r['op']:16s} {r['strat']:16s} "
                  f"free5gc={r['free5gc']:4d} oai={r['oai']:4d} open5gs={r['open5gs']:4d}")

    # 保存
    out = {"results": results}
    Path("/tmp/full_differential_audit.json").write_text(json.dumps(out, indent=2))
    print("\n保存到 /tmp/full_differential_audit.json")


if __name__ == "__main__":
    main()
