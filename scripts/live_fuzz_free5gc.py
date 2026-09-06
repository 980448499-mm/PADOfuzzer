#!/usr/bin/env python3
"""free5GC Fuzzer v2 — inherits BaseFuzzer with FSM guidance.

Usage:
  python scripts/live_fuzz_free5gc.py --hours 5
  python scripts/live_fuzz_free5gc.py --hours 5 --no-fsm  # ablation
  python scripts/live_fuzz_free5gc.py --hours 5 --no-cross-protocol  # ablation
"""

import argparse, asyncio, json, logging, random, sys, time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.fuzzing_engine.live_fuzzer_base import BaseFuzzer, check_container_health

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("live_fuzz_free5gc")

NF_ENDPOINTS = {
    "NRF": ("172.24.0.10", 8000), "AMF": ("172.24.0.20", 8000),
    "SMF": ("172.24.0.30", 8000), "AUSF": ("172.24.0.50", 8000),
    "UDM": ("172.24.0.60", 8000), "UDR": ("172.24.0.70", 8000),
    "PCF": ("172.24.0.80", 8000), "NSSF": ("172.24.0.90", 8000),
}
MONITOR_CONTAINERS = [
    "fuzzing-free5gc-nrf", "fuzzing-free5gc-amf", "fuzzing-free5gc-smf",
    "fuzzing-free5gc-ausf", "fuzzing-free5gc-udm", "fuzzing-free5gc-udr",
    "fuzzing-free5gc-pcf", "fuzzing-free5gc-nssf",
]

SBI_TEMPLATES = {
    "NFRegister": {
        "method": "PUT", "path_template": "/nnrf-nfm/v1/nf-instances/{nfInstanceId}",
        "body": {"nfInstanceId": "AMF-instance-001", "nfType": "AMF", "nfStatus": "REGISTERED",
                 "ipv4Addresses": ["172.24.0.20"], "fqdn": "amf.free5gc.local",
                 "priority": 1, "capacity": 100, "load": 0,
                 "nfServices": [{"serviceInstanceId": "namf-comm-001", "serviceName": "namf-comm",
                                 "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                                 "scheme": "http", "nfServiceStatus": "REGISTERED",
                                 "ipEndPoints": [{"ipv4Address": "172.24.0.20", "port": 8000}]}]}},
    "NFUpdate": {"method": "PATCH", "path_template": "/nnrf-nfm/v1/nf-instances/{nfInstanceId}",
                 "body": {"nfStatus": "REGISTERED", "load": 50, "capacity": 200}},
    "NFDeregister": {"method": "DELETE", "path_template": "/nnrf-nfm/v1/nf-instances/{nfInstanceId}", "body": {}},
    "NFDiscover": {"method": "GET", "path_template": "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=SMF", "body": None},
    "NFAccessToken": {"method": "POST", "path_template": "/nnrf-nfm/v1/oauth2/token",
                      "body": {"grant_type": "client_credentials", "nfInstanceId": "AMF-instance-001", "scope": "namf-comm"}},
    "N1N2MessageTransfer": {"method": "POST", "path_template": "/namf-comm/v1/ue-contexts/test-ue-001/n1-n2-messages",
                            "body": {"n1MessageContainer": {"n1MessageClass": "5GMM", "n1MessageContent": {"contentId": "nas-msg-001"}},
                                     "n2InfoContainer": {"n2InformationClass": "NR"}}},
    "PDUSessionCreate": {"method": "POST", "path_template": "/nsmf-pdusession/v1/pdu-sessions/1/modify",
                         "body": {"supi": "imsi-208930000000031", "dnn": "internet",
                                  "sNssai": {"sst": 1, "sd": "010203"}, "pduSessionId": 1,
                                  "pduSessionType": "IPV4", "sscMode": "SSC_MODE_1"}},
    "UEAuthenticate": {"method": "POST", "path_template": "/nausf-auth/v1/ue-authentications",
                       "body": {"supiOrSuci": "imsi-208930000000031",
                                "servingNetworkName": "5G:mnc093.mcc208.3gppnetwork.org", "authType": "5G_AKA"}},
    "NFProfile": {"method": "GET", "path_template": "/nnrf-nfm/v1/nf-instances/{nfInstanceId}", "body": None},
    "NFList": {"method": "GET", "path_template": "/nnrf-nfm/v1/nf-instances", "body": None},
    "NFSubscribe": {"method": "POST", "path_template": "/nnrf-nfm/v1/subscriptions",
                    "body": {"nfStatusNotifyUri": "http://127.0.0.1:8080/callback",
                             "reqNotifEvents": ["NF_REGISTERED"], "validityTime": "3600"}},
    "NFUnsubscribe": {"method": "DELETE", "path_template": "/nnrf-nfm/v1/subscriptions/{nfInstanceId}", "body": None},
}

_nf_counter: Dict[str, int] = defaultdict(int)
def get_instance_id(nf_type: str) -> str:
    _nf_counter[nf_type] += 1; return f"{nf_type}-fuzz-{_nf_counter[nf_type]:04d}"

class SBIMutator:
    @staticmethod
    def _deep_copy(obj: Any) -> Any: return json.loads(json.dumps(obj))
    def type_confusion(self, body: Dict) -> Dict:
        m = self._deep_copy(body)
        for k in list(m.keys()):
            v = m[k]
            if isinstance(v, bool): m[k] = "TRUE"
            elif isinstance(v, int): m[k] = str(v)
            elif isinstance(v, str) and v: m[k] = 99999
            elif isinstance(v, list): m[k] = "not_a_list"
            elif isinstance(v, dict): m[k] = ["corrupted"]
        return m
    def boundary_ints(self, body: Dict) -> Dict:
        m = self._deep_copy(body)
        ex = [-1, 0, 1, 255, 256, 32767, 32768, 65535, 65536, 2**31-1, 2**31, -2**31, 2**32-1, 2**63-1]
        for k, v in m.items():
            if isinstance(v, int): m[k] = random.choice(ex)
            elif isinstance(v, dict): m[k] = self.boundary_ints(v)
        return m
    def null_required(self, body: Dict) -> Dict:
        m = self._deep_copy(body)
        if m: m[list(m.keys())[0]] = None
        return m
    def empty_values(self, body: Dict) -> Dict:
        m = self._deep_copy(body)
        for k, v in m.items():
            if isinstance(v, str): m[k] = ""
            elif isinstance(v, list): m[k] = []
            elif isinstance(v, dict): m[k] = {}
        return m
    def oversized(self, body: Dict) -> Dict:
        m = self._deep_copy(body)
        for k, v in m.items():
            if isinstance(v, str): m[k] = "A" * 100000
            elif isinstance(v, list): m[k] = [999] * 5000
        return m
    def extra_fields(self, body: Dict) -> Dict:
        m = self._deep_copy(body)
        m[f"\x00null_byte_{random.randint(0, 999)}"] = "injected"
        m[f"../../../etc/passwd"] = "path_traversal"
        m[f"__proto__admin"] = True
        return m
    def sql_injection(self, body: Dict) -> Dict:
        m = self._deep_copy(body)
        pl = ["' OR '1'='1", "'; DROP TABLE subscribers; --", "1' UNION SELECT * FROM users--"]
        for k in list(m.keys()):
            if isinstance(m[k], str): m[k] = random.choice(pl)
        return m
    def special_chars(self, body: Dict) -> Dict:
        m = self._deep_copy(body)
        ch = ["\x00", "\x01", "\xff", "\xfe", "\r\n\r\n", "\t", "\b", "\\u0000", "{{", "}}", "${}"]
        for k in list(m.keys()):
            if isinstance(m[k], str): m[k] += random.choice(ch) * 10
        return m
    def path_traversal_uri(self, path: str) -> str:
        return random.choice([
            path.replace("v1", "v0"), path.replace("v1", ""),
            path + "/../../../etc/passwd", path + "?limit=-1",
            path + "%00.html", path.replace("/", "//"), "/" * 1000 + path,
        ])


class Free5GCFuzzer(BaseFuzzer):
    """free5GC fuzzer with FSM guidance + cross-protocol mutation."""

    def __init__(self, hours=0.5, output_dir=Path("./results"),
                 fsm_guidance=True, cross_protocol=True,
                 concurrency=5, no_novel=False, multi_nf=False):
        super().__init__("free5GC v3.4.x", hours, output_dir, fsm_guidance,
                         cross_protocol=cross_protocol,
                         concurrency=concurrency,
                         no_novel=no_novel)
        self.multi_nf = multi_nf
        self.mutator = SBIMutator()
        self._mutations = ["type_confusion", "boundary_ints", "null_required",
                           "empty_values", "oversized", "extra_fields",
                           "sql_injection", "special_chars", "path_traversal_uri",
                           "grammar_aware", "seed_replay"]
        if cross_protocol:
            self._mutations.append("cross_protocol")
            from src.fuzzing_engine.cross_protocol import CrossProtocolMutator
            self._cross_mutator = CrossProtocolMutator(enabled=True)
        self._coverage_collector = "go_cover"
        self._go_cover_containers = [
            "fuzzing-free5gc-nrf",
            "fuzzing-free5gc-amf",
            "fuzzing-free5gc-smf",
            "fuzzing-free5gc-ausf",
        ]

    @property
    def operations(self) -> List[str]: return list(SBI_TEMPLATES.keys())
    @property
    def mutations(self) -> List[str]: return self._mutations
    @property
    def monitor_containers(self) -> List[str]: return MONITOR_CONTAINERS

    def build_request(self, op_name, mutation):
        t = SBI_TEMPLATES[op_name]
        method, body = t["method"], t["body"]
        path = t["path_template"]
        if "{nfInstanceId}" in path:
            path = path.replace("{nfInstanceId}", get_instance_id(random.choice(
                ["AMF", "SMF", "UPF", "NRF", "UDM", "AUSF", "PCF", "NSSF"])))
        if mutation == "cross_protocol" and body and self._cross_mutator:
            result = self._cross_mutator.mutate(body, path)
            if result: body, path, _meta = result
        elif body and mutation != "path_traversal_uri":
            fn = getattr(self.mutator, mutation, None)
            if fn: body = fn(body)
        elif mutation == "path_traversal_uri":
            path = self.mutator.path_traversal_uri(path)
        nf = {"N1N2MessageTransfer": "AMF", "PDUSessionCreate": "SMF",
              "UEAuthenticate": "AUSF"}.get(op_name)
        if nf is None and self.multi_nf:
            if random.random() < 0.3:
                nf = random.choice(["AMF", "SMF", "AUSF", "UDM", "UDR"])
            else:
                nf = "NRF"
        elif nf is None:
            nf = "NRF"
        addr, port = NF_ENDPOINTS.get(nf, NF_ENDPOINTS["NRF"])
        return method, path, body, nf, addr, port


async def main():
    p = argparse.ArgumentParser(description="free5GC Fuzzer (FSM-guided)")
    p.add_argument("--hours", type=float, default=0.5)
    p.add_argument("--output", type=str, default="./results")
    p.add_argument("--no-fsm", action="store_true")
    p.add_argument("--no-cross-protocol", action="store_true")
    p.add_argument("--no-novel", action="store_true")
    p.add_argument("--no-multi-nf", action="store_true")
    a = p.parse_args()

    logger.info("=" * 60)
    logger.info("free5GC Fuzzer v2 (FSM=%s)", not a.no_fsm)
    logger.info("Duration: %.1f hours", a.hours)
    logger.info("=" * 60)

    if not [c for c, s in check_container_health(MONITOR_CONTAINERS).items() if s == "running"]:
        logger.error("No free5GC containers running."); return

    fz = Free5GCFuzzer(a.hours, Path(a.output), fsm_guidance=not a.no_fsm,
                       cross_protocol=not a.no_cross_protocol,
                       no_novel=a.no_novel,
                       multi_nf=not a.no_multi_nf)
    r = await fz.run()
    of = Path(a.output) / f"fuzz_report_free5gc_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    of.write_text(json.dumps(r, indent=2, default=str))
    print(f"\nDuration: {r['campaign']['duration_seconds']:.0f}s | Requests: {r['campaign']['requests_sent']} | Crashes: {r['crashes']['total']} | FSM states: {r.get('fsm',{}).get('discovered_states','N/A')} | Report: {of}")

if __name__ == "__main__":
    asyncio.run(main())
