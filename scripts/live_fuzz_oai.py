#!/usr/bin/env python3
"""OAI Fuzzer v2 — inherits BaseFuzzer with FSM guidance.

Usage:
  python scripts/live_fuzz_oai_v2.py --hours 5
  python scripts/live_fuzz_oai_v2.py --hours 5 --no-fsm  # ablation
"""

import argparse
import asyncio
import json
import logging
import random
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.fuzzing_engine.live_fuzzer_base import BaseFuzzer, check_container_health

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("live_fuzz_oai")

# ─── OAI-specific configuration ──────────────────────────────

NF_ENDPOINTS = {
    "NRF":  ("172.25.0.10", 80),
    "AMF":  ("172.25.0.20", 80),
    "SMF":  ("172.25.0.30", 80),
    "AUSF": ("172.25.0.50", 80),
    "UDM":  ("172.25.0.60", 80),
}

MONITOR_CONTAINERS = [
    "fuzzing-oai-nrf", "fuzzing-oai-amf", "fuzzing-oai-smf",
    "fuzzing-oai-ausf", "fuzzing-oai-mysql",
]

_nf_counter: Dict[str, int] = defaultdict(int)


def get_instance_id(nf_type: str) -> str:
    _nf_counter[nf_type] += 1
    return f"{nf_type}-fuzz-{_nf_counter[nf_type]:04d}"


# ─── SBI Templates ────────────────────────────────────────────

SBI_TEMPLATES = {
    "NFRegister": {
        "method": "PUT",
        "path_template": "/nnrf-nfm/v1/nf-instances/{nfInstanceId}",
        "body": {
            "nfInstanceId": "AMF-instance-001",
            "nfType": "AMF", "nfStatus": "REGISTERED",
            "ipv4Addresses": ["172.25.0.20"],
            "fqdn": "amf.oai.local",
            "priority": 1, "capacity": 100, "load": 0,
            "nfServices": [{
                "serviceInstanceId": "namf-comm-001",
                "serviceName": "namf-comm",
                "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                "scheme": "http", "nfServiceStatus": "REGISTERED",
                "ipEndPoints": [{"ipv4Address": "172.25.0.20", "port": 8080}],
            }],
        },
    },
    "NFUpdate": {
        "method": "PATCH",
        "path_template": "/nnrf-nfm/v1/nf-instances/{nfInstanceId}",
        "body": {"nfStatus": "REGISTERED", "load": 50, "capacity": 200},
    },
    "NFDeregister": {
        "method": "DELETE",
        "path_template": "/nnrf-nfm/v1/nf-instances/{nfInstanceId}",
        "body": {},
    },
    "NFDiscover": {
        "method": "GET",
        "path_template": "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=SMF",
        "body": None,
    },
    "NFAccessToken": {
        "method": "POST",
        "path_template": "/nnrf-nfm/v1/oauth2/token",
        "body": {
            "grant_type": "client_credentials",
            "nfInstanceId": "AMF-instance-001",
            "scope": "namf-comm",
        },
    },
    "N1N2MessageTransfer": {
        "method": "POST",
        "path_template": "/namf-comm/v1/ue-contexts/test-ue-001/n1-n2-messages",
        "body": {
            "n1MessageContainer": {
                "n1MessageClass": "5GMM",
                "n1MessageContent": {"contentId": "nas-msg-001"},
            },
            "n2InfoContainer": {"n2InformationClass": "NR"},
        },
    },
    "SDMGetAmData": {
        "method": "GET",
        "path_template": "/nudm-sdm/v1/imsi-001010000000001/am-data",
        "body": None,
    },
    "UDRQueryAmf3gppAccess": {
        "method": "GET",
        "path_template": "/nudr-dr/v1/subscription-data/imsi-001010000000001/provisioned-data/am-data",
        "body": None,
    },
    "NFProfile": {
        "method": "GET",
        "path_template": "/nnrf-nfm/v1/nf-instances/{nfInstanceId}",
        "body": None,
    },
    "NFList": {
        "method": "GET",
        "path_template": "/nnrf-nfm/v1/nf-instances",
        "body": None,
    },
    "NFSubscribe": {
        "method": "POST",
        "path_template": "/nnrf-nfm/v1/subscriptions",
        "body": {"nfStatusNotifyUri": "http://127.0.0.1:8080/callback",
                 "reqNotifEvents": ["NF_REGISTERED"], "validityTime": "3600"},
    },
    "NFUnsubscribe": {
        "method": "DELETE",
        "path_template": "/nnrf-nfm/v1/subscriptions/{nfInstanceId}",
        "body": None,
    },
}


# ─── SBIMutator ───────────────────────────────────────────────

class SBIMutator:
    """OAI-specific SBI JSON mutator."""

    @staticmethod
    def _deep_copy(obj: Any) -> Any:
        return json.loads(json.dumps(obj))

    def type_confusion(self, body: Dict) -> Dict:
        mutated = self._deep_copy(body)
        for k in list(mutated.keys()):
            v = mutated[k]
            if isinstance(v, bool): mutated[k] = "TRUE"
            elif isinstance(v, int): mutated[k] = str(v)
            elif isinstance(v, str) and v: mutated[k] = 99999
            elif isinstance(v, list): mutated[k] = "not_a_list"
            elif isinstance(v, dict): mutated[k] = ["corrupted"]
        return mutated

    def boundary_ints(self, body: Dict) -> Dict:
        mutated = self._deep_copy(body)
        extreme = [-1, 0, 1, 255, 256, 32767, 32768, 65535, 65536,
                   2**31 - 1, 2**31, -2**31, 2**32 - 1, 2**63 - 1]
        for k, v in mutated.items():
            if isinstance(v, int): mutated[k] = random.choice(extreme)
            elif isinstance(v, dict): mutated[k] = self.boundary_ints(v)
        return mutated

    def null_required(self, body: Dict) -> Dict:
        mutated = self._deep_copy(body)
        if mutated:
            key = list(mutated.keys())[0]
            mutated[key] = None if key else None
        return mutated

    def empty_values(self, body: Dict) -> Dict:
        mutated = self._deep_copy(body)
        for k, v in mutated.items():
            if isinstance(v, str): mutated[k] = ""
            elif isinstance(v, list): mutated[k] = []
            elif isinstance(v, dict): mutated[k] = {}
        return mutated

    def oversized(self, body: Dict) -> Dict:
        mutated = self._deep_copy(body)
        for k, v in mutated.items():
            if isinstance(v, str): mutated[k] = "A" * 100000
            elif isinstance(v, list): mutated[k] = [999] * 5000
        return mutated

    def extra_fields(self, body: Dict) -> Dict:
        mutated = self._deep_copy(body)
        mutated[f"\x00null_byte_{random.randint(0, 999)}"] = "injected"
        mutated[f"../../../etc/passwd"] = "path_traversal"
        mutated[f"__proto__admin"] = True
        mutated[f"<script>alert(1)</script>"] = "xss"
        return mutated

    def sql_injection(self, body: Dict) -> Dict:
        mutated = self._deep_copy(body)
        payloads = [
            "' OR '1'='1", "'; DROP TABLE subscribers; --",
            "1' UNION SELECT * FROM users--",
        ]
        for k in list(mutated.keys()):
            if isinstance(mutated[k], str):
                mutated[k] = random.choice(payloads)
        return mutated

    def special_chars(self, body: Dict) -> Dict:
        mutated = self._deep_copy(body)
        chars = ["\x00", "\x01", "\xff", "\xfe", "\r\n\r\n", "\t", "\b",
                 "\\u0000", "{{", "}}", "${}"]
        for k in list(mutated.keys()):
            if isinstance(mutated[k], str):
                mutated[k] += random.choice(chars) * 10
        return mutated

    def path_traversal_uri(self, path: str) -> str:
        mutations = [
            path.replace("v1", "v0"),
            path.replace("v1", ""),
            path + "/../../../etc/passwd",
            path + "?limit=-1",
            path + "?limit=999999999",
            path + "%00.html",
            path.replace("/", "//"),
            "/" * 1000 + path,
        ]
        return random.choice(mutations)


# ─── OAI Fuzzer ───────────────────────────────────────────────

class OAIFuzzer(BaseFuzzer):
    """OAI 5G Core fuzzer with FSM guidance + cross-protocol mutation."""

    def __init__(self, hours: float = 0.5,
                 output_dir: Path = Path("./results"),
                 fsm_guidance: bool = True,
                 cross_protocol: bool = True,
                 concurrency: int = 5,
                 no_novel: bool = False,
                 multi_nf: bool = False):
        super().__init__(
            target_name="OAI 5G Core",
            hours=hours,
            output_dir=output_dir,
            fsm_guidance=fsm_guidance,
            cross_protocol=cross_protocol,
            concurrency=concurrency,
            no_novel=no_novel,
        )
        self.multi_nf = multi_nf
        self.mutator = SBIMutator()
        self._mutations = [
            "type_confusion", "boundary_ints", "null_required",
            "empty_values", "oversized", "extra_fields",
            "sql_injection", "special_chars", "path_traversal_uri",
            "grammar_aware", "seed_replay",
        ]
        if cross_protocol:
            self._mutations.append("cross_protocol")
            from src.fuzzing_engine.cross_protocol import CrossProtocolMutator
            self._cross_mutator = CrossProtocolMutator(enabled=True)
        self._coverage_collector = "oai_gcov"
        self._oai_gcov_containers = [
            "fuzzing-oai-nrf",
            "fuzzing-oai-amf",
            "fuzzing-oai-smf",
            "fuzzing-oai-ausf",
        ]

    @property
    def operations(self) -> List[str]:
        return list(SBI_TEMPLATES.keys())

    @property
    def mutations(self) -> List[str]:
        return self._mutations

    @property
    def monitor_containers(self) -> List[str]:
        return MONITOR_CONTAINERS

    def build_request(
        self, op_name: str, mutation: str
    ) -> Tuple[str, str, Optional[Dict], str, str, int]:
        template = SBI_TEMPLATES[op_name]
        method = template["method"]
        body = template["body"]

        path = template["path_template"]
        if "{nfInstanceId}" in path:
            nf_type = random.choice(["AMF", "SMF", "NRF", "UDM", "AUSF"])
            path = path.replace("{nfInstanceId}", get_instance_id(nf_type))

        if mutation == "cross_protocol" and body and self._cross_mutator:
            result = self._cross_mutator.mutate(body, path)
            if result:
                body, path, _meta = result
        elif body and mutation != "path_traversal_uri":
            mutate_fn = getattr(self.mutator, mutation, None)
            if mutate_fn:
                body = mutate_fn(body)
        elif mutation == "path_traversal_uri":
            path = self.mutator.path_traversal_uri(path)

        if op_name in ("SDMGetAmData", "UDRQueryAmf3gppAccess"):
            target_nf = "UDM"
        elif self.multi_nf and random.random() < 0.3:
            target_nf = random.choice(["AMF", "SMF", "AUSF", "UDM"])
        else:
            target_nf = "NRF"

        addr, port = NF_ENDPOINTS.get(target_nf, NF_ENDPOINTS["NRF"])
        return method, path, body, target_nf, addr, port

    def _send_http_sync(self, op_name, target_nf, addr, port,
                        method, path, body, mutation=""):
        """Override for OAI-specific form-encoding of access token."""
        import http.client

        try:
            conn = self._pool.get(addr, port) if self._pool else None
            if conn is None:
                return None

            body_bytes = None
            extra_headers = {}
            if body is not None:
                if op_name == "NFAccessToken":
                    form_parts = [f"{k}={v}" for k, v in body.items()]
                    body_bytes = "&".join(form_parts).encode("utf-8")
                    extra_headers["Content-Type"] = (
                        "application/x-www-form-urlencoded")
                elif isinstance(body, dict):
                    body_bytes = json.dumps(body).encode("utf-8")
                elif isinstance(body, bytes):
                    body_bytes = body
                elif isinstance(body, str):
                    body_bytes = body.encode("utf-8")

            req_headers = {"Accept": "*/*", "User-Agent": "5g-fuzzer/1.0"}
            req_headers.update(extra_headers)
            if body_bytes:
                req_headers.setdefault("Content-Type", "application/json")
                req_headers["Content-Length"] = str(len(body_bytes))

            conn.request(method, path, body=body_bytes, headers=req_headers)
            resp = conn.getresponse()
            resp_body = resp.read()

            self.requests_sent += 1
            resp_preview = resp_body[:200].decode("utf-8", errors="replace")
            signature = f"{resp.status}|{resp_preview[:80]}"
            self.response_diversity[signature] += 1

            if resp.status >= 500:
                self.errors.append({
                    "op": op_name, "target": target_nf, "path": path,
                    "mutation": mutation, "status": resp.status,
                    "body_preview": resp_preview, "time": time.time(),
                })
                self.strategy_stats[mutation]["http_5xx"] += 1
                self.timeline.append({
                    "time": time.time(), "event": "http_5xx",
                    "target": target_nf, "op": op_name,
                    "mutation": mutation, "status": resp.status,
                })

            return resp.status

        except (http.client.HTTPException, OSError,
                ConnectionError, TimeoutError) as e:
            self.errors.append({
                "target": target_nf, "path": path,
                "mutation": mutation, "error": str(e), "time": time.time(),
            })
            self.strategy_stats[mutation]["connection_errors"] += 1
            self.timeline.append({
                "time": time.time(), "event": "connection_error",
                "target": target_nf, "op": op_name, "mutation": mutation,
            })
            if self._pool:
                try:
                    self._pool.recreate(addr, port)
                except Exception:
                    pass
            return None


# ─── Main ─────────────────────────────────────────────────────

async def main():
    parser = argparse.ArgumentParser(
        description="OAI 5G Core Fuzzer v2 (FSM-guided)")
    parser.add_argument("--hours", type=float, default=0.5)
    parser.add_argument("--output", type=str, default="./results")
    parser.add_argument("--no-fsm", action="store_true",
                        help="Disable FSM guidance (ablation)")
    parser.add_argument("--no-cross-protocol", action="store_true",
                        help="Disable cross-protocol mutation (ablation)")
    parser.add_argument("--no-novel", action="store_true",
                        help="Disable all novel algorithms (ablation)")
    parser.add_argument("--no-multi-nf", action="store_true",
                        help="Disable multi-NF direct fuzzing")
    args = parser.parse_args()

    logger.info("=" * 60)
    logger.info("OAI 5G Core Fuzzer v2 (FSM=%s)", not args.no_fsm)
    logger.info("Duration: %.1f hours", args.hours)
    logger.info("=" * 60)

    # Auto-discover NF endpoints
    from src.fuzzing_engine.live_fuzzer_base import discover_endpoints
    discovered = discover_endpoints(MONITOR_CONTAINERS)
    if discovered:
        for nf, (ip, port) in discovered.items():
            NF_ENDPOINTS[nf.upper()] = (ip, port)
        logger.info("Discovered %d NFs: %s", len(discovered), list(discovered.keys()))

    health = check_container_health(MONITOR_CONTAINERS)
    running = [c for c, s in health.items() if s == "running"]
    if not running:
        logger.error("No OAI containers running.")
        return

    fuzzer = OAIFuzzer(
        hours=args.hours,
        output_dir=Path(args.output),
        fsm_guidance=not args.no_fsm,
        cross_protocol=not args.no_cross_protocol,
        no_novel=args.no_novel,
        multi_nf=not args.no_multi_nf,
    )
    # Coverage collector is configured in OAIFuzzer.__init__ (oai_gcov, scope='/build')
    report = await fuzzer.run()

    output_file = (
        Path(args.output)
        / f"fuzz_report_oai_v2_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    output_file.write_text(json.dumps(report, indent=2, default=str))

    print("\n" + "=" * 60)
    print("FUZZING CAMPAIGN COMPLETE")
    print("=" * 60)
    print(f"Duration:     {report['campaign']['duration_seconds']:.0f}s")
    print(f"Requests:     {report['campaign']['requests_sent']}")
    print(f"Rate:         {report['campaign']['request_rate']:.1f} req/s")
    print(f"FSM guidance: {report['campaign']['fsm_guidance']}")
    if report['campaign']['fsm_guidance']:
        fsm = report.get('fsm', {})
        print(f"FSM states:   {fsm.get('discovered_states', 'N/A')}")
    print(f"Crashes:      {report['crashes']['total']}")
    print(f"Errors:       {report['errors']['total']}")
    print(f"Unique resp:  {report['response_diversity']['unique_patterns']}")
    print(f"\nFull report: {output_file}")


if __name__ == "__main__":
    asyncio.run(main())
