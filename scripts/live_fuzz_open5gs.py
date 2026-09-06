#!/usr/bin/env python3
"""Open5GS Fuzzer v2 — inherits BaseFuzzer with FSM guidance + HTTP/2.

Usage:
  python scripts/live_fuzz_open5gs.py --hours 5
  python scripts/live_fuzz_open5gs.py --hours 5 --no-fsm
  python scripts/live_fuzz_open5gs.py --hours 5 --no-cross-protocol
"""

import argparse, asyncio, json, logging, random, socket, sys, time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import h2.connection, h2.config, h2.events

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.fuzzing_engine.live_fuzzer_base import BaseFuzzer, check_container_health

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("live_fuzz_open5gs")

NF_ENDPOINTS = {
    "NRF": ("172.23.0.10", 7777), "AMF": ("172.23.0.20", 7777),
    "SMF": ("172.23.0.30", 7777), "AUSF": ("172.23.0.50", 7777),
    "UDM": ("172.23.0.60", 7777), "UDR": ("172.23.0.70", 7777),
    "PCF": ("172.23.0.80", 7777), "NSSF": ("172.23.0.90", 7777),
    "BSF": ("172.23.0.100", 7777), "SCP": ("172.23.0.110", 7777),
}
MONITOR_CONTAINERS = [
    "fuzzing-open5gs-nrf", "fuzzing-open5gs-amf", "fuzzing-open5gs-smf",
    "fuzzing-open5gs-ausf", "fuzzing-open5gs-udr",
]

SBI_TEMPLATES = {
    "NFRegister": {"method": "PUT", "path_template": "/nnrf-nfm/v1/nf-instances/{nfInstanceId}",
                   "body": {"nfInstanceId": "AMF-instance-001", "nfType": "AMF", "nfStatus": "REGISTERED",
                            "ipv4Addresses": ["172.23.0.20"], "fqdn": "amf.open5gs.local",
                            "priority": 1, "capacity": 100, "load": 0,
                            "nfServices": [{"serviceInstanceId": "namf-comm-001", "serviceName": "namf-comm",
                                            "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                                            "scheme": "http", "nfServiceStatus": "REGISTERED",
                                            "ipEndPoints": [{"ipv4Address": "172.23.0.20", "port": 7777}]}]}},
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
                         "body": {"supi": "imsi-901700000000001", "dnn": "internet",
                                  "sNssai": {"sst": 1, "sd": "010203"}, "pduSessionId": 1,
                                  "pduSessionType": "IPV4", "sscMode": "SSC_MODE_1"}},
    "UEAuthenticate": {"method": "POST", "path_template": "/nausf-auth/v1/ue-authentications",
                       "body": {"supiOrSuci": "imsi-901700000000001",
                                "servingNetworkName": "5G:mnc070.mcc901.3gppnetwork.org", "authType": "5G_AKA"}},
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
    def _deep_copy(obj): return json.loads(json.dumps(obj))
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
            path.replace("v1", "v0"), path + "/../../../etc/passwd",
            path + "?limit=-1", path + "%00.html", "/" * 1000 + path,
        ])


# ─── HTTP/2 Connection ────────────────────────────────────────

class H2Connection:
    def __init__(self, host: str, port: int, timeout: float = 10.0):
        self.host, self.port, self.timeout = host, port, timeout
        self._sock: Optional[socket.socket] = None
        self._conn = None
    def connect(self):
        self._sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        config = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
        self._conn = h2.connection.H2Connection(config=config)
        self._conn.initiate_connection()
        self._sock.sendall(self._conn.data_to_send())
    def close(self):
        if self._conn:
            self._conn.close_connection()
            if self._sock:
                try: self._sock.sendall(self._conn.data_to_send())
                except OSError: pass
        if self._sock:
            try: self._sock.close()
            except OSError: pass
    def request(self, method: str, path: str, body: Optional[bytes] = None,
                headers: Optional[Dict] = None) -> Tuple[int, Dict[str, str], bytes]:
        if self._conn is None or self._sock is None: raise RuntimeError("Not connected")
        rh = [(":method", method), (":path", path),
              (":authority", f"{self.host}:{self.port}"), (":scheme", "http"),
              ("accept", "*/*"), ("user-agent", "5g-fuzzer/1.0")]
        if headers:
            for k, v in headers.items(): rh.append((k.lower(), str(v)))
        if body:
            rh.append(("content-length", str(len(body))))
            rh.append(("content-type", "application/json"))
        sid = self._conn.get_next_available_stream_id()
        self._conn.send_headers(sid, rh)
        if body:
            for i in range(0, len(body), 16384):
                self._conn.send_data(sid, body[i:i+16384], end_stream=(i+16384>=len(body)))
        else:
            self._conn.send_headers(sid, rh, end_stream=True)
        self._sock.sendall(self._conn.data_to_send())
        deadline = time.time() + self.timeout
        rh_list, rdata, sc, ended = [], bytearray(), 0, False
        while time.time() < deadline and not ended:
            try: data = self._sock.recv(65536)
            except socket.timeout: break
            if not data: break
            for ev in self._conn.receive_data(data):
                if isinstance(ev, h2.events.ResponseReceived):
                    sc = int(ev.headers[0][1]) if ev.headers else 0; rh_list = ev.headers
                elif isinstance(ev, h2.events.DataReceived):
                    rdata.extend(ev.data); self._conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                elif isinstance(ev, h2.events.StreamEnded): ended = True
                elif isinstance(ev, h2.events.ConnectionTerminated): break
            out = self._conn.data_to_send()
            if out: self._sock.sendall(out)
        hd: Dict[str, str] = {}
        for k, v in rh_list: hd[k] = v
        return sc, hd, bytes(rdata)

class H2CPool:
    """Thread-local HTTP/2 connection pool — one dedicated connection per host per thread.

    Each executor thread gets its own H2Connection. No sharing = no lock contention.
    H2 connections persist across requests from the same thread (connection reuse).
    """

    def __init__(self, timeout=10.0, pool_size=6):
        import threading
        self.timeout = timeout
        self._local = threading.local()

    def get(self, host: str, port: int) -> H2Connection:
        key = f"{host}:{port}"
        if not hasattr(self._local, 'conns'):
            self._local.conns = {}
        if key not in self._local.conns:
            c = H2Connection(host, port, self.timeout)
            c.connect()
            self._local.conns[key] = c
        return self._local.conns[key]

    def mark_bad(self, host: str, port: int):
        key = f"{host}:{port}"
        if hasattr(self._local, 'conns') and key in self._local.conns:
            try: self._local.conns[key].close()
            except: pass
            del self._local.conns[key]

    def close_all(self):
        pass  # Thread-local cleanup happens on thread exit


# ─── Open5GS Fuzzer ───────────────────────────────────────────

class Open5GSFuzzer(BaseFuzzer):
    """Open5GS fuzzer with FSM guidance + HTTP/2 + cross-protocol mutation."""

    def __init__(self, hours=0.5, output_dir=Path("./results"),
                 fsm_guidance=True, cross_protocol=True,
                 concurrency=3, no_novel=False, multi_nf=True):
        super().__init__("Open5GS v2.7.6", hours, output_dir, fsm_guidance,
                         cross_protocol=cross_protocol,
                         concurrency=concurrency,
                         no_novel=no_novel)
        self.multi_nf = multi_nf
        self.mutator = SBIMutator()
        self._mutations = ["type_confusion", "boundary_ints", "null_required",
                           "empty_values", "oversized", "extra_fields",
                           "sql_injection", "special_chars", "path_traversal_uri",
                           "grammar_aware", "seed_replay", "structure_preserve"]
        if cross_protocol:
            self._mutations.append("cross_protocol")
            from src.fuzzing_engine.cross_protocol import CrossProtocolMutator
            self._cross_mutator = CrossProtocolMutator(enabled=True)
        self._h2pool: Optional[H2CPool] = None
        self._coverage_collector = "gcov"
        self._coverage_collector = "gcov"
        self._gcov_containers = [
            "fuzzing-open5gs-nrf",
            "fuzzing-open5gs-amf",
            "fuzzing-open5gs-smf",
            "fuzzing-open5gs-ausf",
            "fuzzing-open5gs-udr",
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
              "UEAuthenticate": "AUSF", "SDMGetAmData": "UDM",
              "UDRQueryAmf3gppAccess": "UDR"}.get(op_name)
        # Multi-NF fuzzing: 30% of generic ops go to random non-NRF NFs
        if nf is None and self.multi_nf:
            if random.random() < 0.3:
                nf = random.choice(["AMF", "SMF", "AUSF", "UDM", "UDR"])
            else:
                nf = "NRF"
        elif nf is None:
            nf = "NRF"
        addr, port = NF_ENDPOINTS.get(nf, NF_ENDPOINTS["NRF"])
        return method, path, body, nf, addr, port

    def _send_http_sync(self, op_name, target_nf, addr, port,
                        method, path, body, mutation=""):
        """Override: use HTTP/2 via H2CPool."""
        try:
            if self._h2pool is None: self._h2pool = H2CPool(timeout=10.0)
            conn = self._h2pool.get(addr, port)
            body_bytes = None
            if body is not None:
                if isinstance(body, dict): body_bytes = json.dumps(body).encode()
                elif isinstance(body, bytes): body_bytes = body
                elif isinstance(body, str): body_bytes = body.encode()
            status, headers, resp_body = conn.request(method, path, body_bytes)
            self.requests_sent += 1
            resp_preview = resp_body[:200].decode("utf-8", errors="replace")
            signature = f"{status}|{resp_preview[:80]}"
            self.response_diversity[signature] += 1
            if status >= 500:
                self.errors.append({"op": op_name, "target": target_nf, "path": path,
                                    "mutation": mutation, "status": status,
                                    "body_preview": resp_preview, "time": time.time()})
                self.strategy_stats[mutation]["http_5xx"] += 1
                self.timeline.append({"time": time.time(), "event": "http_5xx",
                                      "target": target_nf, "op": op_name,
                                      "mutation": mutation, "status": status})
            return status
        except (OSError, RuntimeError) as e:
            self.errors.append({"target": target_nf, "path": path, "mutation": mutation,
                                "error": str(e), "time": time.time()})
            self.strategy_stats[mutation]["connection_errors"] += 1
            self.timeline.append({"time": time.time(), "event": "connection_error",
                                  "target": target_nf, "op": op_name, "mutation": mutation})
            return None

    def _send_http_raw_sync(
        self, addr: str, port: int, method: str, path: str,
        body_bytes: Optional[bytes],
    ) -> Dict[str, Any]:
        """HTTP/2 raw sender — uses connection pool for reuse.

        Instance method (not static) so it can access self._h2pool.
        """
        try:
            if self._h2pool is None:
                self._h2pool = H2CPool(timeout=10.0, pool_size=self.concurrency * 2)
            conn = self._h2pool.get(addr, port)
            status, _headers, resp_body = conn.request(method, path, body_bytes)
            return {
                "status": status,
                "body_preview": resp_body[:500].decode("utf-8", errors="replace"),
                "error": None,
            }
        except (OSError, RuntimeError) as e:
            if self._h2pool:
                self._h2pool.mark_bad(addr, port)
            return {"status": None, "body_preview": "", "error": str(e)}

    async def run(self):
        self._h2pool = H2CPool(timeout=10.0)
        try:
            return await super().run()
        finally:
            if self._h2pool:
                self._h2pool.close_all()


async def main():
    p = argparse.ArgumentParser(description="Open5GS Fuzzer (FSM-guided + HTTP/2)")
    p.add_argument("--hours", type=float, default=0.5)
    p.add_argument("--output", type=str, default="./results")
    p.add_argument("--no-fsm", action="store_true")
    p.add_argument("--no-cross-protocol", action="store_true")
    p.add_argument("--no-novel", action="store_true")
    p.add_argument("--no-multi-nf", action="store_true")
    a = p.parse_args()
    logger.info("=" * 60)
    logger.info("Open5GS Fuzzer v2 (FSM=%s, HTTP/2)", not a.no_fsm)
    logger.info("Duration: %.1f hours", a.hours)
    logger.info("=" * 60)
    if not [c for c, s in check_container_health(MONITOR_CONTAINERS).items() if s == "running"]:
        logger.error("No Open5GS containers running."); return
    fz = Open5GSFuzzer(a.hours, Path(a.output), fsm_guidance=not a.no_fsm,
                        cross_protocol=not a.no_cross_protocol,
                        no_novel=a.no_novel,
                        multi_nf=not a.no_multi_nf)
    r = await fz.run()
    of = Path(a.output) / f"fuzz_report_open5gs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    of.write_text(json.dumps(r, indent=2, default=str))
    print(f"\nDuration: {r['campaign']['duration_seconds']:.0f}s | Requests: {r['campaign']['requests_sent']} | Crashes: {r['crashes']['total']} | FSM states: {r.get('fsm',{}).get('discovered_states','N/A')} | Report: {of}")

if __name__ == "__main__":
    asyncio.run(main())
