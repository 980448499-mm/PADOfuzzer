"""Base class for live 5GC fuzzers with FSM guidance.

Provides:
  - HTTP/1.1 connection pool (shared by OAI, free5GC)
  - HTTP/2 connection pool (Open5GS)
  - Docker container health monitoring
  - FSM state tracking and RSP-guided operation selection
  - Response diversity metrics
  - Strategy effectiveness tracking
  - Crash severity classification
  - Coverage snapshots
"""

import http.client
import json
import logging
import random
import subprocess
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("live_fuzzer_base")

# ─── Crash severity classification ───────────────────────────

SEVERITY_MAP = {
    "SIGSEGV": "critical", "SIGABRT": "critical",
    "SIGBUS": "high", "SIGFPE": "high",
    "asan": "high", "heap-buffer-overflow": "high",
    "stack-buffer-overflow": "high",
    "OOM": "medium", "assertion": "medium",
    "exit": "low", "error": "info",
}


def classify_crash_severity(logs: str, exit_code: str = "") -> str:
    logs_lower = logs.lower()
    for keyword, severity in SEVERITY_MAP.items():
        if keyword.lower() in logs_lower:
            return severity
    if exit_code and exit_code.isdigit() and int(exit_code) != 0:
        return "medium"
    return "low"


# ─── FSM State Model ──────────────────────────────────────────

class FSMStateTracker:
    """Track protocol states based on HTTP response patterns.

    Maps (operation, status_bucket) → state_id.
    Uses response diversity as a proxy for protocol state discovery.
    """

    def __init__(self):
        self.state_map: Dict[str, int] = {}  # key → state_id
        self.state_visits: Dict[int, int] = defaultdict(int)
        self.state_depth: Dict[int, int] = {}
        self.state_labels: Dict[int, str] = {}
        self.transitions: Dict[int, Dict[str, int]] = defaultdict(dict)
        self.current_state: int = 0
        self.next_id: int = 1
        # Initialize root state
        self.state_map["INIT"] = 0
        self.state_labels[0] = "INIT"
        self.state_depth[0] = 0

    def observe(self, operation: str, status: int) -> int:
        """Record a transition and return the new state."""
        key = f"{operation}|{status}"
        if key not in self.state_map:
            self.state_map[key] = self.next_id
            self.state_labels[self.next_id] = key
            self.state_depth[self.next_id] = self.state_depth.get(
                self.current_state, 0) + 1
            self.next_id += 1

        next_state = self.state_map[key]
        self.transitions[self.current_state][key] = next_state
        self.state_visits[next_state] += 1
        self.current_state = next_state
        return next_state

    @property
    def discovered_states(self) -> int:
        return len(self.state_map)

    def rsp_score(self, state_id: int) -> float:
        """Rare State Prioritization score."""
        visits = self.state_visits.get(state_id, 0)
        depth = self.state_depth.get(state_id, 1)
        return (1.0 / (visits + 1)) * (1.0 + 0.1 * depth)

    def select_target_state(self) -> str:
        """Select target state using RSP."""
        if random.random() < 0.05 and len(self.state_map) > 1:
            # Explore invalid transition
            valid_states = set(self.state_map.values())
            invalid = random.randint(1000, 9999)
            while invalid in valid_states:
                invalid = random.randint(1000, 9999)
            return f"INVALID_{invalid}"

        best_state = max(
            range(self.next_id),
            key=lambda s: self.rsp_score(s),
            default=0,
        )
        return self.state_labels.get(best_state, "INIT")


# ─── HTTP Connection Pool ─────────────────────────────────────

class HTTPConnectionPool:
    """Pool of HTTP/1.1 connections (used by legacy sync path only)."""

    def __init__(self, timeout: float = 10.0):
        self._connections: Dict[str, http.client.HTTPConnection] = {}
        self.timeout = timeout

    def get(self, host: str, port: int) -> http.client.HTTPConnection:
        key = f"{host}:{port}"
        if key not in self._connections:
            self._connections[key] = http.client.HTTPConnection(
                host, port, timeout=self.timeout)
        return self._connections[key]

    def recreate(self, host: str, port: int):
        key = f"{host}:{port}"
        if key in self._connections:
            try: self._connections[key].close()
            except: pass
            del self._connections[key]
        conn = http.client.HTTPConnection(host, port, timeout=self.timeout)
        self._connections[key] = conn

    def close_all(self):
        for conn in self._connections.values():
            try: conn.close()
            except: pass
        self._connections.clear()


# ─── NF Endpoint Discovery ────────────────────────────────────

def discover_endpoints(containers: List[str],
                        default_port: int = 80) -> Dict[str, Tuple[str, int]]:
    """Auto-discover NF endpoints from running Docker containers.

    Returns dict: nf_name -> (ip, port)
    """
    import http.client
    endpoints: Dict[str, Tuple[str, int]] = {}
    for container in containers:
        try:
            result = subprocess.run(
                ["docker", "inspect", container,
                 "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"],
                capture_output=True, text=True, timeout=5,
            )
            ip = result.stdout.strip()
            if not ip:
                continue
            # Probe common ports (8080 first — OAI official images use it)
            for port in [8080, 80, 7777, 8000]:
                try:
                    conn = http.client.HTTPConnection(ip, port, timeout=2)
                    conn.request("GET", "/")
                    resp = conn.getresponse()
                    resp.read()
                    conn.close()
                    if resp.status < 600:  # Any response = alive
                        nf_name = container.replace("fuzzing-", "").replace("oai-", "")
                        endpoints[nf_name] = (ip, port)
                        logger.debug("Discovered %s at %s:%d", nf_name, ip, port)
                        break
                except Exception:
                    continue
        except subprocess.SubprocessError:
            continue
    return endpoints


# ─── Container Monitoring ─────────────────────────────────────

def check_container_health(containers: List[str]) -> Dict[str, str]:
    """Check Docker container statuses."""
    statuses = {}
    for c in containers:
        try:
            result = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Status}}", c],
                capture_output=True, text=True, timeout=5,
            )
            statuses[c] = result.stdout.strip()
        except subprocess.SubprocessError:
            statuses[c] = "unknown"
    return statuses


def get_crash_logs(container: str, tail: int = 30) -> str:
    try:
        result = subprocess.run(
            ["docker", "logs", container, "--tail", str(tail)],
            capture_output=True, text=True, timeout=5,
        )
        return result.stdout[-2000:] if result.stdout else result.stderr
    except subprocess.SubprocessError:
        return ""


# ─── Base Fuzzer ──────────────────────────────────────────────

class BaseFuzzer:
    """Common fuzzing logic shared across OAI, free5GC, and Open5GS.

    Subclasses must provide:
      - _build_http_request(op) → (method, path, body, target_nf)
      - NF_ENDPOINTS dict
      - MONITOR_CONTAINERS list
    """

    def __init__(
        self,
        target_name: str,
        hours: float = 0.5,
        output_dir: Path = Path("./results"),
        fsm_guidance: bool = True,
        cross_protocol: bool = True,
        concurrency: int = 3,
        no_novel: bool = False,
    ):
        self.target_name = target_name
        self.hours = hours
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.fsm_guidance = fsm_guidance
        self.cross_protocol = cross_protocol
        self.concurrency = concurrency
        self.no_novel = no_novel  # ablation: disable all algorithms
        # Lazy-init in subclasses that need it
        self._cross_mutator: Any = None
        # Novel algorithms — initialized in run(), defaults here for safety
        self._mutation_bandit = None
        self._cond_ts = None
        self._mt_sharing = None
        self._sat_detector = None
        self._markov_model = None
        # Coverage collector (requires gcov-instrumented binary)
        self._coverage_collector: Any = None
        self._coverage_data: List[Dict[str, Any]] = []
        # Seed persistence
        self._seed_dir: Optional[Path] = None
        self._seeds_saved: int = 0
        self._crash_scripts_saved: int = 0
        self._last_seed_body: Optional[bytes] = None
        self._last_seed_path: str = ""
        self._last_seed_method: str = ""
        # Logic bug detector (for memory-safe targets like free5GC)
        self._logic_bug_detector: Any = None
        self._logic_bug_detector_enabled: bool = True
        # State-aware seed corpus: FSM state → [full request dict, ...]
        self._seed_corpus: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
        self._seed_replay_count: Dict[str, int] = defaultdict(int)  # (op, hash) → replays
        # Novel techniques
        self._schema_learner: Any = None
        self._temporal_fuzzer: Any = None
        self._differential_fuzzer: Any = None
        # 5xx payload cache: proven crash-inducing bodies for cross-op replay
        self._fivexx_payload_cache: List[Dict[str, Any]] = []

        self.requests_sent = 0
        self.crashes_detected: List[Dict[str, Any]] = []
        self.errors: List[Dict[str, Any]] = []
        self.start_time = 0.0
        self._pool: Optional[HTTPConnectionPool] = None

        # Metrics
        self.strategy_stats: Dict[str, Dict[str, int]] = defaultdict(
            lambda: defaultdict(int))
        self.operation_stats: Dict[str, Dict[str, int]] = defaultdict(
            lambda: defaultdict(int))
        self.response_diversity: Dict[str, int] = defaultdict(int)
        self.timeline: List[Dict[str, Any]] = []
        self.coverage_snapshots: List[Dict[str, Any]] = []
        self._last_unique_count: int = 0

        # FSM
        self.fsm_tracker = FSMStateTracker() if fsm_guidance else None

    # ─── Subclass interface ──────────────────────────────────

    @property
    def operations(self) -> List[str]:
        raise NotImplementedError

    @property
    def mutations(self) -> List[str]:
        raise NotImplementedError

    @property
    def monitor_containers(self) -> List[str]:
        raise NotImplementedError

    def build_request(
        self, op_name: str, mutation: str
    ) -> Tuple[str, str, Optional[Dict], str, str, int]:
        """Return (method, path, body, target_nf, addr, port)."""
        raise NotImplementedError

    # ─── Main loop ────────────────────────────────────────────

    def _encode_body(self, body: Optional[Dict]) -> Optional[bytes]:
        if body is None:
            return None
        if isinstance(body, dict):
            return json.dumps(body).encode("utf-8")
        if isinstance(body, bytes):
            return body
        if isinstance(body, str):
            return body.encode("utf-8")
        return None

    async def run(self) -> Dict[str, Any]:
        self.start_time = time.time()
        deadline = self.start_time + self.hours * 3600
        baseline = check_container_health(self.monitor_containers)
        self._already_stopped: set = {
            c for c, s in baseline.items()
            if s not in ("running", "")
        }
        if self._already_stopped:
            logger.info("Already stopped at baseline: %s", self._already_stopped)

        # Init temporal fuzzer
        try:
            from src.fuzzing_engine.novel_fuzzing import TemporalFuzzer
            self._temporal_fuzzer = TemporalFuzzer()
        except ImportError:
            pass

        # Init schema learner for grammar-aware mutations
        try:
            from src.fuzzing_engine.novel_fuzzing import SchemaLearner
            self._schema_learner = SchemaLearner()
        except ImportError:
            pass

        # ── Novel algorithms ────────────────────────────────────
        if self.no_novel:
            self._mutation_bandit = None
            self._cond_ts = None
            self._mt_sharing = None
            self._sat_detector = None
            self._markov_model = None
            logger.info("Novel algorithms: DISABLED (ablation mode)")
        else:
            try:
                from src.fuzzing_engine.novel_algorithms import (
                    NonStationaryMutationBandit,
                    ConditionalThompsonSampling,
                    MultiTaskDirichletSharing,
                    CoverageSatDetector, CoverageMarkovModel)
                self._mutation_bandit = NonStationaryMutationBandit(
                    list(self.mutations))
                self._cond_ts = ConditionalThompsonSampling(
                    mutations=list(self.mutations),
                    endpoints=list(self.operations))
                target_id = self.target_name.lower().replace(" ", "-").replace("5g", "")
                self._mt_sharing = MultiTaskDirichletSharing(
                    target_name=target_id,
                    mutations=list(self.mutations),
                    endpoints=list(self.operations))
                self._sat_detector = CoverageSatDetector(window=10, threshold=0.0005)
                self._markov_model = CoverageMarkovModel()
                logger.info("Novel algorithms: NS-bandit + cond-TS + "
                             "MT-sharing + sat-detector + markov")
            except ImportError:
                self._mutation_bandit = None
                self._cond_ts = None
                self._mt_sharing = None
                self._sat_detector = None
                self._markov_model = None

        self._pool = HTTPConnectionPool(timeout=10.0)
        batch = 0
        ops = self.operations
        temporal_pattern = None
        import asyncio

        try:
            while time.time() < deadline:
                batch += 1
                elapsed = time.time() - self.start_time

                # ── Prepare 20 requests ──
                batch_requests: List[Dict[str, Any]] = []
                for i in range(20):
                    # FSM-guided + Markov-weighted operation selection
                    if self.fsm_tracker and self.fsm_tracker.discovered_states > 1:
                        weights = []
                        # Markov model weights (coverage-guided)
                        mw = {}
                        if self._markov_model and self._markov_model.num_regions > 5:
                            mw = self._markov_model.get_op_weights(ops)
                        for op in ops:
                            freq_score = 1.0 / (self.operation_stats[op].get("total", 0) + 1)
                            markov_score = mw.get(op, 1.0 / len(ops))
                            score = 0.5 * freq_score + 0.5 * markov_score
                            weights.append(max(0.05, score))
                        total_w = sum(weights)
                        weights = [w / total_w for w in weights]
                        op_name = random.choices(ops, weights=weights, k=1)[0]
                    else:
                        if len(ops) > 0:
                            op_name = ops[((batch - 1) * 20 + i) % len(ops)]
                        else:
                            op_name = "unknown"

                    try:
                        # ── Crash-hunting: 30% requests use precision-mutated seeds ──
                        if (self._sat_detector and
                            not self._sat_detector.is_exploration and
                            random.random() < 0.30):
                            ch_req = self._sat_detector.pick_crash_hunt_request({})
                            if ch_req:
                                op_name, method, path, body = ch_req
                                body_bytes_crash = json.dumps(body).encode() if isinstance(body, dict) else (body or None)
                                self._last_seed_body = body_bytes_crash
                                self._last_seed_path = path
                                self._last_seed_method = method
                                batch_requests.append({
                                    "op_name": op_name, "mutation": "crash_hunt",
                                    "target_nf": "NRF",
                                    "addr": getattr(self, '_nf_endpoints', {}).get("NRF", ("127.0.0.1", 80))[0],
                                    "port": getattr(self, '_nf_endpoints', {}).get("NRF", ("127.0.0.1", 80))[1],
                                    "method": method, "path": path,
                                    "body_bytes": body_bytes_crash,
                                })
                                continue

                        # ── Seed replay: 20% of requests when corpus non-empty ──
                        total_seeds = sum(len(s) for s in self._seed_corpus.values())
                        use_seed_replay = (total_seeds > 3 and
                                          random.random() < 0.20)

                        if use_seed_replay:
                            try:
                                seed_req = self._replay_seed()
                                batch_requests.append(seed_req)
                                self.operation_stats[seed_req.get("op_name", op_name)]["total"] += 1
                                continue
                            except ValueError:
                                pass  # Fall through to normal mutation

                        mutation = self._select_strategy(op_name)
                        self.strategy_stats[mutation]["total"] += 1
                        self.operation_stats[op_name]["total"] += 1

                        method, path, body, target_nf, addr, port = \
                            self.build_request(op_name, mutation)

                        # ── Structure-preserving mutation: valid JSON, extreme values ──
                        # Keeps JSON structure valid to pass SBI parsing, then triggers
                        # application-level bugs with edge-case field values.
                        if (self._schema_learner and isinstance(body, dict) and
                                body and random.random() < 0.20):
                            body = self._structure_preserve_mutate(body, path)
                            mutation = "structure_preserve"
                            self.strategy_stats["structure_preserve"]["total"] += 1

                        # ── Grammar-aware mutation (schema-guided edge values) ──
                        if (self._schema_learner and isinstance(body, dict) and
                                body and random.random() < 0.15):
                            body = self._grammar_aware_mutate(body, path)
                            mutation = "grammar_aware"
                            self.strategy_stats["grammar_aware"]["total"] += 1

                        # Cross-protocol mutation injection
                        if self.cross_protocol and self._cross_mutator:
                            if (isinstance(body, dict) and
                                    random.random() < 0.15):
                                body = self._cross_mutator.mutate(
                                    op_name, body, mutation)

                        body_bytes = self._encode_body(body)
                        self._last_seed_body = body_bytes
                        self._last_seed_path = path
                        self._last_seed_method = method

                        batch_requests.append({
                            "op_name": op_name, "mutation": mutation,
                            "target_nf": target_nf, "addr": addr, "port": port,
                            "method": method, "path": path,
                            "body_bytes": body_bytes,
                            # Save original body dict for seed corpus
                            "_body_dict": body if isinstance(body, dict) else None,
                        })
                    except Exception as e:
                        self.errors.append({"error": str(e), "time": time.time()})

                # ── Send in concurrent chunks ──
                for chunk_start in range(0, len(batch_requests), self.concurrency):
                    chunk = batch_requests[chunk_start:chunk_start + self.concurrency]
                    tasks = [
                        self._send_http_concurrent(
                            r["addr"], r["port"], r["method"],
                            r["path"], r["body_bytes"],
                        )
                        for r in chunk
                    ]
                    results = await asyncio.gather(*tasks, return_exceptions=True)

                    # Process results (main thread, safe)
                    for req_info, result in zip(chunk, results):
                        if isinstance(result, Exception):
                            continue
                        try:
                            is_new_resp = self._process_response(
                                req_info["op_name"], req_info["target_nf"],
                                req_info["mutation"], req_info["path"], result)
                            # FSM observation
                            prev_states = self.fsm_tracker.discovered_states if self.fsm_tracker else 0
                            if self.fsm_tracker and result.get("status"):
                                prev = self.fsm_tracker.discovered_states
                                self.fsm_tracker.observe(
                                    req_info["op_name"], result["status"])
                            # ── Bandit reward + Conditional TS refinement ──
                            new_fsm = (self.fsm_tracker and
                                       self.fsm_tracker.discovered_states > prev_states)
                            status = result.get("status", 0) if result else 0
                            crash = 1 if (status and status >= 500) else 0
                            crash_event = status == 0
                            is_divergent = status >= 500 or (status == 0)

                            if self._mutation_bandit is not None:
                                reward_val = (
                                    new_states * 5.0 +
                                    (1 if is_new_resp else 0) * 1.0 +
                                    crash * 20.0 +
                                    (30 if crash_event else
                                     15 if is_divergent else 0))
                                self._mutation_bandit.reward(
                                    req_info["mutation"], reward_val,
                                    crash_event=crash_event)

                            if self._cond_ts is not None:
                                self._cond_ts.refine(
                                    req_info["op_name"],
                                    req_info["mutation"],
                                    status, is_divergent)

                            if self._mt_sharing is not None:
                                boost = (
                                    5.0 if crash_event else
                                    2.0 if is_divergent else
                                    0.5 if 400 <= status < 500 else 0.1)
                                self._mt_sharing.update_local(
                                    req_info["op_name"],
                                    req_info["mutation"], boost)

                            # ── Save to seed corpus on new state OR new response ──
                            if self.fsm_tracker and (new_fsm or is_new_resp):
                                state = self.fsm_tracker.current_state
                                seed_entry = {
                                    "op_name": req_info["op_name"],
                                    "mutation": req_info["mutation"],
                                    "target_nf": req_info["target_nf"],
                                    "addr": req_info["addr"],
                                    "port": req_info["port"],
                                    "method": req_info["method"],
                                    "path": req_info["path"],
                                    "body_bytes": req_info.get("body_bytes"),
                                }
                                sig = f"{seed_entry['method']}|{seed_entry['path']}|{hash(str(seed_entry.get('body_bytes',''))[:80])}"
                                existing = [s for s in self._seed_corpus[state]
                                           if f"{s.get('method','')}|{s.get('path','')}|{hash(str(s.get('body_bytes',''))[:80])}" == sig]
                                if not existing:
                                    self._seed_corpus[state].append(seed_entry)
                                    # Multi-task Dirichlet: export stats on valuable seed
                                    if self._mt_sharing and (new_fsm or is_new_resp):
                                        self._mt_sharing.export_stats(batch)
                                    # Crash-hunting: register seeds that found new states
                                    if self._sat_detector and new_fsm:
                                        self._sat_detector.add_crash_hunt_seed(
                                            seed_entry)
                        except Exception as e:
                            self.errors.append({"error": str(e), "time": time.time()})

                # ── Periodic tasks ──
                if batch % 10 == 0:
                    await self._health_check(batch)
                    if self._temporal_fuzzer and batch % 50 == 0:
                        temporal_pattern = self._temporal_fuzzer.select_pattern()
                        logger.debug("Temporal: %s", temporal_pattern.name)
                    unique_now = len(self.response_diversity)
                    self.coverage_snapshots.append({
                        "elapsed": elapsed, "batch": batch,
                        "unique_responses": unique_now,
                        "new_in_batch": unique_now - self._last_unique_count,
                    })
                    self._last_unique_count = unique_now
                    await self._collect_code_coverage(batch, elapsed)

                    # ── Novel algorithms integration ─────────────
                    # 1. Coverage saturation detection
                    if self._sat_detector and self._coverage_data:
                        latest = self._coverage_data[-1]
                        if "lines_covered" in latest:
                            mode = self._sat_detector.feed(
                                latest.get("lines_covered", 0),
                                latest.get("lines_total", 1))

                    # 2. Multi-task Dirichlet sharing: sync statistics
                    if self._mt_sharing and batch % 200 == 0:
                        self._mt_sharing.export_stats(batch)
                        self._mt_sharing.import_stats()

                    # 3. Markov model: update from coverage data
                    if self._markov_model and self._coverage_data:
                        latest = self._coverage_data[-1]
                        per_nf = latest.get("per_nf", {})
                        raw = []
                        for nf, d in per_nf.items():
                            if "files" in d:
                                for fname, flines, fc in d.get("files", []):
                                    raw.append((fname, flines, fc, flines))
                        new_regions = self._markov_model.update_from_raw(raw)

                # ── Logic bug analysis: run detectors every 50 batches ──
                if batch % 50 == 0 and self._logic_bug_detector:
                    for nf_name in set(
                        c.replace("fuzzing-", "").replace("oai-", "")
                        for c in self.monitor_containers
                    ):
                        bugs = self._logic_bug_detector.check_error_consistency(nf_name)
                        for bug in bugs:
                            if bug not in self._logic_bug_detector.bugs:
                                self._logic_bug_detector.bugs.append(bug)
                                self._auto_generate_logic_bug_report(bug)
                                logger.warning("  🧠 Logic bug: [%s] %s",
                                               bug.severity.upper(), bug.description)
                    # Also scan container logs for panic traces
                    for container in self.monitor_containers:
                        logs = get_crash_logs(container)
                        if logs:
                            nf_name = container.replace("fuzzing-", "").replace("oai-", "")
                            new_bugs = self._logic_bug_detector.analyze_logs(logs, nf_name)
                            for bug in new_bugs:
                                self._auto_generate_logic_bug_report(bug)
                                logger.warning("  🧠 Logic bug: [%s] %s",
                                               bug.severity.upper(), bug.description)

                # ── Operation chain probing: protocol edge cases every 50 batches ──
                if batch % 50 == 0:
                    await self._operation_chain_probe()

                # ── Deep state exploration: probe missing FSM states every 100 batches ──
                if batch % 100 == 0 and self.fsm_tracker:
                    await self._deep_state_probe()

                if batch % 10 == 0:
                    rate = self.requests_sent / max(elapsed, 1)
                    fsm_info = ""
                    if self.fsm_tracker:
                        fsm_info = f" | FSM states: {self.fsm_tracker.discovered_states}"
                    logger.info(
                        "Batch %d | %d reqs | %d crashes | %.1f req/s | %.0fs%s",
                        batch, self.requests_sent, len(self.crashes_detected),
                        rate, elapsed, fsm_info,
                    )

                # ── Memory cleanup: prevent unbounded growth ──
                if batch % 500 == 0:
                    # Keep only frequently-seen response signatures
                    if len(self.response_diversity) > 5000:
                        sorted_sigs = sorted(
                            self.response_diversity.items(),
                            key=lambda x: x[1], reverse=True)
                        self.response_diversity = dict(sorted_sigs[:5000])
                    # Cap seed corpus per state
                    for state in self._seed_corpus:
                        if len(self._seed_corpus[state]) > 50:
                            self._seed_corpus[state] = \
                                self._seed_corpus[state][-50:]
                    # Limit 5xx payload cache
                    if len(self._fivexx_payload_cache) > 20:
                        self._fivexx_payload_cache = \
                            self._fivexx_payload_cache[-20:]
                    logger.info("  🧹 Memory cleanup: diversity=%d seeds=%d",
                                 len(self.response_diversity),
                                 sum(len(s) for s in self._seed_corpus.values()))

                # Temporal fuzzing: inter-batch delay
                sleep_time = 0.0
                if temporal_pattern and temporal_pattern.inter_request_ms:
                    sleep_time = random.choice(temporal_pattern.inter_request_ms)
                await asyncio.sleep(sleep_time)

        finally:
            if self._pool:
                self._pool.close_all()

        await self._health_check(batch + 1)
        return self._build_report()

    def _select_strategy(self, op_name: str = "") -> str:
        """Select mutation strategy via conditional Thompson Sampling.

        Uses ConditionalThompsonSampling when available, which learns
        per-endpoint mutation effectiveness. Falls back to
        NonStationaryMutationBandit (SW-UCB). Last resort: local UCB1.
        """
        if self._cond_ts is not None and op_name:
            return self._cond_ts.select_mutation(op_name)
        if self._mutation_bandit is not None:
            return self._mutation_bandit.select()

        import math
        mutations = list(self.mutations)
        if not self.cross_protocol and "cross_protocol" in mutations:
            mutations.remove("cross_protocol")

        total = sum(
            self.strategy_stats[m].get("total", 0) for m in mutations)
        if total < 100:
            return random.choice(mutations)

        best, best_score = mutations[0], -1.0
        for m in mutations:
            s = self.strategy_stats[m]
            trials = s.get("total", 1)
            reward = s.get("http_500", 0) + s.get("new_coverage", 0)
            avg_reward = reward / max(trials, 1)
            exploration = math.sqrt(2 * math.log(total + 1) / trials)
            ucb = avg_reward + exploration
            if ucb > best_score:
                best_score, best = ucb, m
        return best

    async def _fuzz_request(self, op_name: str, batch: int):
        mutations = list(self.mutations)
        if not self.cross_protocol and "cross_protocol" in mutations:
            mutations.remove("cross_protocol")

        # 20% chance: replay a successful seed from current FSM state
        if (self.fsm_tracker and self._seed_corpus and
                random.random() < 0.2):
            state = self.fsm_tracker.current_state
            seeds = self._seed_corpus.get(state, [])
            if seeds:
                op_name, mutation = random.choice(seeds)
            else:
                mutation = self._select_strategy(op_name)
        else:
            mutation = self._select_strategy(op_name)

        self.strategy_stats[mutation]["total"] += 1
        self.operation_stats[op_name]["total"] += 1

        method, path, body, target_nf, addr, port = self.build_request(
            op_name, mutation)

        status = await self._send_http(
            op_name, target_nf, addr, port, method, path, body, mutation)

        if status is not None:
            bucket = f"{status // 100}xx"
            self.strategy_stats[mutation][f"http_{bucket}"] += 1
            self.operation_stats[op_name][f"http_{bucket}"] += 1
            # Save to state corpus if new coverage discovered
            if (self.fsm_tracker and
                    self.strategy_stats[mutation].get("new_coverage", 0) > 0):
                state = self.fsm_tracker.current_state
                key = (op_name, mutation)
                if key not in self._seed_corpus.get(state, []):
                    self._seed_corpus[state].append(key)
            if self.fsm_tracker:
                self.fsm_tracker.observe(op_name, status)

    async def _send_http(
        self, op_name: str, target_nf: str, addr: str, port: int,
        method: str, path: str, body: Optional[Dict],
        mutation: str = "",
    ) -> Optional[int]:
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self._send_http_sync,
            op_name, target_nf, addr, port, method, path, body, mutation,
        )

    def _send_http_sync(
        self, op_name: str, target_nf: str, addr: str, port: int,
        method: str, path: str, body: Optional[Dict],
        mutation: str = "",
    ) -> Optional[int]:
        """Overridable HTTP/1.1 sender."""
        try:
            conn = self._pool.get(addr, port) if self._pool else None
            if conn is None:
                return None

            body_bytes = None
            if body is not None:
                if isinstance(body, dict):
                    body_bytes = json.dumps(body).encode("utf-8")
                elif isinstance(body, bytes):
                    body_bytes = body
                elif isinstance(body, str):
                    body_bytes = body.encode("utf-8")

            req_headers = {
                "Accept": "*/*", "User-Agent": "5g-fuzzer/1.0",
            }
            if body_bytes:
                req_headers["Content-Type"] = "application/json"
                req_headers["Content-Length"] = str(len(body_bytes))

            # Save seed for corpus persistence and crash reproduction
            self._last_seed_body = body_bytes
            self._last_seed_path = path
            self._last_seed_method = method

            conn.request(method, path, body=body_bytes, headers=req_headers)
            resp = conn.getresponse()
            resp_body = resp.read()

            self.requests_sent += 1
            resp_preview = resp_body[:500].decode("utf-8", errors="replace")
            signature = f"{resp.status}|{resp_preview[:80]}"
            is_new = signature not in self.response_diversity
            self.response_diversity[signature] += 1
            if is_new:
                self.strategy_stats[mutation]["new_coverage"] = \
                    self.strategy_stats[mutation].get("new_coverage", 0) + 1

            # Schema learner: learn API structure from responses
            if self._schema_learner is None:
                try:
                    from src.fuzzing_engine.novel_fuzzing import SchemaLearner
                    self._schema_learner = SchemaLearner()
                except ImportError:
                    pass
            if self._schema_learner:
                self._schema_learner.learn_from_response(
                    path, resp_preview, resp.status)

            # Logic bug detection (for Go/memory-safe targets)
            if self._logic_bug_detector_enabled:
                self._analyze_for_logic_bugs(
                    resp.status, resp_preview, path, mutation, target_nf)

            if resp.status >= 500:
                self.errors.append({
                    "op": op_name, "target": target_nf, "path": path,
                    "mutation": mutation, "status": resp.status,
                    "body_preview": resp_preview, "time": time.time(),
                })
                self.strategy_stats[mutation]["http_5xx"] += 1
                if resp.status == 500:
                    self.strategy_stats[mutation]["http_500"] += 1
                elif resp.status == 501:
                    self.strategy_stats[mutation]["http_501"] += 1
                self.timeline.append({
                    "time": time.time(), "event": f"http_{resp.status}",
                    "target": target_nf, "op": op_name, "mutation": mutation,
                    "status": resp.status,
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

    # ─── Concurrent HTTP sender (thread-safe) ───────────────────

    @staticmethod
    def _send_http_raw_sync(
        addr: str, port: int, method: str, path: str,
        body_bytes: Optional[bytes],
    ) -> Dict[str, Any]:
        """Thread-safe HTTP/1.1 sender — fresh connection per request.

        TCP handshake on Docker bridge is <1ms, so connection reuse offers
        negligible benefit for HTTP/1.1 but introduces thread-safety issues.
        """
        conn = http.client.HTTPConnection(addr, port, timeout=10.0)
        try:
            req_headers = {
                "Accept": "*/*", "User-Agent": "5g-fuzzer/2.0",
            }
            if body_bytes:
                req_headers["Content-Type"] = "application/json"
                req_headers["Content-Length"] = str(len(body_bytes))
            conn.request(method, path, body=body_bytes, headers=req_headers)
            resp = conn.getresponse()
            resp_body = resp.read()
            return {
                "status": resp.status,
                "body_preview": resp_body[:500].decode("utf-8", errors="replace"),
                "error": None,
            }
        except (http.client.HTTPException, OSError,
                ConnectionError, TimeoutError) as e:
            return {"status": None, "body_preview": "", "error": str(e)}
        finally:
            try:
                conn.close()
            except Exception:
                pass

    async def _send_http_concurrent(
        self, addr: str, port: int, method: str, path: str,
        body_bytes: Optional[bytes],
    ) -> Dict[str, Any]:
        """Async wrapper for the raw concurrent HTTP sender."""
        import asyncio
        import concurrent.futures
        # Dedicated thread pool — default pool has only min(32, cpu+4)=20
        # threads shared across all workers. With 21w × 3c = 63 concurrent
        # tasks, the default pool serializes requests. A larger dedicated
        # pool lets all concurrent requests execute in parallel.
        if not hasattr(self, '_executor'):
            self._executor = concurrent.futures.ThreadPoolExecutor(
                max_workers=self.concurrency * 4)
        return await asyncio.get_event_loop().run_in_executor(
            self._executor, self._send_http_raw_sync,
            addr, port, method, path, body_bytes,
        )

    def _process_response(
        self, op_name: str, target_nf: str, mutation: str, path: str,
        result: Dict[str, Any],
    ) -> bool:
        """Update all shared state from a raw HTTP result. Called in main thread.

        Returns True if the response signature was previously unseen.
        """
        status = result["status"]
        body_preview = result.get("body_preview", "")
        error = result.get("error")

        if error:
            self.errors.append({
                "target": target_nf, "path": path,
                "mutation": mutation, "error": error, "time": time.time(),
            })
            self.strategy_stats[mutation]["connection_errors"] += 1
            self.timeline.append({
                "time": time.time(), "event": "connection_error",
                "target": target_nf, "op": op_name, "mutation": mutation,
            })
            return False

        if status is None:
            return False

        self.requests_sent += 1
        # 5xx response — log immediately for visibility
        if status >= 500:
            logger.warning("  🔴 HTTP %d | %s | %s | %s → %s",
                           status, op_name, mutation, path[:80],
                           body_preview[:100])
        signature = f"{status}|{body_preview[:80]}"
        is_new = signature not in self.response_diversity
        self.response_diversity[signature] += 1
        if is_new:
            self.strategy_stats[mutation]["new_coverage"] = \
                self.strategy_stats[mutation].get("new_coverage", 0) + 1

        if self._schema_learner:
            self._schema_learner.learn_from_response(
                path, body_preview, status)

        if self._logic_bug_detector_enabled:
            self._analyze_for_logic_bugs(
                status, body_preview, path, mutation, target_nf)

        if status >= 500:
            self.errors.append({
                "op": op_name, "target": target_nf, "path": path,
                "mutation": mutation, "status": status,
                "body_preview": body_preview, "time": time.time(),
            })
            self.strategy_stats[mutation]["http_5xx"] += 1
            if status == 500:
                self.strategy_stats[mutation]["http_500"] += 1
            elif status == 501:
                self.strategy_stats[mutation]["http_501"] += 1
            self.timeline.append({
                "time": time.time(), "event": f"http_{status}",
                "target": target_nf, "op": op_name, "mutation": mutation,
                "status": status,
            })
            # Cache 5xx-inducing body for cross-operation replay
            if self._last_seed_body and len(self._fivexx_payload_cache) < 20:
                self._fivexx_payload_cache.append({
                    "body": self._last_seed_body,
                    "op": op_name, "status": status,
                })

    # ─── Seed Replay & Grammar-Aware Mutation ──────────────────

    def _minimal_mutation(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Apply 1-2 field-level mutations to an existing seed body.

        Designed for neighborhood exploration around known-interesting requests.
        """
        import copy
        mutated = copy.deepcopy(body)
        keys = list(mutated.keys())
        if not keys:
            # Empty body → inject something
            mutated["__injected__"] = random.choice([None, "", "\x00", 0])
            return mutated

        n_fields = random.choice([1, 1, 1, 2])  # 75% chance of 1 field
        target_keys = random.sample(keys, min(n_fields, len(keys)))

        for key in target_keys:
            val = mutated[key]
            if isinstance(val, str):
                if len(val) > 10 and random.random() < 0.3:
                    mutated[key] = val[:-1]  # truncate by 1
                elif len(val) < 100:
                    mutated[key] = val + random.choice(
                        ["\x00", " ", "'", "\n", "//", "undefined"])
                else:
                    mutated[key] = val[:len(val)//2]  # halve long strings
            elif isinstance(val, int):
                mutated[key] = val + random.choice([-1, 1, -val, 0, 2147483647])
            elif isinstance(val, bool):
                mutated[key] = not val
            elif isinstance(val, list) and val:
                if random.random() < 0.5:
                    mutated[key] = val[:-1]  # remove last element
                else:
                    mutated[key] = val + [val[0]]  # duplicate first
            elif isinstance(val, dict):
                mutated[key] = {**val, "__edge__": random.choice([None, "", 0])}
            elif val is None:
                mutated[key] = random.choice([0, "", False])

        return mutated

    def _structure_preserve_mutate(
        self, body: Dict[str, Any], path: str
    ) -> Dict[str, Any]:
        """Structure-preserving semantic mutation.

        Keeps JSON VALID but pushes field values to protocol-level edge cases.
        Goal: pass SBI validation (avoid 400), trigger application bugs (500).

        Strategy per field type:
          UUID    → valid-format but extreme/non-existent IDs
          integer → INT_MAX, INT_MIN, -1, 0
          string  → out-of-set enum values, valid-length extremes
          array   → empty, overpopulated
          bool    → always valid, skip
        """
        import copy
        mutated = copy.deepcopy(body)

        if self._schema_learner is None:
            try:
                from src.fuzzing_engine.novel_fuzzing import SchemaLearner
                self._schema_learner = SchemaLearner()
            except ImportError:
                return mutated

        if not isinstance(mutated, dict) or not mutated:
            return mutated

        # Pick 1-3 fields to apply semantic edge values
        keys = list(mutated.keys())
        n = random.choice([1, 2, 2, 3])  # Weighted toward 2 fields
        target_keys = random.sample(keys, min(n, len(keys)))

        for key in target_keys:
            edge_val = self._schema_learner.generate_semantic_edge(
                key, mutated[key], path)
            if edge_val is not None:
                mutated[key] = edge_val

        return mutated

    def _grammar_aware_mutate(
        self, body: Dict[str, Any], path: str
    ) -> Dict[str, Any]:
        """Schema-aware mutation: use learned field types for targeted edge values."""
        import copy
        mutated = copy.deepcopy(body)

        if self._schema_learner is None:
            try:
                from src.fuzzing_engine.novel_fuzzing import SchemaLearner
                self._schema_learner = SchemaLearner()
            except ImportError:
                return mutated

        if not isinstance(mutated, dict) or not mutated:
            return mutated

        # Pick 1-3 fields to apply grammar-aware edge values
        keys = list(mutated.keys())
        target_keys = random.sample(keys, min(random.choice([1, 1, 2, 3]), len(keys)))

        for key in target_keys:
            edge_val = self._schema_learner.generate_edge_value(
                key, mutated[key])
            if edge_val is not None:
                mutated[key] = edge_val

        # 30% chance: also remove a mandatory field
        mandatory = self._schema_learner.get_mandatory_fields(path)
        if mandatory and random.random() < 0.3:
            field_to_drop = random.choice(list(mandatory))
            if field_to_drop in mutated:
                del mutated[field_to_drop]

        return mutated

    def _replay_seed(self) -> Dict[str, Any]:
        """Select a seed from the corpus and apply minimal mutation.

        Returns a batch_requests-style dict suitable for the concurrent sender.
        Prioritizes seeds with fewer replays (UCB-like exploration).
        """
        # Collect all seeds across all states
        all_seeds: List[tuple] = []  # (state_id, seed_dict)
        for state_id, seeds in self._seed_corpus.items():
            for seed in seeds:
                all_seeds.append((state_id, seed))

        if not all_seeds:
            raise ValueError("No seeds in corpus")

        # Prefer under-replayed seeds
        weights = []
        for _, seed in all_seeds:
            key = f"{seed.get('op_name','')}|{seed.get('path','')}"
            replays = self._seed_replay_count.get(key, 0)
            weights.append(1.0 / (replays + 1))

        total_w = sum(weights)
        weights = [w / total_w for w in weights]
        chosen_seed = random.choices(all_seeds, weights=weights, k=1)[0][1]

        # Track replay
        key = f"{chosen_seed.get('op_name','')}|{chosen_seed.get('path','')}"
        self._seed_replay_count[key] += 1

        # Apply minimal mutation
        original_body = chosen_seed.get("body_bytes")
        if original_body and isinstance(original_body, bytes):
            try:
                body_dict = json.loads(original_body)
                mutated_body = self._minimal_mutation(body_dict)
                chosen_seed["body_bytes"] = json.dumps(mutated_body).encode()
            except (json.JSONDecodeError, TypeError):
                pass

        # Mark as replay for stats
        chosen_seed["mutation"] = "seed_replay"
        self.strategy_stats["seed_replay"]["total"] += 1

        return chosen_seed

    # ─── Deep State Exploration ──────────────────────────────────

    # ─── Operation chain definitions ────────────────────────────

    # Protocol-violating operation pairs: (predecessor, target)
    # Executing predecessor then target may trigger edge-case states.
    OP_CHAINS = [
        ("NFRegister", "NFDeregister"),   # Register then immediate delete
        ("NFDeregister", "NFDeregister"), # Double delete (nonexistent)
        ("NFUpdate", "NFRegister"),       # Update before register
        ("NFRegister", "NFRegister"),     # Duplicate register
        ("NFDeregister", "NFDiscover"),   # Discover deleted NF
        ("NFRegister", "NFUpdate"),       # Update after register
        ("NFDeregister", "NFUpdate"),     # Update deleted NF
    ]

    async def _operation_chain_probe(self):
        """Send a random operation pair to trigger protocol edge cases."""
        import asyncio
        chain = random.choice(self.OP_CHAINS)
        predecessor, target_op = chain

        try:
            # Execute predecessor
            pm, pp, pb, pnf, pa, ppo = self.build_request(predecessor, "chain_probe")
            if pb and isinstance(pb, dict) and pb:
                pb = self._grammar_aware_mutate(pb, pp)
            pb_bytes = self._encode_body(pb)
            self.strategy_stats["chain_probe"]["total"] += 1
            result1 = await self._send_http_concurrent(pa, ppo, pm, pp, pb_bytes)
            if result1.get("status"):
                if self.fsm_tracker:
                    self.fsm_tracker.observe(predecessor, result1["status"])

            # Execute target (may fail due to predecessor state change)
            tm, tp, tb, tnf, ta, tpo = self.build_request(target_op, "chain_probe")
            if tb and isinstance(tb, dict) and tb:
                tb = self._grammar_aware_mutate(tb, tp)
            tb_bytes = self._encode_body(tb)
            self.strategy_stats["chain_probe"]["total"] += 1
            result2 = await self._send_http_concurrent(ta, tpo, tm, tp, tb_bytes)
            is_new = self._process_response(
                target_op, tnf, "chain_probe", tp, result2)
            if self.fsm_tracker and result2.get("status"):
                prev = self.fsm_tracker.discovered_states
                self.fsm_tracker.observe(target_op, result2["status"])
                if self.fsm_tracker.discovered_states > prev:
                    logger.info("  ⛓️ Chain HIT: %s→%s → new state!", predecessor, target_op)
            if is_new:
                logger.info("  ⛓️ Chain new response: %s→%s", predecessor, target_op)
        except Exception:
            pass

    # ─── 5xx payload patterns ────────────────────────────────────

    # 5xx-inducing payload patterns (from known 5GC vulnerabilities)
    FIVEX_PAYLOADS: List[Dict[str, Any]] = [
        # Null byte injection (free5GC AUSF CWE-20)
        {"str_override": "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"},
        # Path traversal in URL-embedded IDs
        {"str_override": "../../../etc/passwd"},
        {"str_override": "....//....//....//etc/passwd"},
        # Oversized fields
        {"str_override": "A" * 65536},
        # Type confusion
        {"str_override": "", "int_override": -1},
        {"str_override": "null", "bool_override": None},
        # SQL/NoSQL injection in string fields
        {"str_override": "' OR '1'='1"},
        {"str_override": "{\"$gt\": \"\"}"},
        # Unicode/encoding attacks
        {"str_override": ""},
        {"str_override": "%00%00%00"},
    ]

    def _missing_fsm_states(self) -> List[Tuple[str, str]]:
        """Return (operation, status_code) pairs not yet discovered.

        E.g. [('NFRegister', '500'), ('UEAuthenticate', '201')]
        """
        if not self.fsm_tracker:
            return []
        discovered = set(self.fsm_tracker.state_map.keys())
        missing = []
        # Target specific status codes relevant to SBI APIs
        target_codes = ["200", "201", "204", "301", "302", "400", "403",
                        "404", "409", "429", "500", "501", "502", "503"]
        for op in self.operations:
            for code in target_codes:
                key = f"{op}|{code}"
                if key not in discovered:
                    missing.append((op, code))
        return missing

    async def _deep_state_probe(self):
        """Systematically probe for undiscovered FSM states.

        Strategies (in order of effectiveness):
          1. Cross-operation 5xx payload replay: payloads that triggered 500 on
             operation A are replayed against operations B, C, D...
          2. Operation-chain edge cases: pairs that violate protocol expectations.
          3. Static 5xx payload patterns (null bytes, oversized, etc.).
        """
        missing = self._missing_fsm_states()
        if not missing:
            return

        fivexx_targets = [(op, b) for op, b in missing if b in ("500", "502", "503")]
        other_targets = [(op, b) for op, b in missing if b not in ("500", "502", "503")]

        logger.info("  🔍 Deep probe: %d missing (%d 5xx) → probing",
                      len(missing), len(fivexx_targets))

        import asyncio
        probes_sent = 0

        # ── Strategy 1: Cross-operation 5xx payload replay ──
        if self._fivexx_payload_cache and fivexx_targets:
            for op_name, bucket in fivexx_targets[:3]:
                try:
                    cached = random.choice(self._fivexx_payload_cache)
                    # Skip if same operation (already tried)
                    if cached.get("op") == op_name and len(self._fivexx_payload_cache) > 1:
                        continue

                    method, path, body, target_nf, addr, port = \
                        self.build_request(op_name, "deep_probe")
                    if not body or not isinstance(body, dict):
                        continue

                    # Overlay cached 5xx body onto template: copy injected fields
                    try:
                        cached_body = json.loads(cached["body"])
                        if isinstance(cached_body, dict):
                            for k in list(cached_body.keys())[:3]:
                                if k in body:
                                    body[k] = cached_body[k]
                                elif len(body) < 10:
                                    body[k] = cached_body[k]
                    except (json.JSONDecodeError, TypeError):
                        pass

                    probes_sent += 1
                    self.strategy_stats["deep_probe"]["total"] += 1
                    self.operation_stats[op_name]["total"] += 1
                    body_bytes = self._encode_body(body)
                    result = await self._send_http_concurrent(
                        addr, port, method, path, body_bytes)
                    self._process_response(
                        op_name, target_nf, "deep_probe", path, result)
                    if self.fsm_tracker and result.get("status"):
                        self.fsm_tracker.observe(op_name, result["status"])
                except Exception:
                    pass

        # ── Strategy 2: Operation-chain edge cases ──
        # Define protocol-violating operation pairs
        CHAIN_PAIRS = [
            # (predecessor, target) — predecessor is executed before target
            ("NFRegister", "NFDeregister"),   # Register then immediate delete
            ("NFDeregister", "NFDeregister"), # Double delete
            ("NFUpdate", "NFRegister"),       # Update before register
            ("NFRegister", "NFRegister"),     # Duplicate register
            ("NFDeregister", "NFDiscover"),   # Discover after delete
            ("NFRegister", "NFUpdate"),       # Update after register
        ]

        for op_name, bucket in fivexx_targets[probes_sent:probes_sent+4] if probes_sent < len(fivexx_targets) else []:
            try:
                # Find chain pairs where this operation is the target
                chain = next((c for c in CHAIN_PAIRS if c[1] == op_name), None)
                if not chain:
                    continue

                predecessor, _ = chain
                # Execute predecessor first (set up protocol violation context)
                pm, pp, pb, pnf, pa, ppo = self.build_request(predecessor, "deep_probe")
                if pb and isinstance(pb, dict) and pb:
                    pb = self._grammar_aware_mutate(pb, pp)
                pb_bytes = self._encode_body(pb)
                await self._send_http_concurrent(pa, ppo, pm, pp, pb_bytes)

                # Now execute target operation (may fail due to predecessor)
                method, path, body, target_nf, addr, port = \
                    self.build_request(op_name, "deep_probe")
                if not body or not isinstance(body, dict):
                    continue
                # Apply grammar-aware edge values
                body = self._grammar_aware_mutate(body, path)

                probes_sent += 1
                self.strategy_stats["deep_probe"]["total"] += 1
                self.operation_stats[op_name]["total"] += 1
                body_bytes = self._encode_body(body)
                result = await self._send_http_concurrent(
                    addr, port, method, path, body_bytes)
                self._process_response(
                    op_name, target_nf, "deep_probe", path, result)
                if self.fsm_tracker and result.get("status"):
                    prev = self.fsm_tracker.discovered_states
                    self.fsm_tracker.observe(op_name, result["status"])
                    if self.fsm_tracker.discovered_states > prev:
                        logger.info("  🎯 CHAIN HIT: %s→%s → new state!",
                                     predecessor, op_name)
            except Exception:
                pass

        # ── Strategy 3: Static 5xx payload patterns ──
        remaining = [t for t in fivexx_targets + other_targets
                     if t not in [t2 for t2 in fivexx_targets[:probes_sent]]]
        for op_name, bucket in remaining[:max(1, 7 - probes_sent)]:
            try:
                method, path, body, target_nf, addr, port = \
                    self.build_request(op_name, "deep_probe")
                if not body or not isinstance(body, dict):
                    continue

                if bucket in ("500", "502", "503"):
                    pattern = self.FIVEX_PAYLOADS[probes_sent % len(self.FIVEX_PAYLOADS)]
                    self._apply_probe_payload(body, pattern)
                elif bucket in ("301", "302"):
                    body = {}
                else:
                    self._apply_probe_payload(body, {"int_override": 0})

                probes_sent += 1
                self.strategy_stats["deep_probe"]["total"] += 1
                self.operation_stats[op_name]["total"] += 1
                body_bytes = self._encode_body(body)
                result = await self._send_http_concurrent(
                    addr, port, method, path, body_bytes)
                self._process_response(
                    op_name, target_nf, "deep_probe", path, result)
                if self.fsm_tracker and result.get("status"):
                    self.fsm_tracker.observe(op_name, result["status"])
            except Exception:
                pass

    @staticmethod
    def _apply_probe_payload(body: Dict[str, Any],
                              pattern: Dict[str, Any]):
        """Inject a probe payload into a body dict, targeting the most relevant field."""
        if not body:
            return
        # Find the most likely string field to attack
        str_keys = [k for k, v in body.items() if isinstance(v, str)]
        int_keys = [k for k, v in body.items() if isinstance(v, int)]
        bool_keys = [k for k, v in body.items() if isinstance(v, bool)]

        if "str_override" in pattern and str_keys:
            body[random.choice(str_keys)] = pattern["str_override"]
        if "int_override" in pattern and int_keys:
            body[random.choice(int_keys)] = pattern["int_override"]
        if "bool_override" in pattern and bool_keys:
            body[random.choice(bool_keys)] = pattern["bool_override"]

    # ─── Coverage collection ───────────────────────────────────

    async def _collect_code_coverage(self, batch: int, elapsed: float):
        """Collect real code coverage — supports gcov (C/C++) and Go cover."""
        if self._coverage_collector is None:
            return

        import asyncio
        try:
            if self._coverage_collector == "gcov":
                collect_fn = self._collect_gcov_snapshot
            elif self._coverage_collector == "llvm_cov":
                collect_fn = self._collect_llvm_cov_snapshot
            elif self._coverage_collector == "go_cover":
                collect_fn = self._collect_go_cover_snapshot
            elif self._coverage_collector == "oai_gcov":
                collect_fn = self._collect_oai_gcov_snapshot
            else:
                collect_fn = self._coverage_collector.collect

            snap = await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(None, collect_fn),
                timeout=120.0,
            )
            if snap:
                self._coverage_data.append(snap)
                if "line_coverage_pct" in snap:
                    branch_str = ""
                    if snap.get("branch_coverage_pct") is not None:
                        branch_str = f" | branches {snap['branch_coverage_pct']:.1f}% ({snap.get('branches_covered',0)}/{snap.get('branches_total',0)})"
                    logger.info("  📊 Coverage: %.1f%% lines (%d/%d)%s",
                                 snap["line_coverage_pct"],
                                 snap.get("lines_covered", 0),
                                 snap.get("lines_total", 0),
                                 branch_str)
                else:
                    self._coverage_data.append(snap)
        except (asyncio.TimeoutError, Exception) as e:
            if isinstance(e, asyncio.TimeoutError):
                logger.debug("Coverage collection timed out")
            else:
                logger.debug("Coverage collection error: %s", e)

    def _collect_gcov_snapshot(self) -> Dict[str, Any]:
        """Collect gcov coverage from Open5GS NRF container.

        Stops NRF briefly, copies gcda files, restarts.
        Only collects every 5th call to reduce overhead.
        """
        import subprocess, tempfile, re, os, glob, shutil
        # Collect from all coverage-instrumented NFs
        gcov_nfs = getattr(self, '_gcov_containers', ['fuzzing-open5gs-nrf'])
        call_count = getattr(self, '_gcov_call_count', 0)
        self._gcov_call_count = call_count + 1

        # Collect on first call, then every 20th (reduced frequency = less downtime)
        if call_count % 20 != 0 and call_count > 0:
            return getattr(self, '_gcov_last_data', {})

        tmp = tempfile.mkdtemp(prefix='gcov_')
        try:
            total_exec = 0
            total_lines = 0
            total_files = 0

            for container in gcov_nfs:
                # Check container is running
                r = subprocess.run(['docker', 'inspect', '-f', '{{.State.Running}}', container],
                                 capture_output=True, text=True, timeout=5)
                if 'true' not in r.stdout:
                    continue

                # Get NF name from container name
                nf = container.replace('fuzzing-open5gs-', '')

                # Stop gracefully (writes gcda alongside gcno in /build/build/)
                subprocess.run(['docker', 'stop', container],
                             capture_output=True, timeout=15)

                # Copy merged gcda + gcno tree (no GCOV_PREFIX, so both in /build/build/)
                subprocess.run(['docker', 'cp',
                              f'{container}:/build/build/.', f'{tmp}/{nf}'],
                             capture_output=True, timeout=15)

                # Restart
                subprocess.run(['docker', 'start', container],
                             capture_output=True, timeout=10)

                # Restart
                subprocess.run(['docker', 'start', container],
                             capture_output=True, timeout=10)

            # Parse gcda + gcno — both in /build/build/ tree since no GCOV_PREFIX
            gcda_files = glob.glob(f'{tmp}/**/*.gcda', recursive=True)
            total_branches = 0
            total_branches_taken = 0
            for gcda in gcda_files:
                gcno_dir = os.path.dirname(gcda)  # gcno is in same dir as gcda
                r = subprocess.run(['gcov', '-b', '-n', '-o', gcno_dir, gcda],
                                 capture_output=True, text=True, timeout=10)
                for line in r.stdout.split('\n'):
                    m = re.match(r'Lines executed:([\d.]+)% of (\d+)', line)
                    if m:
                        pct = float(m.group(1))
                        n = int(m.group(2))
                        total_exec += int(n * pct / 100)
                        total_lines += n
                        total_files += 1
                    bm = re.match(r'Branches executed:([\d.]+)% of (\d+)', line)
                    if bm:
                        total_branches += int(bm.group(2))
                        total_branches_taken += int(int(bm.group(2)) * float(bm.group(1)) / 100)

            result = {
                "line_coverage_pct": round(total_exec / max(total_lines, 1) * 100, 1),
                "lines_covered": total_exec,
                "lines_total": total_lines,
                "branch_coverage_pct": round(total_branches_taken / max(total_branches, 1) * 100, 1) if total_branches > 0 else None,
                "branches_covered": total_branches_taken,
                "branches_total": total_branches,
                "files_covered": total_files,
                "nfs_collected": len(gcov_nfs),
                "type": "gcov_line+branch",
                "timestamp": time.time(),
            }
            self._gcov_last_data = result
            return result
        except Exception as e:
            return {"error": str(e)}
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def _collect_llvm_cov_snapshot(self) -> Dict[str, Any]:
        """Collect LLVM SanitizerCoverage data from Open5GS containers.

        Reads /dev/shm/open5gs_cov_<pid>.bin live — no container restart needed.
        Each file is an array of uint32_t edge counters. Non-zero = covered.
        """
        import subprocess, tempfile, struct

        containers = getattr(self, '_llvm_cov_containers', ['fuzzing-open5gs-nrf'])
        call_count = getattr(self, '_llvm_cov_call_count', 0)
        self._llvm_cov_call_count = call_count + 1

        # Collect every 5th call (every ~50 batches), or first call
        if call_count % 5 != 0 and call_count > 0:
            return getattr(self, '_llvm_cov_last', {})

        per_nf = {}
        total_edges_all = 0
        total_covered_all = 0

        for container in containers:
            try:
                # Check container is running
                r = subprocess.run(
                    ['docker', 'inspect', '-f', '{{.State.Running}}', container],
                    capture_output=True, text=True, timeout=5)
                if 'true' not in r.stdout:
                    continue

                # Find all coverage shm files in the container
                r = subprocess.run(
                    ['docker', 'exec', container, 'sh', '-c',
                     'ls /dev/shm/open5gs_cov_*.bin 2>/dev/null || echo NONE'],
                    capture_output=True, text=True, timeout=10)
                if 'NONE' in r.stdout or not r.stdout.strip():
                    continue

                total_edges = 0
                covered_edges = 0

                for shm_file in r.stdout.strip().split('\n'):
                    shm_file = shm_file.strip()
                    if not shm_file:
                        continue
                    # Read binary coverage data
                    r2 = subprocess.run(
                        ['docker', 'exec', container, 'cat', shm_file],
                        capture_output=True, timeout=10)
                    if r2.returncode != 0:
                        continue
                    data = r2.stdout
                    # Parse uint32_t array (little-endian)
                    num_guards = len(data) // 4
                    for i in range(num_guards):
                        val = struct.unpack_from('<I', data, i * 4)[0]
                        total_edges += 1
                        if val > 0:
                            covered_edges += 1

                nf_name = container.replace('fuzzing-open5gs-', '')
                per_nf[nf_name] = {
                    'edges_covered': covered_edges,
                    'edges_total': total_edges,
                    'pct': round(covered_edges / max(total_edges, 1) * 100, 1),
                }
                total_edges_all += total_edges
                total_covered_all += covered_edges
            except Exception as e:
                per_nf[container] = {'error': str(e)}

        result = {
            'line_coverage_pct': round(total_covered_all / max(total_edges_all, 1) * 100, 1),
            'lines_covered': total_covered_all,
            'lines_total': total_edges_all,
            'branch_coverage_pct': None,
            'type': 'llvm_sancov',
            'per_nf': per_nf,
            'timestamp': time.time(),
        }
        self._llvm_cov_last = result
        return result

    def _collect_oai_gcov_snapshot(self) -> Dict[str, Any]:
        """Collect gcov coverage from OAI containers.

        OAI builds with GCOV_PREFIX=/tmp/coverage so .gcda files land under
        /tmp/coverage/<original-build-path>. .gcno files are at the original
        build path /build/build/<nf>/...  We run gcov INSIDE the container
        (which has gcc-12/gcov-12 matching the build) and parse its output
        on the host. This avoids gcc version mismatch.
        """
        import subprocess, re, tempfile
        oai_nfs = getattr(self, '_oai_gcov_containers', ['fuzzing-oai-nrf'])
        call_count = getattr(self, '_oai_gcov_call_count', 0)
        self._oai_gcov_call_count = call_count + 1
        if call_count % 20 != 0 and call_count > 0:
            return getattr(self, '_oai_gcov_last', {})

        per_nf: Dict[str, Dict[str, Any]] = {}
        total_exec_all = 0
        total_lines_all = 0
        total_branches_all = 0
        total_branches_taken_all = 0
        files_total = 0

        for container in oai_nfs:
            try:
                r = subprocess.run(['docker', 'inspect', '-f', '{{.State.Running}}', container],
                                  capture_output=True, text=True, timeout=5)
                if 'true' not in r.stdout: continue
                nf = container.replace('fuzzing-oai-', '')

                subprocess.run(['docker', 'stop', '-t', '5', container],
                              capture_output=True, timeout=20)
                subprocess.run(['docker', 'start', container], capture_output=True, timeout=10)
                # Wait for OAI to be ready (gcov finalized .gcda before SIGTERM, but
                # we just restarted — that started fresh process; .gcda already on disk
                # from previous shutdown)

                # Build merged tree inside container, run gcov-12, dump full output;
                # parse on host (filter to OAI source files only).
                cmd = (
                    'set -e; '
                    'merge_root=/tmp/gcov_merged && rm -rf $merge_root && mkdir -p $merge_root && '
                    'cp -a /build/build/. $merge_root/ 2>/dev/null || true; '
                    'cp -a /tmp/coverage/build/build/. $merge_root/ 2>/dev/null || true; '
                    'cd $merge_root && '
                    'find . -name "*.gcda" | while read g; do '
                    '  gcov-12 -b -n -o "$(dirname $g)" "$g" 2>/dev/null || true; '
                    'done'
                )
                r = subprocess.run(['docker', 'exec', container, 'bash', '-c', cmd],
                                  capture_output=True, text=True, timeout=120)
                total_exec = 0
                total_lines = 0
                total_branches = 0
                total_branches_taken = 0
                files_count = 0
                cur_file = None
                file_in_scope = False
                for line in r.stdout.split('\n'):
                    if line.startswith("File '"):
                        cur_file = line[6:].rstrip("'")
                        file_in_scope = (
                            '/build/component/oai-' in cur_file
                            or '/common-src/' in cur_file
                        )
                    elif file_in_scope:
                        if line.startswith('Lines executed:'):
                            m = re.match(r'Lines executed:([\d.]+)% of (\d+)', line)
                            if m:
                                pct = float(m.group(1))
                                n = int(m.group(2))
                                total_exec += int(n * pct / 100)
                                total_lines += n
                                files_count += 1
                        elif line.startswith('Branches executed:'):
                            bm = re.match(r'Branches executed:([\d.]+)% of (\d+)', line)
                            if bm:
                                total_branches += int(bm.group(2))
                                total_branches_taken += int(int(bm.group(2)) * float(bm.group(1)) / 100)

                per_nf[nf] = {
                    "lines_covered": total_exec,
                    "lines_total": total_lines,
                    "branches_covered": total_branches_taken,
                    "branches_total": total_branches,
                    "branch_pct": round(total_branches_taken / max(total_branches, 1) * 100, 1) if total_branches > 0 else None,
                    "files_covered": files_count,
                    "pct": round(total_exec / max(total_lines, 1) * 100, 1),
                }
                total_exec_all += total_exec
                total_lines_all += total_lines
                total_branches_all += total_branches
                total_branches_taken_all += total_branches_taken
                files_total += files_count
            except Exception as e:
                per_nf[container] = {"error": str(e)}

        result = {
            "line_coverage_pct": round(total_exec_all / max(total_lines_all, 1) * 100, 1),
            "lines_covered": total_exec_all,
            "lines_total": total_lines_all,
            "branch_coverage_pct": round(total_branches_taken_all / max(total_branches_all, 1) * 100, 1) if total_branches_all > 0 else None,
            "branches_covered": total_branches_taken_all,
            "branches_total": total_branches_all,
            "files_covered": files_total,
            "type": "oai_gcov",
            "per_nf": per_nf,
            "timestamp": time.time(),
        }
        self._oai_gcov_last = result
        return result

    def _collect_go_cover_snapshot(self) -> Dict[str, Any]:
        """Collect Go cover data from free5GC NF containers.

        Stops each NF, copies GOCOVERDIR data, restarts. Iterates over all
        containers in self._go_cover_containers (defaults to single nrf).
        """
        import subprocess, tempfile
        # Support both legacy single-container and new multi-container modes
        containers = getattr(self, '_go_cover_containers', None)
        if containers is None:
            single = getattr(self, '_go_cover_container', 'fuzzing-free5gc-nrf')
            containers = [single]
        call_count = getattr(self, '_go_cover_call_count', 0)
        self._go_cover_call_count = call_count + 1

        if call_count % 20 != 0 and call_count > 0:
            return getattr(self, '_go_cover_last', {})

        # Resolve go binary — host may not have go on PATH
        go_bin = None
        for cand in ('/home/mm/go/bin/go', '/home/mm/go-install/go/bin/go', '/usr/local/go/bin/go', '/usr/bin/go'):
            if Path(cand).exists():
                go_bin = cand; break
        if go_bin is None:
            import shutil as _sh
            go_bin = _sh.which('go')

        per_nf: Dict[str, Dict[str, Any]] = {}
        total_stmts_all = 0
        total_covered_all = 0
        files_covered_all = set()

        for container in containers:
            tmp = tempfile.mkdtemp(prefix='gocover_')
            try:
                # Check container exists/running
                r = subprocess.run(['docker', 'inspect', '-f', '{{.State.Running}}', container],
                                  capture_output=True, text=True, timeout=5)
                if 'true' not in r.stdout:
                    continue
                # Go 1.20+ writes coverage data to GOCOVERDIR live — no need to stop
                subprocess.run(['docker', 'cp', f'{container}:/tmp/cover/.', tmp],
                             capture_output=True, timeout=10)

                total_stmts = 0
                covered_stmts = 0
                files_covered = set()

                if go_bin:
                    r = subprocess.run(
                        [go_bin, 'tool', 'covdata', 'textfmt',
                         f'-i={tmp}', f'-o={tmp}/out.txt'],
                        capture_output=True, text=True, timeout=20)
                    if r.returncode == 0 and Path(f'{tmp}/out.txt').exists():
                        for line in open(f'{tmp}/out.txt'):
                            line = line.strip()
                            if not line or line.startswith('mode'): continue
                            parts = line.split()
                            if len(parts) >= 3 and ':' in parts[0]:
                                try:
                                    stmts = int(parts[1])
                                    count = int(parts[2])
                                    total_stmts += stmts
                                    if count > 0:
                                        covered_stmts += stmts
                                        files_covered.add(parts[0].split(':')[0])
                                except ValueError:
                                    pass

                nf_name = container.replace('fuzzing-free5gc-', '')
                per_nf[nf_name] = {
                    "lines_covered": covered_stmts,
                    "lines_total": total_stmts,
                    "files_covered": len(files_covered),
                    "pct": round(covered_stmts / max(total_stmts, 1) * 100, 1),
                }
                total_stmts_all += total_stmts
                total_covered_all += covered_stmts
                files_covered_all.update(files_covered)
            except Exception as e:
                per_nf[container] = {"error": str(e)}
            finally:
                import shutil
                shutil.rmtree(tmp, ignore_errors=True)

        result = {
            "line_coverage_pct": round(total_covered_all / max(total_stmts_all, 1) * 100, 1),
            "lines_covered": total_covered_all,
            "lines_total": total_stmts_all,
            "files_covered": len(files_covered_all),
            "type": "go_cover",
            "per_nf": per_nf,
            "timestamp": time.time(),
        }
        self._go_cover_last = result
        return result

    def _save_crash_reproduction(self, crash_info: Dict[str, Any],
                                    logs: str) -> None:
        """Generate a standalone Python crash reproduction script."""
        if not self._last_seed_body and not self._last_seed_path:
            return
        self._crash_scripts_saved += 1
        nf = crash_info.get("nf", "unknown")
        script = (
            "#!/usr/bin/env python3\n"
            f"# Crash reproduction for {nf} ({crash_info.get('severity','?')})\n"
            f"# Detected: {time.ctime(crash_info.get('time', time.time()))}\n"
            "import http.client, json\n\n"
            f"host, port = '127.0.0.1', 80  # Update to target IP\n"
            f"method = {repr(self._last_seed_method)}\n"
            f"path = {repr(self._last_seed_path)}\n"
        )
        if self._last_seed_body:
            script += f"body = {repr(self._last_seed_body)}\n"
        else:
            script += "body = None\n"
        script += (
            "conn = http.client.HTTPConnection(host, port, timeout=10)\n"
            "headers = {'Content-Type': 'application/json'}\n"
            "if body:\n"
            "    conn.request(method, path, body=body, headers=headers)\n"
            "else:\n"
            "    conn.request(method, path, headers=headers)\n"
            "resp = conn.getresponse()\n"
            "print(f'Status: {resp.status}')\n"
            "print(f'Body: {resp.read()[:500]}')\n"
        )
        script_path = (
            self.output_dir / "crashes" /
            f"reproduce_{nf}_{self._crash_scripts_saved:04d}.py")
        script_path.parent.mkdir(parents=True, exist_ok=True)
        script_path.write_text(script)
        logger.info("Crash reproduction script saved: %s", script_path)

    def _auto_generate_logic_bug_report(self, bug) -> None:
        """Auto-generate a markdown report for a logic bug."""
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        report = f"""# Logic Bug Report — {bug.category}

**Date:** {now}
**Severity:** {bug.severity.upper()}
**Category:** {bug.category}
**Description:** {bug.description}

## Evidence
```json
{json.dumps(bug.evidence, indent=2, default=str)}
```

## Reproduction Hint
{bug.reproduce_hint or 'Check fuzzer logs for the request that triggered this bug.'}

---
*Auto-generated by 5g-fuzzer logic bug detector*
"""
        report_dir = self.output_dir / "bug_reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / f"logic_bug_{bug.category}_{int(time.time())}.md"
        report_path.write_text(report)
        logger.info("Logic bug report: %s", report_path)

    def _auto_generate_bug_report(self, crash_info: Dict[str, Any],
                                   logs: str) -> None:
        """Auto-generate a markdown bug report when a crash is detected."""
        nf = crash_info.get("nf", "unknown")
        severity = crash_info.get("severity", "low")
        status = crash_info.get("status", "unknown")
        now = time.strftime("%Y-%m-%d %H:%M:%S")

        # Extract key error lines
        error_lines = []
        for line in logs.split("\n"):
            if any(kw in line for kw in [
                "FATAL", "ERRO", "SIGSEGV", "SIGABRT", "ASAN", "error",
                "panic", "assert", "ASSERT", "signal", "Signal",
            ]):
                error_lines.append(line.strip()[-300:])

        # Determine CWE and CVSS
        if "SIGSEGV" in logs:
            cwe, cvss = "CWE-129 (OOB/Use-after-free)", 7.5
        elif "SIGABRT" in logs or "assert" in logs.lower():
            cwe, cvss = "CWE-617 (Reachable Assertion)", 7.5
        elif "panic" in logs.lower() or "ERRO" in logs:
            cwe, cvss = "CWE-20 (Improper Input Validation)", 5.3
        else:
            cwe, cvss = "CWE-248 (Uncaught Exception)", 5.0

        report = f"""# {nf.upper()} — Fuzzer-Discovered Crash Report

**Date:** {now}
**NF:** {nf}
**Container:** {crash_info.get('container', '?')}
**Status:** {status}
**Severity:** {severity.upper()} (CVSS {cvss})
**CWE:** {cwe}

---

## Summary

The {nf} crashed with exit status `{status}` during fuzzing.

## Crash Logs (key lines)

```
{chr(10).join(error_lines[:30] if error_lines else ['No explicit error lines found'])}
```

## Reproduction

```python
import http.client, json

# Last request sent before crash:
host, port = "127.0.0.1", 80
method = {repr(self._last_seed_method)}
path = {repr(self._last_seed_path)}
body = {repr(self._last_seed_body[:200] if self._last_seed_body else None)}

conn = http.client.HTTPConnection(host, port, timeout=10)
headers = {{'Content-Type': 'application/json'}}
if body:
    conn.request(method, path, body=body, headers=headers)
else:
    conn.request(method, path, headers=headers)
resp = conn.getresponse()
print(f"Status: {{resp.status}}")
print(f"Body: {{resp.read()[:500]}}")
```

## Impact

- {nf} service denial (crash → restart loop)
- Potential for further exploitation of the same crash path

## CVSS 3.1

```
AV:N / AC:L / PR:N / UI:N / S:U / C:N / I:N / A:H → {cvss} ({severity.upper()})
```

---
*Auto-generated by 5g-fuzzer at {now}*
"""
        report_dir = self.output_dir / "bug_reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / f"crash_{nf}_{int(time.time())}.md"
        report_path.write_text(report)
        logger.info("Bug report auto-generated: %s", report_path)

    def _auto_restart_container(self, container: str) -> None:
        """Attempt to restart a crashed container so fuzzing can continue."""
        try:
            subprocess.run(
                ["docker", "restart", container],
                capture_output=True, timeout=15)
            # Remove from already_stopped so it's monitored again
            if hasattr(self, '_already_stopped'):
                self._already_stopped.discard(container)
            logger.info("  🔄 Auto-restarted: %s", container)
        except Exception as e:
            logger.warning("  ⚠️  Failed to restart %s: %s", container, e)

    def save_seed_to_corpus(self, new_edges: int = 0) -> None:
        """Persist the last seed to the corpus directory if it discovered new coverage."""
        if not self._seed_dir:
            self._seed_dir = self.output_dir / "corpus"
            self._seed_dir.mkdir(parents=True, exist_ok=True)
        if not self._last_seed_body:
            return
        self._seeds_saved += 1
        seed_path = self._seed_dir / f"seed_{self._seeds_saved:06d}.bin"
        seed_path.write_bytes(self._last_seed_body)
        meta = {
            "method": self._last_seed_method,
            "path": self._last_seed_path,
            "new_edges": new_edges,
            "timestamp": time.time(),
        }
        meta_path = seed_path.with_suffix(".meta.json")
        meta_path.write_text(json.dumps(meta))

    def _analyze_for_logic_bugs(self, status: int, body: str, path: str,
                                   mutation: str, target_nf: str) -> None:
        """Run logic bug detection on a response."""
        if self._logic_bug_detector is None:
            try:
                from src.fuzzing_engine.logic_bug_detector import LogicBugDetector
                self._logic_bug_detector = LogicBugDetector()
            except ImportError:
                self._logic_bug_detector_enabled = False
                return
        self._logic_bug_detector.analyze_response(
            status, body, path, mutation, target_nf)

    def setup_coverage_collector(self, container: str, source_dir: str = "/build"):
        """Setup real code coverage collection for a container."""
        try:
            from src.fuzzing_engine.coverage_collector import CoverageCollector
            self._coverage_collector = CoverageCollector(
                container=container, source_dir=source_dir)
            if self._coverage_collector.available:
                logger.info("Real code coverage collection ENABLED for %s", container)
            else:
                logger.info("Coverage collector not available for %s", container)
                self._coverage_collector = None
        except ImportError:
            self._coverage_collector = None

    # ─── Health check ────────────────────────────────────────

    async def _health_check(self, batch: int):
        import asyncio
        current = check_container_health(self.monitor_containers)
        for container, status in current.items():
            if status not in ("running", ""):
                # Try to revive containers that were already dead at baseline
                if container in getattr(self, '_already_stopped', set()):
                    self._auto_restart_container(container)
                    # Re-check after restart attempt
                    new_status = check_container_health([container]).get(container, "")
                    if new_status in ("running", ""):
                        self._already_stopped.discard(container)
                        logger.info("  ✅ Revived %s (was dead at baseline)", container)
                        continue  # Alive now, monitor normally next time
                    continue  # Still dead, skip
                nf_name = container.replace("fuzzing-", "").replace("oai-", "")
                logs = get_crash_logs(container)
                severity = classify_crash_severity(logs, "")
                crash_info = {
                    "container": container, "nf": nf_name, "status": status,
                    "severity": severity, "time": time.time(),
                    "batch": batch, "logs": logs,
                }
                existing = [
                    c for c in self.crashes_detected
                    if c["container"] == container
                ]
                if not existing or existing[-1]["status"] != status:
                    self.crashes_detected.append(crash_info)
                    self.timeline.append({
                        "time": time.time(), "event": "crash",
                        "target": nf_name, "severity": severity,
                    })
                    # Generate crash reproduction script
                    self._save_crash_reproduction(crash_info, logs)
                    # Auto-generate bug report
                    self._auto_generate_bug_report(crash_info, logs)
                    # Auto-restart container to continue fuzzing
                    self._auto_restart_container(container)
                    logger.warning(
                        "CRASH [%s]: %s -> %s",
                        severity.upper(), container, status)
                    if logs:
                        for line in logs.split("\n"):
                            if any(kw in line for kw in [
                                "FATAL", "ERRO", "SIGSEGV", "SIGABRT",
                                "ASAN", "error", "panic",
                            ]):
                                logger.warning("  %s", line.strip()[-200:])

    # ─── Report ───────────────────────────────────────────────

    def _build_report(self) -> Dict[str, Any]:
        elapsed = time.time() - self.start_time

        crash_by_nf = defaultdict(int)
        crash_by_severity = defaultdict(int)
        for c in self.crashes_detected:
            crash_by_nf[c["nf"]] += 1
            crash_by_severity[c.get("severity", "low")] += 1

        error_types = defaultdict(int)
        for e in self.errors:
            if "status" in e:
                error_types[f"HTTP_{e['status']}"] += 1
            else:
                error_types["connection_error"] += 1

        strategy_ranking = sorted([
            {
                "strategy": n,
                "total": s.get("total", 0),
                "http_5xx": s.get("http_5xx", 0),
                "http_500": s.get("http_500", 0),
                "http_501": s.get("http_501", 0),
                "http_4xx": s.get("http_4xx", 0),
                "http_2xx": s.get("http_2xx", 0),
                "connection_errors": s.get("connection_errors", 0),
                "score": s.get("http_500", 0) + s.get("connection_errors", 0),
            }
            for n, s in self.strategy_stats.items()
        ], key=lambda x: x["score"], reverse=True)

        operation_ranking = sorted([
            {
                "operation": n,
                "total": s.get("total", 0),
                "http_5xx": s.get("http_5xx", 0),
                "http_4xx": s.get("http_4xx", 0),
                "http_2xx": s.get("http_2xx", 0),
                "connection_errors": s.get("connection_errors", 0),
            }
            for n, s in self.operation_stats.items()
        ], key=lambda x: x["http_5xx"], reverse=True)

        timeline_events = defaultdict(int)
        for t in self.timeline:
            timeline_events[t["event"]] += 1

        report = {
            "campaign": {
                "target": self.target_name,
                "duration_seconds": elapsed,
                "duration_hours": elapsed / 3600,
                "requests_sent": self.requests_sent,
                "request_rate": self.requests_sent / max(elapsed, 1),
                "fsm_guidance": self.fsm_guidance,
            },
            "crashes": {
                "total": len(self.crashes_detected),
                "by_nf": dict(crash_by_nf),
                "by_severity": dict(crash_by_severity),
                "details": self.crashes_detected,
            },
            "errors": {
                "total": len(self.errors),
                "by_type": dict(error_types),
            },
            "response_diversity": {
                "unique_patterns": len(self.response_diversity),
                "top_patterns": sorted(
                    self.response_diversity.items(),
                    key=lambda x: x[1], reverse=True,
                )[:10],
            },
            "strategy_effectiveness": {
                "ranking": strategy_ranking,
                "total_strategies": len(self.mutations),
            },
            "operation_coverage": {
                "ranking": operation_ranking,
                "operations_tested": len(self.operations),
                "mutation_strategies": self.mutations,
            },
            "coverage": {
                "total_unique_responses": len(self.response_diversity),
                "snapshots": self.coverage_snapshots,
                "growth_rate": (
                    len(self.response_diversity) / max(elapsed, 1)) * 60,
                "plateau_detected": (
                    len(self.coverage_snapshots) >= 3 and all(
                        s["new_in_batch"] <= 1
                        for s in self.coverage_snapshots[-3:])),
            },
            "timeline": {
                "total_events": len(self.timeline),
                "events_by_type": dict(timeline_events),
                "details": (
                    self.timeline[-20:] if len(self.timeline) > 20
                    else self.timeline),
            },
        }

        if self.fsm_tracker:
            report["fsm"] = {
                "discovered_states": self.fsm_tracker.discovered_states,
                "state_labels": self.fsm_tracker.state_labels,
                "state_visits": dict(self.fsm_tracker.state_visits),
            }

        if self._logic_bug_detector and self._logic_bug_detector.bugs:
            report["logic_bugs"] = self._logic_bug_detector.summary()

        if self._schema_learner:
            report["schema_learning"] = self._schema_learner.stats
        if self._temporal_fuzzer:
            report["temporal_fuzzing"] = self._temporal_fuzzer.stats

        if self._coverage_data:
            latest = self._coverage_data[-1]
            report["code_coverage"] = {
                "source": "gcov",
                "final_line_coverage_pct": latest.get("line_coverage_pct", 0),
                "final_branch_coverage_pct": latest.get("branch_coverage_pct", 0),
                "lines_covered": latest.get("lines_covered", 0),
                "lines_total": latest.get("lines_total", 0),
                "files_covered": latest.get("files_covered", 0),
                "snapshots": self._coverage_data,
            }

        return report
