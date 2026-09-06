"""Non-stationary online learning algorithms for 5G Core fuzzing.

Algorithms:
  1. NonStationaryMutationBandit — SW-UCB with crash-triggered reset
     and CUSUM drift detection. Models crash-restart as discrete
     change-points in the bandit environment.

  2. ConditionalThompsonSampling — Per-endpoint Dirichlet Thompson
     Sampling with active endpoint query selection. Learns which
     mutations are effective for each SBI endpoint separately.

  3. MultiTaskDirichletSharing — Hierarchical Dirichlet sufficient
     statistic sharing across fuzzer instances. Provides no-harm
     guarantee: shared prior never increases regret by more than O(1).

  4. CoverageSatDetector — Saturation detection + crash-hunting mode.

  5. CoverageMarkovModel — Markov chain coverage-guided operation selection.

Theoretical guarantees:
  - Theorem 1: R_T = O~(sqrt(T * K_cp)) for crash-aware SW-UCB
  - Theorem 2: Minimax lower bound Omega(sqrt(T * K_cp * K))
  - Proposition 3: Endpoint conditioning gives Omega(Delta^2/sigma^2)
    variance reduction over flat estimation
  - Theorem 4: Hierarchical Dirichlet sharing adds at most O(1) regret
  - Proposition 5: Posterior precision O(1/sqrt(n))
"""

import hashlib
import json
import logging
import math
import random
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("novel_algorithms")


# ═══════════════════════════════════════════════════════════════════
# 1. Non-Stationary Mutation Bandit (SW-UCB + Crash Reset + CUSUM)
# ═══════════════════════════════════════════════════════════════════

class NonStationaryMutationBandit:
    """SW-UCB with crash-triggered window reset and CUSUM drift detection.

    When a 5GC NF crashes and restarts, the reward distribution for
    all mutation arms shifts simultaneously. Standard UCB1's cumulative
    estimate becomes contaminated by pre-restart observations.

    Three mechanisms handle non-stationarity:
    1. Sliding window: only recent W observations contribute to mean
    2. Crash reset: on confirmed crash, discard 75% of the window
    3. CUSUM: detect gradual drift (e.g., memory pressure accumulation)

    Regret bound: R_T = O~(sqrt(T * K_cp)) where K_cp is the number
    of crash-restart events (Theorem 1).
    """

    def __init__(self, strategies: List[str], window_size: int = 200,
                 cusum_threshold: float = 3.0):
        self.strategies = strategies
        self.window_size = window_size
        self.cusum_threshold = cusum_threshold

        # Sliding window reward history per strategy
        self.reward_window: Dict[str, deque] = {
            s: deque(maxlen=window_size) for s in strategies
        }
        self.total_rounds = 0
        self.change_points: List[dict] = []

        # CUSUM state per strategy
        self._cusum_ref_mean: Dict[str, Optional[float]] = {}
        self._cusum_accum: Dict[str, float] = defaultdict(float)

        # Analytics
        self._ucb_cache: Dict[str, float] = {}
        self.outcomes: Dict[str, Dict[str, int]] = defaultdict(
            lambda: defaultdict(int))

    def select(self) -> str:
        """SW-UCB: select strategy using only recent rewards."""
        untried = [s for s in self.strategies
                   if len(self.reward_window[s]) == 0]
        if untried:
            return random.choice(untried)

        self.total_rounds += 1
        ln_n = math.log(self.total_rounds + 1)

        best_score, best = -1.0, self.strategies[0]
        for s in self.strategies:
            window = self.reward_window[s]
            n = len(window)
            if n == 0:
                continue
            mean = sum(window) / n
            exploration = math.sqrt(2.0 * ln_n / n)
            score = mean + exploration
            self._ucb_cache[s] = score
            if score > best_score:
                best_score, best = score, s
        return best

    def reward(self, strategy: str, r: float,
               crash_event: bool = False):
        """Feed reward with crash-aware change-point detection.

        Args:
            strategy: the mutation strategy used
            r: reward value (PADO 5-tier: 0, 5, 15, 25, 30)
            crash_event: True if a container crash was detected
        """
        self.reward_window[strategy].append(r)
        self.outcomes[strategy]["uses"] += 1

        if crash_event:
            self._on_change_point("crash_restart", strategy)
            self.outcomes[strategy]["crashes"] += 1
            return

        # Classify outcome for analytics
        if r >= 25:
            self.outcomes[strategy]["high_divergence"] += 1
        elif r >= 15:
            self.outcomes[strategy]["class_divergence"] += 1
        elif r >= 5:
            self.outcomes[strategy]["code_mismatch"] += 1

        # CUSUM drift detection
        self._update_cusum(strategy, r)

    def _on_change_point(self, cp_type: str, trigger: str):
        """Reset sliding windows on detected change point.

        On crash: discard 75% of window (environment fully reset).
        On CUSUM drift: discard 50% (partial shift).
        """
        discard_ratio = 0.75 if cp_type == "crash_restart" else 0.5

        self.change_points.append({
            'time': self.total_rounds,
            'type': cp_type,
            'trigger': trigger,
        })

        for s in self.strategies:
            w = self.reward_window[s]
            keep = max(len(w) // int(1 / (1 - discard_ratio)), 1)
            new_w = deque(list(w)[-keep:], maxlen=self.window_size)
            self.reward_window[s] = new_w

        # Reset CUSUM references
        self._cusum_ref_mean.clear()
        self._cusum_accum.clear()

        logger.info("Change point [%s] at round %d, trigger=%s",
                     cp_type, self.total_rounds, trigger)

    def _update_cusum(self, strategy: str, r: float):
        """CUSUM change-point detection for gradual reward drift."""
        window = self.reward_window[strategy]
        if len(window) < 10:
            return

        current_mean = sum(window) / len(window)

        if strategy not in self._cusum_ref_mean or \
                self._cusum_ref_mean[strategy] is None:
            self._cusum_ref_mean[strategy] = current_mean
            return

        ref = self._cusum_ref_mean[strategy]
        # Compute running std from window
        if len(window) >= 2:
            variance = sum((x - current_mean) ** 2 for x in window) / (len(window) - 1)
            std = math.sqrt(variance) if variance > 0 else 1.0
        else:
            std = 1.0

        # One-sided CUSUM normalized by std
        if std > 0:
            self._cusum_accum[strategy] += abs(r - ref) / std - 0.5
        else:
            self._cusum_accum[strategy] += 0

        # Reset accumulator if it goes negative
        self._cusum_accum[strategy] = max(0, self._cusum_accum[strategy])

        if self._cusum_accum[strategy] > self.cusum_threshold:
            logger.info("CUSUM drift detected for %s: accum=%.2f",
                         strategy, self._cusum_accum[strategy])
            self._on_change_point("cusum_drift", strategy)
            self._cusum_accum[strategy] = 0
            self._cusum_ref_mean[strategy] = current_mean

    def get_stats(self) -> List[dict]:
        """Return ranked strategy statistics."""
        ranked = []
        for s in self.strategies:
            window = self.reward_window[s]
            n = len(window)
            mean = sum(window) / n if n > 0 else 0
            ucb = self._ucb_cache.get(s, 0.0)
            outcomes = dict(self.outcomes[s])
            ranked.append({
                "strategy": s,
                "window_count": n,
                "mean_reward": round(mean, 2),
                "ucb": round(ucb, 3),
                "total_reward": round(sum(window), 1),
                **{f"outcome_{k}": v for k, v in outcomes.items()},
            })
        ranked.sort(key=lambda x: x["mean_reward"], reverse=True)
        return ranked

    @property
    def num_change_points(self) -> int:
        return len(self.change_points)


# ═══════════════════════════════════════════════════════════════════
# 2. Conditional Thompson Sampling (Per-Endpoint Dirichlet TS)
# ═══════════════════════════════════════════════════════════════════

class ConditionalThompsonSampling:
    """Per-endpoint Dirichlet Thompson Sampling with active query.

    Instead of treating all (mutation, endpoint) pairs as a flat K-arm
    bandit, we condition on endpoint and learn per-endpoint Dirichlet
    posteriors over mutations. This provides variance reduction when
    the same mutation produces very different rewards on different
    endpoints (Proposition 3).

    Active endpoint query: prioritize endpoints where posterior
    variance is highest, accelerating grammar convergence.
    """

    def __init__(self, mutations: List[str], endpoints: List[str],
                 alpha0: float = 1.0):
        self.mutations = mutations
        self.endpoints = endpoints
        self.alpha0 = alpha0

        # Per-endpoint Dirichlet parameters: alpha[endpoint][mutation]
        self.alpha: Dict[str, Dict[str, float]] = {}
        for ep in endpoints:
            self.alpha[ep] = {m: alpha0 for m in mutations}

        # Track per-endpoint observation count for active query
        self.obs_count: Dict[str, int] = defaultdict(int)

        # History for grammar precision tracking
        self.precision_history: List[dict] = []

    def select_endpoint(self) -> str:
        """Active query: pick endpoint with highest posterior variance.

        Dirichlet(alpha) variance for component i:
        Var[p_i] = alpha_i * (sum_alpha - alpha_i) /
                   (sum_alpha^2 * (sum_alpha + 1))

        High variance = still uncertain = worth exploring.
        """
        best_var, best_ep = -1.0, self.endpoints[0]
        for ep in self.endpoints:
            v = self._endpoint_variance(ep)
            if v > best_var:
                best_var, best_ep = v, ep
        return best_ep

    def select_mutation(self, endpoint: str) -> str:
        """Thompson Sample from per-endpoint Dirichlet posterior.

        Sample alpha_i ~ Gamma(alpha[ep][m], 1) for each mutation,
        then pick the mutation with highest sample.
        """
        alphas = self.alpha.get(endpoint)
        if not alphas:
            return random.choice(self.mutations)

        samples = {}
        for m, a in alphas.items():
            samples[m] = random.gammavariate(max(a, 0.01), 1.0)
        return max(samples, key=samples.get)

    def refine(self, endpoint: str, mutation: str,
               status_code: int, divergent: bool):
        """Response-driven Dirichlet posterior refinement.

        Reward hierarchy mirrors the 5-tier PADO reward:
        - CRASH (status=0): strong boost (discovered a vulnerability)
        - DIVERGENT with high severity: moderate boost
        - REJECT (4xx): weak signal (mutation reaches validation layer)
        - OTHER: minimal update
        """
        if status_code == 0:
            boost = 5.0  # crash discovery: strong positive signal
        elif divergent and status_code >= 500:
            boost = 3.0  # server error + divergence
        elif divergent:
            boost = 2.0  # behavioral divergence
        elif 400 <= status_code < 500:
            boost = 0.5  # reaches validation but rejected
        elif 200 <= status_code < 300:
            boost = 0.3  # accepted: small update
        else:
            boost = 0.1  # minimal signal

        # Auto-register endpoint/mutation if not seen during init
        if endpoint not in self.alpha:
            self.alpha[endpoint] = {m: self.alpha0 for m in self.mutations}
            self.endpoints.append(endpoint)
        if mutation not in self.alpha[endpoint]:
            self.alpha[endpoint][mutation] = self.alpha0
        self.alpha[endpoint][mutation] += boost
        self.obs_count[endpoint] = self.obs_count.get(endpoint, 0) + 1

    def grammar_precision(self, endpoint: str) -> float:
        """Measure how well we've learned the grammar for this endpoint.

        Precision = 1 - (max_variance / theoretical_max_variance).
        Converges to 1 at rate O(1/sqrt(n)) (Proposition 5).
        """
        max_var = self._endpoint_variance(endpoint)
        # Theoretical max for M mutations with alpha0 prior
        M = len(self.mutations)
        max_initial_var = (self.alpha0 * (M * self.alpha0 - self.alpha0)) / \
                          ((M * self.alpha0) ** 2 * (M * self.alpha0 + 1))
        if max_initial_var <= 0:
            return 1.0
        return max(0.0, 1.0 - max_var / max_initial_var)

    def top_mutations(self, endpoint: str, n: int = 5) -> List[Tuple[str, float]]:
        """Return top-n mutations by posterior mean for an endpoint."""
        alphas = self.alpha.get(endpoint, {})
        total = sum(alphas.values())
        if total == 0:
            return []
        ranked = sorted(
            [(m, a / total) for m, a in alphas.items()],
            key=lambda x: x[1], reverse=True
        )
        return ranked[:n]

    def _endpoint_variance(self, endpoint: str) -> float:
        """Max posterior variance across all mutations for endpoint."""
        alphas = self.alpha.get(endpoint, {})
        if not alphas:
            return float('inf')
        total = sum(alphas.values())
        if total <= 0:
            return float('inf')
        # Max variance across components
        max_var = 0.0
        for a in alphas.values():
            var = (a * (total - a)) / (total ** 2 * (total + 1))
            max_var = max(max_var, var)
        return max_var

    def snapshot_precision(self) -> dict:
        """Record current grammar precision for all endpoints."""
        snap = {
            'time': time.time(),
            'endpoints': {}
        }
        for ep in self.endpoints:
            snap['endpoints'][ep] = {
                'precision': round(self.grammar_precision(ep), 4),
                'observations': self.obs_count[ep],
                'top_mutations': self.top_mutations(ep, 3),
            }
        self.precision_history.append(snap)
        return snap

    @property
    def stats(self) -> Dict[str, Any]:
        avg_precision = 0.0
        if self.endpoints:
            avg_precision = sum(
                self.grammar_precision(ep) for ep in self.endpoints
            ) / len(self.endpoints)
        return {
            "endpoints": len(self.endpoints),
            "mutations": len(self.mutations),
            "avg_grammar_precision": round(avg_precision, 4),
            "total_observations": sum(self.obs_count.values()),
        }


# ═══════════════════════════════════════════════════════════════════
# 3. Multi-Task Dirichlet Sharing (Hierarchical Bayesian Transfer)
# ═══════════════════════════════════════════════════════════════════

class MultiTaskDirichletSharing:
    """Hierarchical Dirichlet sharing across fuzzer instances.

    Each fuzzer instance targeting a different 5GC implementation
    maintains its own local Dirichlet posterior. Periodically,
    instances export their sufficient statistics (alpha parameters)
    to a shared filesystem pool.

    The combined posterior for target i is:
        alpha_i^post = alpha_bar_{-i} + alpha_i^local

    where alpha_bar_{-i} is the average of all other targets' local
    parameters. This provides:

    - Automatic warm-start for under-explored mutations
    - No-harm guarantee: local dominance ensures shared prior
      cannot override locally learned experience (Theorem 4)
    - Negative transfer protection: when alpha_i^local >> alpha_bar,
      local experience completely dominates

    Communication cost: O(M) per sync cycle (M = number of mutations).
    """

    def __init__(self, target_name: str,
                 mutations: List[str],
                 endpoints: List[str],
                 sync_path: str = "/tmp/fuzzer_mtts",
                 sync_interval: int = 200):
        self.target = target_name
        self.mutations = mutations
        self.endpoints = endpoints
        self.sync_path = Path(sync_path)
        self.sync_path.mkdir(parents=True, exist_ok=True)
        self.sync_interval = sync_interval

        # Local Dirichlet parameters per endpoint
        self.local_alpha: Dict[str, Dict[str, float]] = {}
        for ep in endpoints:
            self.local_alpha[ep] = {m: 1.0 for m in mutations}

        # Shared prior from other targets
        self.shared_alpha: Dict[str, Dict[str, float]] = {}

        # Analytics
        self.stats = {"exports": 0, "imports": 0, "sync_cycles": 0}

    def export_stats(self, round_num: int):
        """Export local sufficient statistics to shared pool.

        Writes per-endpoint Dirichlet alpha parameters as JSON.
        Communication cost: O(M * E) per sync.
        """
        if round_num % self.sync_interval != 0:
            return

        payload = {
            'target': self.target,
            'round': round_num,
            'timestamp': time.time(),
            'alpha': {ep: dict(alphas) for ep, alphas in self.local_alpha.items()},
        }
        path = self.sync_path / f"{self.target}_stats.json"
        path.write_text(json.dumps(payload, default=str))
        self.stats["exports"] += 1

    def import_stats(self):
        """Import shared priors from other targets.

        Computes alpha_bar_{-i} = average of other targets' local alphas.
        Combined posterior: alpha_i^post = alpha_bar_{-i} + alpha_i^local.
        """
        self.shared_alpha = {ep: defaultdict(float) for ep in self.endpoints}
        count = 0

        for f in self.sync_path.glob("*_stats.json"):
            try:
                data = json.loads(f.read_text())
                if data.get('target') == self.target:
                    continue
                for ep in self.endpoints:
                    ep_alpha = data.get('alpha', {}).get(ep, {})
                    for m in self.mutations:
                        self.shared_alpha[ep][m] += ep_alpha.get(m, 0.0)
                count += 1
            except Exception:
                continue

        if count > 0:
            for ep in self.endpoints:
                for m in self.mutations:
                    self.shared_alpha[ep][m] /= count
            self.stats["imports"] += 1

        self.stats["sync_cycles"] += 1

    def combined_posterior(self, endpoint: str) -> Dict[str, float]:
        """Compute combined posterior: shared + local.

        alpha_post[m] = alpha_shared[ep][m] + alpha_local[ep][m]

        No-harm guarantee (Theorem 4): when alpha_local > alpha_shared
        for mutation m, local experience dominates the posterior.
        """
        local = self.local_alpha.get(endpoint, {})
        shared = self.shared_alpha.get(endpoint, {})

        combined = {}
        for m in self.mutations:
            combined[m] = local.get(m, 1.0) + shared.get(m, 0.0)
        return combined

    def sample_mutation(self, endpoint: str) -> str:
        """Thompson Sample from combined posterior for an endpoint."""
        posterior = self.combined_posterior(endpoint)

        samples = {}
        for m, alpha in posterior.items():
            samples[m] = random.gammavariate(max(alpha, 0.01), 1.0)
        return max(samples, key=samples.get) if samples else random.choice(self.mutations)

    def update_local(self, endpoint: str, mutation: str, reward_value: float):
        """Update local Dirichlet parameter from observation."""
        if endpoint not in self.local_alpha:
            self.local_alpha[endpoint] = {m: 1.0 for m in self.mutations}
        self.local_alpha[endpoint][mutation] += reward_value

    def local_dominance_ratio(self, endpoint: str, mutation: str) -> float:
        """Ratio of local to shared alpha for a mutation.

        Ratio >= 1.0 means local experience dominates (no-harm zone).
        Ratio < 1.0 means shared prior is influential (warm-start zone).
        """
        local_val = self.local_alpha.get(endpoint, {}).get(mutation, 1.0)
        shared_val = self.shared_alpha.get(endpoint, {}).get(mutation, 0.0)
        if shared_val <= 0:
            return float('inf')
        return local_val / shared_val

    def transfer_benefit(self) -> dict:
        """Analyze how many mutations benefit from shared knowledge."""
        warm_started = 0
        locally_dominant = 0
        for ep in self.endpoints:
            for m in self.mutations:
                ratio = self.local_dominance_ratio(ep, m)
                if ratio < 1.0:
                    warm_started += 1  # shared knowledge helps
                else:
                    locally_dominant += 1  # local knowledge sufficient
        return {
            "warm_started_mutations": warm_started,
            "locally_dominant_mutations": locally_dominant,
            "total_mutations": len(self.endpoints) * len(self.mutations),
        }


# ═══════════════════════════════════════════════════════════════════
# 4. Coverage Saturation Detection + Mode Switch
# ═══════════════════════════════════════════════════════════════════

class CoverageSatDetector:
    """Monitor coverage growth; switch to crash-hunting when saturated.

    Phase 1 (exploration): default fuzzing.
    Phase 2 (crash-hunting): precision-mutate seeds that triggered
        new states, errors, or unique responses.
    """

    EXPLORATION = "exploration"
    CRASH_HUNTING = "crash_hunting"

    def __init__(self, window: int = 10, threshold: float = 0.0005,
                 min_snapshots: int = 5):
        self.window = window
        self.threshold = threshold
        self.min_snapshots = min_snapshots
        self.history: List[float] = []
        self.mode = self.EXPLORATION
        self.mode_switches: List[dict] = []
        self._crash_hunt_seeds: List[dict] = []
        self._crash_hunt_round = 0

    def feed(self, lines_covered: int, lines_total: int) -> str:
        pct = lines_covered / max(lines_total, 1)
        self.history.append(pct)
        if len(self.history) > self.window:
            self.history.pop(0)

        if self.mode == self.EXPLORATION and self._is_saturated():
            self.mode = self.CRASH_HUNTING
            self._crash_hunt_round = 0
            self.mode_switches.append({
                "time": time.time(), "from": self.EXPLORATION,
                "to": self.CRASH_HUNTING,
                "coverage_pct": round(pct * 100, 2),
            })
            logger.info("Mode: EXPLORATION -> CRASH-HUNTING "
                         "(coverage saturated at %.2f%%)", pct * 100)
        return self.mode

    def _is_saturated(self) -> bool:
        if len(self.history) < self.min_snapshots:
            return False
        return (self.history[-1] - self.history[0]) < self.threshold

    def add_crash_hunt_seed(self, seed: dict):
        seed["_added_at"] = time.time()
        self._crash_hunt_seeds.append(seed)
        if len(self._crash_hunt_seeds) > 200:
            self._crash_hunt_seeds = self._crash_hunt_seeds[-200:]

    def pick_crash_hunt_request(self, templates: dict
                                ) -> Optional[Tuple[str, str, str, any]]:
        if not self._crash_hunt_seeds:
            return None
        self._crash_hunt_round += 1
        seed = random.choice(self._crash_hunt_seeds)
        body = dict(seed.get("body", {}) or {})
        if body and isinstance(body, dict) and len(body) > 0:
            key = random.choice(list(body.keys()))
            old_val = body[key]
            if isinstance(old_val, int):
                body[key] = random.choice([-1, 0, 1, old_val + 1, old_val - 1,
                                            2**31 - 1, -2**31])
            elif isinstance(old_val, str):
                body[key] = old_val + random.choice([
                    "\x00", "'", "\n", "{}", "[]", "A" * 1000])
            elif isinstance(old_val, bool):
                body[key] = not old_val
            elif old_val is None:
                body[key] = ""
            elif isinstance(old_val, list):
                body[key] = old_val + [None]
        return (seed.get("op_name", "NFDiscover"),
                seed.get("method", "GET"),
                seed.get("path", "/"),
                body)

    @property
    def is_exploration(self) -> bool:
        return self.mode == self.EXPLORATION


# ═══════════════════════════════════════════════════════════════════
# 5. Coverage Markov Model (unchanged)
# ═══════════════════════════════════════════════════════════════════

class CoverageMarkovModel:
    """Build a coverage transition graph to guide fuzzer toward unseen code."""

    def __init__(self):
        self.graph: Dict[Tuple[str, str], Dict[Tuple[str, str], int]] = \
            defaultdict(lambda: defaultdict(int))
        self.region_visited: Set[Tuple[str, str]] = set()
        self.region_coverage: Dict[Tuple[str, str], int] = {}
        self._last_region: Optional[Tuple[str, str]] = None
        self.op_success: Dict[str, List[float]] = defaultdict(list)
        self.op_to_new_regions: Dict[str, int] = defaultdict(int)

    def update_from_raw(self, raw_data: List[Tuple[str, int, int, int]]):
        current_regions = set()
        for file_path, line, covered, total in raw_data:
            if covered > 0:
                func = self._extract_func(file_path, line)
                region = (file_path, func)
                current_regions.add(region)
                self.region_coverage[region] = \
                    self.region_coverage.get(region, 0) + covered

        new_regions = current_regions - self.region_visited

        if new_regions and self._last_region:
            for nr in new_regions:
                self.graph[self._last_region][nr] += 1

        if current_regions:
            self._last_region = random.choice(list(current_regions))

        self.region_visited |= current_regions
        return len(new_regions)

    @staticmethod
    def _extract_func(file_path: str, line: int) -> str:
        parts = file_path.replace("\\", "/").split("/")
        if len(parts) >= 2:
            src = f"{parts[-2]}/{parts[-1]}:{line // 10 * 10}"
        else:
            src = f"{file_path}:{line // 10 * 10}"
        return src

    def record_op_result(self, op_name: str, new_regions: int):
        if new_regions > 0:
            self.op_to_new_regions[op_name] += new_regions

    def get_op_weights(self, operations: List[str]) -> Dict[str, float]:
        weights = {}
        for op in operations:
            score = self.op_to_new_regions.get(op, 0) + 1
            weights[op] = score
        total = sum(weights.values())
        if total > 0:
            return {op: w / total for op, w in weights.items()}
        return {op: 1.0 / len(operations) for op in operations}

    def predict_novelty(self, op_name: str) -> float:
        successes = self.op_to_new_regions.get(op_name, 0)
        total = len(self.region_visited) or 1
        return (successes + 1) / (total + 2)

    @property
    def num_regions(self) -> int:
        return len(self.region_visited)

    @property
    def num_edges(self) -> int:
        return sum(len(t) for t in self.graph.values())


# ═══════════════════════════════════════════════════════════════════
# 6. Differential Fuzzer (protocol-aware, used as infrastructure)
# ═══════════════════════════════════════════════════════════════════

class DifferentialFuzzer:
    """Send identical SBI requests to multiple 5GC implementations.

    Used as infrastructure for the divergence reward signal.
    Protocol dispatch is engineering, not algorithmic contribution.
    """

    def __init__(self, endpoints: Dict[str, Tuple[str, int]],
                 operations: List[str],
                 build_fn: callable):
        self.endpoints = endpoints
        self.operations = operations
        self.build_fn = build_fn
        self.divergences: List[dict] = []
        self.total_tests = 0
        self.total_divergences = 0
        self.op_divergence: Dict[str, int] = defaultdict(int)
        self.op_tests: Dict[str, int] = defaultdict(int)

    def run_one(self, op_name: str, mutation: str,
                timeout: float = 10.0) -> Dict[str, Any]:
        import http.client
        import json as _json

        results = {}
        method = None
        path = None
        body = None

        self.total_tests += 1
        self.op_tests[op_name] += 1

        for target, (host, port) in self.endpoints.items():
            try:
                method, path, body = self.build_fn(op_name, mutation)

                body_bytes = None
                if body is not None:
                    if isinstance(body, dict):
                        body_bytes = _json.dumps(body).encode()
                    elif isinstance(body, bytes):
                        body_bytes = body
                    elif isinstance(body, str):
                        body_bytes = body.encode()

                if port == 7777:
                    import subprocess, tempfile
                    headers_str = ""
                    if body_bytes:
                        tf = tempfile.NamedTemporaryFile(delete=False)
                        tf.write(body_bytes)
                        tf.close()
                        r = subprocess.run(
                            ['curl', '-s', '-w', '\n%{http_code}',
                             '--http2-prior-knowledge',
                             '-X', method,
                             f'http://{host}:{port}{path}',
                             '-H', 'Content-Type: application/json',
                             '-H', 'Accept: */*',
                             '-d', f'@{tf.name}'],
                            capture_output=True, text=True, timeout=timeout)
                        import os
                        os.unlink(tf.name)
                    else:
                        r = subprocess.run(
                            ['curl', '-s', '-w', '\n%{http_code}',
                             '--http2-prior-knowledge',
                             '-X', method,
                             f'http://{host}:{port}{path}',
                             '-H', 'Accept: */*'],
                            capture_output=True, text=True, timeout=timeout)
                    lines = r.stdout.strip().split('\n')
                    resp_body = '\n'.join(lines[:-1])
                    status = int(lines[-1]) if lines[-1].isdigit() else 0
                    results[target] = {"status": status, "body": resp_body[:500]}
                else:
                    conn = http.client.HTTPConnection(host, port, timeout=timeout)
                    headers = {"Accept": "*/*", "User-Agent": "diff-fuzzer/1.0"}
                    if body_bytes:
                        headers["Content-Type"] = "application/json"
                    conn.request(method, path, body=body_bytes, headers=headers)
                    resp = conn.getresponse()
                    resp_body = resp.read()
                    results[target] = {
                        "status": resp.status,
                        "body": resp_body[:500].decode("utf-8", errors="replace")}
                    conn.close()
            except Exception as e:
                results[target] = {"status": 0, "error": str(e)}

        statuses = {t: r.get("status", 0) for t, r in results.items()}
        unique_statuses = set(statuses.values())
        divergent = len(unique_statuses) > 1

        reason = ""
        if divergent:
            if 0 in unique_statuses:
                reason = "crash_vs_alive"
            else:
                has_5xx = any(s >= 500 for s in unique_statuses)
                has_4xx = any(400 <= s < 500 for s in unique_statuses)
                has_2xx = any(200 <= s < 300 for s in unique_statuses)
                if has_5xx and has_2xx:
                    reason = "success_vs_failure"
                elif has_4xx and has_2xx:
                    reason = "validation_diff"
                elif len(unique_statuses) >= 3:
                    reason = "all_different"
                else:
                    reason = "status_mismatch"

            self.total_divergences += 1
            self.op_divergence[op_name] += 1
            entry = {
                "time": time.time(),
                "op": op_name,
                "mutation": mutation,
                "method": method,
                "path": path,
                "statuses": statuses,
                "reason": reason,
            }
            self.divergences.append(entry)
            logger.warning("DIFF [%s]: %s %s -> %s",
                           reason, method, path,
                           {t: s for t, s in statuses.items()})

        return {
            "op": op_name, "mutation": mutation,
            "method": method, "path": path,
            "results": results,
            "divergent": divergent,
            "reason": reason,
        }

    def compute_pado_reward(self, results: Dict[str, Dict]) -> int:
        """Compute 5-tier PADO divergence reward from per-target results.

        Reward hierarchy (Eq. dgsm_reward):
        30: crash vs alive (any sigma=0 and any sigma>0)
        25: all three classes differ (max behavioral gap)
        15: class-level: 2 agree, 1 differs
         5: same class, different specific codes
         0: all three agree
        """
        statuses = {t: r.get("status", 0) for t, r in results.items()}

        if len(statuses) < 2:
            return 0

        status_vals = list(statuses.values())
        unique = set(status_vals)

        if len(unique) == 1:
            return 0

        # Check crash vs alive
        has_crash = any(s == 0 for s in status_vals)
        has_alive = any(s > 0 for s in status_vals)
        if has_crash and has_alive:
            return 30

        # Map to response classes
        classes = [s // 100 for s in status_vals]
        unique_classes = set(classes)

        # All three classes differ
        if len(unique_classes) >= 3:
            return 25

        # Exactly two classes differ (2-vs-1 pattern)
        if len(unique_classes) == 2:
            return 15

        # Same class but different specific codes
        return 5

    def get_divergence_rate(self) -> float:
        return self.total_divergences / max(self.total_tests, 1)

    def get_top_divergent_ops(self, n: int = 10) -> List[tuple]:
        ranked = sorted(self.op_divergence.items(),
                         key=lambda x: x[1], reverse=True)
        return [(op, count, self.op_tests.get(op, 0)) for op, count in ranked[:n]]

    def summary(self) -> dict:
        return {
            "total_tests": self.total_tests,
            "total_divergences": self.total_divergences,
            "divergence_rate": round(self.get_divergence_rate() * 100, 1),
            "top_divergent_ops": self.get_top_divergent_ops(5),
        }
