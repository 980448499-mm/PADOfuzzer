"""Statistical analysis of experiment results.

Validates paper hypotheses:
  H1: State-aware mutation finds more unique crashes than structure-agnostic
      (compare ours_full vs aflnet_like)
  H2: Cross-protocol injection finds bugs missed by single-protocol fuzzing
      (compare ours_full vs ours_no_cross_protocol)
  H3: FSM guidance improves state coverage
      (compare ours_full vs ours_no_fsm)
  H4: Multi-5GC testing reveals implementation-specific vulnerabilities
      (crashes unique to each 5GC implementation)
"""

import json
import logging
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from scipy import stats

from src.experiments.runner import ExperimentResult

logger = logging.getLogger(__name__)


class ResultAnalyzer:
    """Statistical analysis of experimental results.

    Uses:
      - Mann-Whitney U test for crash count comparisons
      - Effect size (Cohen's d) for practical significance
      - Coverage growth curve fitting: y = a - b * e^(-c * x)
    """

    def __init__(self, results: Optional[List[ExperimentResult]] = None):
        self.results = results or []
        self._by_config: Dict[str, List[ExperimentResult]] = defaultdict(list)
        self._by_target: Dict[str, List[ExperimentResult]] = defaultdict(list)

        for r in self.results:
            self._by_config[r.config_name].append(r)
            self._by_target[r.target.value].append(r)

    def load_from_dir(self, results_dir: Path) -> None:
        """Load all experiment results from a directory."""
        for json_file in results_dir.rglob("*.json"):
            try:
                with open(json_file) as f:
                    data = json.load(f)

                from src import FiveGCImpl
                result = ExperimentResult(
                    config_name=data["config_name"],
                    target=FiveGCImpl(data["target"]),
                    run_id=data["run_id"],
                    start_time=data["start_time"],
                    end_time=data["end_time"],
                    total_iterations=data["total_iterations"],
                    unique_crashes=data["unique_crashes"],
                    total_crashes=data["total_crashes"],
                    edges_covered=data["edges_covered"],
                    strategy_stats=data.get("strategy_stats", {}),
                    crash_details=data.get("crash_details", []),
                )
                self.results.append(result)
                self._by_config[result.config_name].append(result)
                self._by_target[result.target.value].append(result)
            except Exception as e:
                logger.debug(f"Failed to load {json_file}: {e}")

    # ─── Hypothesis testing ────────────────────────────────────

    def test_h1_state_aware_vs_aflnet(self) -> Dict[str, Any]:
        """H1: State-aware mutation (ours_full) finds more unique crashes
        than structure-agnostic fuzzing (aflnet_like)."""
        ours = self._by_config.get("ours_full", [])
        aflnet = self._by_config.get("aflnet_like", [])

        if not ours or not aflnet:
            return {"status": "insufficient_data"}

        ours_crashes = [r.unique_crashes for r in ours]
        aflnet_crashes = [r.unique_crashes for r in aflnet]

        # Mann-Whitney U test (non-parametric, suitable for crash counts)
        statistic, p_value = stats.mannwhitneyu(
            ours_crashes, aflnet_crashes, alternative="greater"
        )

        # Effect size (Cohen's d)
        d = self._cohens_d(ours_crashes, aflnet_crashes)

        return {
            "hypothesis": "H1: State-aware > AFLNet-like for unique crashes",
            "test": "Mann-Whitney U (one-sided)",
            "ours_mean": float(np.mean(ours_crashes)),
            "aflnet_mean": float(np.mean(aflnet_crashes)),
            "statistic": float(statistic),
            "p_value": float(p_value),
            "significant": bool(p_value < 0.05),
            "cohens_d": float(d),
            "effect_size": self._interpret_d(d),
        }

    def test_h2_cross_protocol(self) -> Dict[str, Any]:
        """H2: Cross-protocol injection finds bugs missed by single-protocol."""
        ours = self._by_config.get("ours_full", [])
        no_cross = self._by_config.get("ours_no_cross_protocol", [])

        if not ours or not no_cross:
            return {"status": "insufficient_data"}

        ours_crashes = [r.unique_crashes for r in ours]
        no_cross_crashes = [r.unique_crashes for r in no_cross]

        statistic, p_value = stats.mannwhitneyu(
            ours_crashes, no_cross_crashes, alternative="greater"
        )
        d = self._cohens_d(ours_crashes, no_cross_crashes)

        return {
            "hypothesis": "H2: Cross-protocol injection finds additional bugs",
            "test": "Mann-Whitney U (one-sided)",
            "ours_mean": float(np.mean(ours_crashes)),
            "no_cross_mean": float(np.mean(no_cross_crashes)),
            "statistic": float(statistic),
            "p_value": float(p_value),
            "significant": bool(p_value < 0.05),
            "cohens_d": float(d),
            "effect_size": self._interpret_d(d),
        }

    def test_h3_fsm_state_coverage(self) -> Dict[str, Any]:
        """H3: FSM guidance improves state coverage."""
        ours = self._by_config.get("ours_full", [])
        no_fsm = self._by_config.get("ours_no_fsm", [])

        if not ours or not no_fsm:
            return {"status": "insufficient_data"}

        ours_edges = [r.edges_covered for r in ours]
        no_fsm_edges = [r.edges_covered for r in no_fsm]

        statistic, p_value = stats.mannwhitneyu(
            ours_edges, no_fsm_edges, alternative="greater"
        )
        d = self._cohens_d(ours_edges, no_fsm_edges)

        return {
            "hypothesis": "H3: FSM guidance improves state/edge coverage",
            "test": "Mann-Whitney U (one-sided)",
            "ours_mean_edges": float(np.mean(ours_edges)),
            "no_fsm_mean_edges": float(np.mean(no_fsm_edges)),
            "statistic": float(statistic),
            "p_value": float(p_value),
            "significant": bool(p_value < 0.05),
            "cohens_d": float(d),
            "effect_size": self._interpret_d(d),
        }

    def test_h4_multi_impl(self) -> Dict[str, Any]:
        """H4: Multi-5GC testing reveals implementation-specific vulnerabilities."""
        crashes_per_target: Dict[str, set] = defaultdict(set)

        for r in self.results:
            for crash_detail in r.crash_details:
                crash_id = crash_detail.get("id", "")
                crashes_per_target[r.target.value].add(crash_id)

        # Compute target overlap
        targets = list(crashes_per_target.keys())
        overlap: Dict[str, Any] = {}

        if len(targets) >= 2:
            for i, t1 in enumerate(targets):
                for t2 in targets[i + 1:]:
                    s1 = crashes_per_target.get(t1, set())
                    s2 = crashes_per_target.get(t2, set())
                    shared = len(s1 & s2)
                    unique_to_t1 = len(s1 - s2)
                    unique_to_t2 = len(s2 - s1)
                    overlap[f"{t1}_vs_{t2}"] = {
                        f"{t1}_total": len(s1),
                        f"{t2}_total": len(s2),
                        "shared": shared,
                        f"unique_to_{t1}": unique_to_t1,
                        f"unique_to_{t2}": unique_to_t2,
                    }

        return {
            "hypothesis": "H4: Implementations have unique vulnerabilities",
            "crashes_per_target": {
                t: len(cs) for t, cs in crashes_per_target.items()
            },
            "overlap_analysis": overlap,
        }

    # ─── Coverage growth analysis ──────────────────────────────

    def fit_coverage_growth_curve(
        self, results: List[ExperimentResult]
    ) -> Dict[str, float]:
        """Fit exponential coverage growth curve: y = a - b * e^(-c * x).

        Returns (a, b, c, r_squared) where:
          a = asymptotic maximum coverage
          b = total growth
          c = growth rate
        """
        # Collect (time, edges) points
        points: List[Tuple[float, float]] = []
        for r in results:
            for t, edges in r.coverage_growth:
                points.append((t - r.start_time, float(edges)))

        if len(points) < 10:
            return {"a": 0, "b": 0, "c": 0, "r_squared": 0}

        x = np.array([p[0] for p in points], dtype=np.float64)
        y = np.array([p[1] for p in points], dtype=np.float64)

        # Initial guess
        a_guess = y[-1] * 1.1 if len(y) > 0 else 1000
        b_guess = a_guess - y[0] if len(y) > 0 else 500
        c_guess = 0.0001

        try:
            from scipy.optimize import curve_fit

            def model_func(x_val, a, b, c):
                return a - b * np.exp(-c * x_val)

            popt, _ = curve_fit(
                model_func, x, y,
                p0=[a_guess, b_guess, c_guess],
                maxfev=5000,
            )
            a, b, c = popt

            # Compute R-squared
            residuals = y - model_func(x, a, b, c)
            ss_res = np.sum(residuals**2)
            ss_tot = np.sum((y - np.mean(y))**2)
            r_squared = 1 - (ss_res / ss_tot) if ss_tot > 0 else 0

            return {"a": float(a), "b": float(b), "c": float(c),
                    "r_squared": float(r_squared)}
        except Exception:
            return {"a": 0, "b": 0, "c": 0, "r_squared": 0}

    def time_to_first_crash(self) -> Dict[str, float]:
        """Compute mean time to first crash for each configuration."""
        tfc: Dict[str, List[float]] = defaultdict(list)
        for r in self.results:
            for t, _, _ in r.crash_timeline:
                tfc[r.config_name].append(t - r.start_time)

        return {
            config: float(np.mean(times))
            for config, times in tfc.items() if times
        }

    # ─── Summary report ────────────────────────────────────────

    def generate_report(self) -> Dict[str, Any]:
        """Generate a comprehensive experiment report."""
        return {
            "overview": self._compute_overview(),
            "hypothesis_tests": {
                "h1": self.test_h1_state_aware_vs_aflnet(),
                "h2": self.test_h2_cross_protocol(),
                "h3": self.test_h3_fsm_state_coverage(),
                "h4": self.test_h4_multi_impl(),
            },
            "coverage_growth": self._compute_coverage_growth_summary(),
            "time_to_first_crash": self.time_to_first_crash(),
        }

    def _compute_overview(self) -> Dict[str, Any]:
        """Compute overview statistics."""
        total_results = len(self.results)
        total_crashes = sum(r.total_crashes for r in self.results)
        total_unique = sum(r.unique_crashes for r in self.results)
        total_iterations = sum(r.total_iterations for r in self.results)

        return {
            "total_experiment_runs": total_results,
            "total_iterations_across_all": total_iterations,
            "total_crashes_found": total_crashes,
            "total_unique_crashes": total_unique,
            "configurations_count": len(self._by_config),
            "targets_count": len(self._by_target),
        }

    def _compute_coverage_growth_summary(self) -> Dict[str, Any]:
        """Compute coverage growth analysis per configuration."""
        growth: Dict[str, Any] = {}
        for config_name, results in self._by_config.items():
            curve = self.fit_coverage_growth_curve(results)
            growth[config_name] = {
                "asymptotic_max_a": curve["a"],
                "total_growth_b": curve["b"],
                "growth_rate_c": curve["c"],
                "r_squared": curve["r_squared"],
            }
        return growth

    # ─── Helpers ──────────────────────────────────────────────

    @staticmethod
    def _cohens_d(group1: List[float], group2: List[float]) -> float:
        """Compute Cohen's d effect size."""
        n1, n2 = len(group1), len(group2)
        if n1 < 2 or n2 < 2:
            return 0.0
        s1 = np.std(group1, ddof=1)
        s2 = np.std(group2, ddof=1)
        pooled_sd = np.sqrt(((n1 - 1) * s1**2 + (n2 - 1) * s2**2) / (n1 + n2 - 2))
        if pooled_sd == 0:
            return 0.0
        return float((np.mean(group1) - np.mean(group2)) / pooled_sd)

    @staticmethod
    def _interpret_d(d: float) -> str:
        """Interpret Cohen's d effect size."""
        abs_d = abs(d)
        if abs_d < 0.2:
            return "negligible"
        elif abs_d < 0.5:
            return "small"
        elif abs_d < 0.8:
            return "medium"
        else:
            return "large"
