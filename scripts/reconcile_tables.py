#!/usr/bin/env python3
"""Reconcile Tables 5/6/9 of the PADOfuzzer manuscript against source logs.

Reads results/experiment_v2/<target>/<target>_<group>.json and prints the
requests / crashes / regret values that actually exist in the logs, so the
paper's tables can be rebuilt from a single, consistent data source.

The paper's "crashes" column is, in the code, the count of requests whose
primary-target HTTP status was 0 (timeout / connection refusal / process
crash) — see scripts/experiment_v2_launcher.py `is_crash = (code == 0)`.
This script reports that raw value and flags it so the definitional issue is
visible rather than silently conflated with process-level SIGABRT/SIGSEGV.

Usage: python3 scripts/reconcile_tables.py [--json out.json]
"""

import argparse
import json
import os
from pathlib import Path
from typing import Dict, List, Optional

BASE = Path("results/experiment_v2")
OLD_BASE = Path("results/experiment_v2_old")  # original (pre-PADO-fix) data

# The five representative targets used in Tables 5/6/9 of the paper.
TABLE_TARGETS = [
    "free5gc-amf",
    "oai-nrf",
    "open5gs-amf",
    "open5gs-ausf",
    "open5gs-udm",
]

# Code ablation groups (experiment_v2_launcher.py): G0 random, G1 SW-UCB,
# G2 SW-UCB+PADO (PEDB removed), G3 +CrashReset (no-op), G4 +MTShare,
# G5 +activeQuery (no-op).
GROUPS = ["G0", "G1", "G2", "G3", "G4", "G5"]

# Component-removal variants. The paper calls these "G2-noJKSM"/"G2-noPADO".
# The re-run writes {target}_G2_nojksm.json / {target}_G2_nopado.json; the
# original (pre-PADO-fix) data used the legacy code names G4_nojksm/G4_nopado.
VARIANTS = ["G2_nojksm", "G2_nopado"]
VARIANT_ALIASES = {
    "G2_nojksm": ["G2_nojksm", "G4_nojksm"],
    "G2_nopado": ["G2_nopado", "G4_nopado"],
}

BASELINES = ["aflnet", "stateafl", "schemathesis", "boofuzz"]

# New-data groups produced by the re-run (PADO fix).
NEW_GROUPS = ["G2", "G2_nojksm", "G2_nopado"]


CORRUPT: List[str] = []


def load(target: str, group: str) -> Optional[dict]:
    """Load from the new (re-run) base first, then fall back to the old base.

    Variant groups (G2_nojksm / G2_nopado) resolve to the re-run's G2_* filename
    first, then the legacy G4_* filename (original pre-PADO-fix data).
    """
    names = VARIANT_ALIASES.get(group, [group])
    for base in (BASE, OLD_BASE):
        for name in names:
            path = base / target / f"{target}_{name}.json"
            if not path.exists():
                continue
            try:
                with open(path) as f:
                    return json.load(f)
            except (json.JSONDecodeError, UnicodeDecodeError, OSError) as e:
                CORRUPT.append(f"{target}/{group}: {type(e).__name__}")
                return None
    return None


def regret_final(d: dict) -> Optional[float]:
    rc = d.get("regret_curve") or []
    if not rc:
        return None
    last = rc[-1]
    if isinstance(last, dict):
        return last.get("regret")
    return None


def fmt_int(n: Optional[int]) -> str:
    if n is None:
        return "-"
    return f"{n:,}"


def fmt_float(n: Optional[float], digits: int = 1) -> str:
    if n is None:
        return "-"
    return f"{n:,.{digits}f}"


def k(n: Optional[float]) -> str:
    """Human-friendly thousands/Millions."""
    if n is None:
        return "-"
    if n >= 1_000_000:
        return f"{n/1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n/1_000:.1f}K"
    return f"{n:.0f}"


def row(target: str, group: str) -> Optional[dict]:
    d = load(target, group)
    if d is None:
        return None
    reqs = d.get("requests")
    crashes = d.get("crashes")
    reg = regret_final(d)
    return {
        "target": target,
        "group": group,
        "reqs": reqs,
        "crashes": crashes,
        "regret": reg,
        "div": d.get("cross_divergences"),
        "crash_per_1k": (crashes / reqs * 1000) if reqs else None,
        "regret_per_req": (reg / reqs) if (reg is not None and reqs) else None,
        "impossible": crashes is not None and reqs is not None and crashes > reqs,
    }


def print_master(targets: List[str]) -> None:
    print("=" * 100)
    print("MASTER TABLE — every group × target (requests / crashes / regret / divergence)")
    print("=" * 100)
    header = f"{'target':<14} {'group':<13} {'reqs':>12} {'crashes':>11} {'regret':>13} {'div':>10} {'crash/1K':>9} {'regret/req':>10} {'impossible':>11}"
    print(header)
    print("-" * 100)
    for t in targets:
        for g in GROUPS + VARIANTS:
            r = row(t, g)
            if r is None:
                continue
            imp = "  <-- !" if r["impossible"] else ""
            print(f"{r['target']:<14} {r['group']:<13} {r['reqs']:>12,} "
                  f"{r['crashes']:>11,} {fmt_float(r['regret']):>13} "
                  f"{str(r['div']):>10} {fmt_float(r['crash_per_1k']):>9} "
                  f"{fmt_float(r['regret_per_req'], 3):>10} {imp}")
        for b in BASELINES:
            r = row(t, f"baseline_{b}")
            if r is None:
                continue
            print(f"{r['target']:<14} {('base_'+b):<13} {r['reqs']:>12,} "
                  f"{r['crashes']:>11,} {'-':>13} {'-':>10} "
                  f"{fmt_float(r['crash_per_1k']):>9} {'-':>10}")
        print("-" * 100)


def print_table5(targets: List[str]) -> None:
    """Reconstructed Table 5 (component-removal ablation)."""
    print("\n" + "=" * 100)
    print("TABLE 5 (reconstructed) — Component-removal ablation, 24h")
    print("G2 = full system (SW-UCB + PADO); G2-noJKSM; G2-noPADO")
    print("=" * 100)
    print(f"{'target':<14} {'G2 reqs':>10} {'G2 cr':>8} | {'noJKSM reqs':>12} {'noJKSM cr':>9} | {'noPADO reqs':>12} {'noPADO cr':>9}")
    print("-" * 100)
    for t in targets:
        g2 = row(t, "G2")
        noj = row(t, "G2_nojksm")
        nop = row(t, "G2_nopado")
        print(f"{t:<14} {k(g2['reqs']):>10} {fmt_int(g2['crashes']):>8} | "
              f"{k(noj['reqs'] if noj else None):>12} {fmt_int(noj['crashes'] if noj else None):>9} | "
              f"{k(nop['reqs'] if nop else None):>12} {fmt_int(nop['crashes'] if nop else None):>9}")


def print_table6(targets: List[str]) -> None:
    """Reconstructed Table 6 (ablation results)."""
    print("\n" + "=" * 100)
    print("TABLE 6 (reconstructed) — Ablation: requests / crashes / regret, 24h")
    print("=" * 100)
    for metric, key in [("Requests Sent", "reqs"), ("Crashes", "crashes"), ("Regret (final)", "regret")]:
        print(f"\n--- {metric} ---")
        hdr = f"{'group':<5} " + "".join(f"{t:>14}" for t in targets)
        print(hdr)
        for g in GROUPS:
            cells = []
            for t in targets:
                r = row(t, g)
                if r is None:
                    cells.append("-")
                elif key == "reqs":
                    cells.append(f"{r['reqs']:>14,}")
                elif key == "crashes":
                    cells.append(f"{r['crashes']:>14,}")
                else:
                    cells.append(f"{fmt_float(r['regret']):>14}")
            print(f"{g:<5} " + "".join(cells))


def print_table9(targets: List[str]) -> None:
    """Reconstructed Table 9 (external baseline comparison)."""
    print("\n" + "=" * 100)
    print("TABLE 9 (reconstructed) — External baseline vs G2 (24h), crash/1K")
    print("=" * 100)
    for t in targets:
        print(f"\n{t}")
        print(f"{'fuzzer':<14} {'reqs':>12} {'crashes':>11} {'crash/1K':>9}")
        r = row(t, "G2")
        if r:
            print(f"{'G2 (Ours)':<14} {r['reqs']:>12,} {r['crashes']:>11,} {fmt_float(r['crash_per_1k']):>9}")
        for b in BASELINES:
            r = row(t, f"baseline_{b}")
            if r:
                print(f"{b:<14} {r['reqs']:>12,} {r['crashes']:>11,} {fmt_float(r['crash_per_1k']):>9}")


def print_honest_analysis(targets: List[str]) -> None:
    """Honest metrics: divergence rate, security-relevant %, and the ablation
    contribution (PADO = G2 vs G2-noPADO; JKSM = G2 vs G2-noJKSM). G2-noPADO is
    `--group G2 --disable-pado` (SW-UCB, no PADO); G2-noJKSM is
    `--group G2 --disable-jksm`."""
    print("\n" + "=" * 100)
    print("HONEST ANALYSIS — divergence rate + regret decomposition")
    print("=" * 100)

    # 1. Divergence rate + security-relevant % from the re-run G2 data.
    tot_req = tot_div = 0
    reason = {}
    for t in targets:
        d = load(t, "G2")
        if d is None:
            continue
        tot_req += d.get("requests", 0) or 0
        tot_div += d.get("cross_divergences", 0) or 0
        for r, c in (d.get("divergence_reason_counter") or {}).items():
            reason[r] = reason.get(r, 0) + c
    div_rate = tot_div / tot_req * 100 if tot_req else 0
    sec_relevant = sum(c for r, c in reason.items()
                       if r in ("crash_vs_alive", "validation_diff"))
    all_reason = sum(reason.values())
    print(f"G2 divergence rate (re-run, note reference-dispatch caveat): {div_rate:.2f}% "
          f"({tot_div:,}/{tot_req:,})")
    print(f"G2 divergence reason distribution: {reason}")
    if all_reason:
        print(f"G2 security-relevant (crash_vs_alive + validation_diff): "
              f"{sec_relevant/all_reason*100:.1f}% ({sec_relevant:,}/{all_reason:,})")
    else:
        print("G2 security-relevant %: n/a (divergence_reason_counter empty)")

    # 2. Ablation contribution: PADO = G2 vs G2-noPADO; JKSM = G2 vs G2-noJKSM.
    print("\nAblation contribution (regret): PADO = G2 vs G2-noPADO, JKSM = G2 vs G2-noJKSM")
    print(f"{'target':<14} {'G2 regret':>12} {'noPADO':>12} {'PADO red.':>11} "
          f"{'noJKSM':>12} {'JKSM red.':>11}")
    print("-" * 100)
    for t in targets:
        g2 = row(t, "G2")
        nop = row(t, "G2_nopado")
        noj = row(t, "G2_nojksm")
        if g2 is None or g2["regret"] is None:
            print(f"{t:<14}  (missing G2)")
            continue
        g2r = g2["regret"]
        nopr = nop["regret"] if nop else None
        nojr = noj["regret"] if noj else None
        pado_red = (g2r - nopr) / g2r * 100 if nopr else None
        jksm_red = (g2r - nojr) / g2r * 100 if nojr else None
        pado_s = f"{pado_red:>10.1f}%" if pado_red is not None else "         -"
        jksm_s = f"{jksm_red:>10.1f}%" if jksm_red is not None else "         -"
        print(f"{t:<14} {fmt_float(g2r):>12} {fmt_float(nopr):>12} {pado_s} "
              f"{fmt_float(nojr):>12} {jksm_s}")
    print("\nNote: positive reduction = removing the component increases regret,")
    print("so the component contributes to learning. The pre-PEDB-removal CondTS")
    print("comparison used the legacy G4_nopado (CondTS) data and showed CondTS was")
    print("WORSE than SW-UCB — the reason PEDB was removed (see response letter).")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", type=str, default=None, help="also dump full JSON to path")
    args = ap.parse_args()

    print_master(TABLE_TARGETS)
    print_table5(TABLE_TARGETS)
    print_table6(TABLE_TARGETS)
    print_table9(TABLE_TARGETS)
    print_honest_analysis(TABLE_TARGETS)

    # Full sweep: aggregate per group across every per-NF target directory.
    # Excludes the aggregate dirs "free5gc"/"oai" and "logs" (not single NFs).
    all_targets = sorted(
        d.name for d in BASE.iterdir()
        if d.is_dir() and d.name not in ("logs", "free5gc", "oai")
        and any(f.name.endswith("_G2.json") for f in d.iterdir())
    )
    print("\n" + "=" * 100)
    print(f"FULL SWEEP — {len(all_targets)} per-NF target dirs, aggregate per group")
    print("=" * 100)
    print(f"{'group':<6} {'targets':>8} {'total reqs':>13} {'total crashes':>14} {'sum regret':>13}")
    for g in GROUPS:
        tr = tc = 0
        n = 0
        sreg = 0.0
        for t in all_targets:
            r = row(t, g)
            if r and r["reqs"] is not None:
                n += 1
                tr += r["reqs"]
                tc += r["crashes"] or 0
                if r["regret"] is not None:
                    sreg += r["regret"]
        print(f"{g:<6} {n:>8} {tr:>13,} {tc:>14,} {fmt_float(sreg):>13}")

    if CORRUPT:
        print("\n" + "=" * 100)
        print("CORRUPTED / TRUNCATED LOG FILES (skipped):")
        for c in CORRUPT:
            print("  " + c)

    if args.json:
        out = {t: {g: row(t, g) for g in GROUPS + VARIANTS
                   + [f"baseline_{b}" for b in BASELINES]}
               for t in TABLE_TARGETS}
        Path(args.json).write_text(json.dumps(out, indent=2, default=str))
        print(f"\nSaved JSON to {args.json}")


if __name__ == "__main__":
    main()
