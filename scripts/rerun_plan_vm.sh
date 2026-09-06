#!/usr/bin/env bash
# Per-VM re-run plan (partitioned by implementation).
#
# Each VM runs a FULL 5GC deployment (free5GC + OAI + Open5GS) at the standard
# 172.24.0.x / 172.25.0.x / 172.23.0.x IPs, and fuzzes ONE implementation as
# the primary target. The other two implementations serve only as PADO
# references (never fuzzed as primary on this VM), so references stay clean.
#
# Because each VM has its own containers, the three implementations of the
# same NF no longer overlap: the single-machine "same-NF must be sequential"
# constraint disappears. Within a VM, different NF types run in parallel.
#
# Re-run scope: G2 (full system) + G2-noJKSM, for every target.
# NOT re-run: G0, G1, G2-noPADO, external baselines (PADO bug does not affect them).
#
# Usage (one VM each):
#   VM=1 bash scripts/rerun_plan_vm.sh   # free5gc targets (8)
#   VM=2 bash scripts/rerun_plan_vm.sh   # oai targets     (8)
#   VM=3 bash scripts/rerun_plan_vm.sh   # open5gs targets (9)
#
# Options:
#   DRY_RUN=1      print commands only
#   ISOLATE_NRF=1  (default) run this VM's NRF last -> ~4 days/VM
#   ISOLATE_NRF=0  run NRF in parallel       -> ~2 days/VM (accepts re-register risk)

set -uo pipefail
cd "$(dirname "$0")/.."

VM="${VM:-1}"
HOURS="${HOURS:-24}"
DRY_RUN="${DRY_RUN:-0}"
ISOLATE_NRF="${ISOLATE_NRF:-1}"
RESULTS_DIR="${RESULTS_DIR:-$HOME/桌面/5g-fuzzer/results/experiment_v2}"

log() { echo "[$(date '+%F %T')] VM$VM $*"; }

run_target() {
    local target="$1"

    if [ -f "$RESULTS_DIR/${target}/${target}_G2.json" ]; then
        log "SKIP (已完成) G2 $target"
    else
        log "START G2        $target"
        if [ "$DRY_RUN" = "1" ]; then
            echo "  python3 scripts/experiment_v2_launcher.py --target $target --group G2 --hours $HOURS"
        else
            python3 scripts/experiment_v2_launcher.py --target "$target" --group G2 --hours "$HOURS"
        fi
        log "DONE  G2        $target"
    fi

    if [ -f "$RESULTS_DIR/${target}/${target}_G2_nojksm.json" ]; then
        log "SKIP (已完成) G2-noJKSM $target"
    else
        log "START G2-noJKSM $target"
        if [ "$DRY_RUN" = "1" ]; then
            echo "  python3 scripts/experiment_v2_launcher.py --target $target --group G2 --disable-jksm --hours $HOURS"
        else
            python3 scripts/experiment_v2_launcher.py --target "$target" --group G2 --disable-jksm --hours "$HOURS"
        fi
        log "DONE  G2-noJKSM $target"
    fi

    if [ -f "$RESULTS_DIR/${target}/${target}_G2_nopado.json" ]; then
        log "SKIP (已完成) G2-noPADO $target"
    else
        log "START G2-noPADO $target"
        if [ "$DRY_RUN" = "1" ]; then
            echo "  python3 scripts/experiment_v2_launcher.py --target $target --group G2 --disable-pado --hours $HOURS"
        else
            python3 scripts/experiment_v2_launcher.py --target "$target" --group G2 --disable-pado --hours "$HOURS"
        fi
        log "DONE  G2-noPADO $target"
    fi
}

# ── Per-VM target lists (implementation partition) ─────────────
case "$VM" in
    1) NRF=free5gc-nrf
       TARGETS=(free5gc-amf free5gc-smf free5gc-ausf free5gc-udm free5gc-udr free5gc-pcf free5gc-nssf) ;;
    2) NRF=oai-nrf
       TARGETS=(oai-amf oai-smf oai-ausf oai-udm oai-udr oai-nssf oai-pcf) ;;
    3) NRF=open5gs-nrf
       TARGETS=(open5gs-amf open5gs-smf open5gs-ausf open5gs-udm open5gs-udr open5gs-nssf open5gs-bsf open5gs-scp) ;;
    *) echo "VM must be 1, 2, or 3" >&2; exit 1 ;;
esac

log "NRF=$NRF  targets(${#TARGETS[@]}): ${TARGETS[*]}"

if [ "$ISOLATE_NRF" = "1" ]; then
    # Non-NRF targets in parallel, then NRF last.
    for t in "${TARGETS[@]}"; do
        run_target "$t" &
    done
    wait
    log "=== NRF phase (isolated) ==="
    run_target "$NRF"
else
    # Everything in parallel (NRF included).
    for t in "${TARGETS[@]}"; do
        run_target "$t" &
    done
    run_target "$NRF" &
    wait
fi

log "ALL DONE (VM$VM)"
