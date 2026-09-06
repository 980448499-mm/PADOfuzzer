#!/usr/bin/env bash
# Re-run plan after the PADO reference-target bug fix.
#
# What is re-run: G2 (full system) + G2-noJKSM, for all 25 targets.
# What is NOT re-run: G0, G1, G2-noPADO, and the four external baselines
#   (they do not use the PADO 3-way reward, so the bug does not affect them).
#
# Parallelism constraint (post-fix):
#   - PADO now compares the SAME NF across free5gc/OAI/Open5GS, so two
#     fuzzers targeting the same NF type hammer the same three containers
#     and corrupt each other's divergence signal. => same NF type = SEQUENTIAL.
#   - Different NF types use disjoint containers. => PARALLEL across NF types.
#   - NRF is the registry; crashing it disrupts NFs of the same implementation
#     that re-register after a restart. By default NRF runs last (isolated).
#
# Wall-clock estimate (24h/task):
#   - ISOLATE_NRF=1 (default): ~6 days (non-NRF) + ~6 days (NRF) = ~12 days
#   - ISOLATE_NRF=0           : ~6 days (all NF types in parallel; NRF runs
#                               alongside cross-implementation NFs)
#
# Usage:
#   DRY_RUN=1 bash scripts/rerun_plan.sh     # print commands only
#   bash scripts/rerun_plan.sh               # run for real

set -uo pipefail
cd "$(dirname "$0")/.."

HOURS="${HOURS:-24}"
DRY_RUN="${DRY_RUN:-0}"
ISOLATE_NRF="${ISOLATE_NRF:-1}"

log() { echo "[$(date '+%F %T')] $*"; }

run_target() {
    local target="$1"
    log "START G2        $target"
    if [ "$DRY_RUN" = "1" ]; then
        echo "  python3 scripts/experiment_v2_launcher.py --target $target --group G2 --hours $HOURS"
    else
        python3 scripts/experiment_v2_launcher.py --target "$target" --group G2 --hours "$HOURS"
    fi
    log "DONE  G2        $target"

    log "START G2-noJKSM $target"
    if [ "$DRY_RUN" = "1" ]; then
        echo "  python3 scripts/experiment_v2_launcher.py --target $target --group G2 --disable-jksm --hours $HOURS"
    else
        python3 scripts/experiment_v2_launcher.py --target "$target" --group G2 --disable-jksm --hours "$HOURS"
    fi
    log "DONE  G2-noJKSM $target"
}

# One worker = one NF type. Its targets run SEQUENTIALLY (same-NF PADO overlap).
worker() {
    local nf="$1"; shift
    log "worker $nf START"
    for t in "$@"; do
        run_target "$t"
    done
    log "worker $nf DONE"
}

# ── Launch one worker per NF type, in parallel ─────────────────────
if [ "$ISOLATE_NRF" = "1" ]; then
    worker amf  free5gc-amf  oai-amf  open5gs-amf &
    worker smf  free5gc-smf  oai-smf  open5gs-smf &
    worker ausf free5gc-ausf oai-ausf open5gs-ausf &
    worker udm  free5gc-udm  oai-udm  open5gs-udm &
    worker udr  free5gc-udr  oai-udr  open5gs-udr &
    worker pcf  free5gc-pcf  oai-pcf &
    worker nssf free5gc-nssf oai-nssf open5gs-nssf &
    worker bsf  open5gs-bsf &
    worker scp  open5gs-scp &
    wait
    # NRF last (registry).
    worker nrf free5gc-nrf oai-nrf open5gs-nrf
else
    worker amf  free5gc-amf  oai-amf  open5gs-amf &
    worker smf  free5gc-smf  oai-smf  open5gs-smf &
    worker ausf free5gc-ausf oai-ausf open5gs-ausf &
    worker udm  free5gc-udm  oai-udm  open5gs-udm &
    worker udr  free5gc-udr  oai-udr  open5gs-udr &
    worker pcf  free5gc-pcf  oai-pcf &
    worker nssf free5gc-nssf oai-nssf open5gs-nssf &
    worker bsf  open5gs-bsf &
    worker scp  open5gs-scp &
    worker nrf  free5gc-nrf  oai-nrf  open5gs-nrf &
    wait
fi

log "ALL DONE"
