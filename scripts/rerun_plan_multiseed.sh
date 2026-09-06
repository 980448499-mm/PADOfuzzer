#!/usr/bin/env bash
# Multi-seed re-run for variance: G1 (seeds 2,3) + G2 (seeds 2,3).
# Each target runs 4 seeds sequentially (same primary target => cannot overlap);
# different targets (different NF types) run in parallel.
#
# Seed 1 is the existing single-seed data (G1 from the original run, G2 from the
# current re-run). This script produces seeds 2 and 3 for G1 and G2.
#
# Usage (one VM each):
#   VM=1 bash scripts/rerun_plan_multiseed.sh   # free5gc (8 targets)
#   VM=2 bash scripts/rerun_plan_multiseed.sh   # oai     (8 targets)
#   VM=3 bash scripts/rerun_plan_multiseed.sh   # open5gs (9 targets)
#   DRY_RUN=1 ... to preview

set -uo pipefail
cd "$(dirname "$0")/.."

VM="${VM:-1}"
HOURS="${HOURS:-24}"
DRY_RUN="${DRY_RUN:-0}"
RESULTS_DIR="${RESULTS_DIR:-$HOME/桌面/5g-fuzzer/results/experiment_v2}"

log() { echo "[$(date '+%F %T')] VM$VM $*"; }

run_target() {
    local target="$1"
    for group in G1 G2; do
        for seed in 2 3; do
            local fn="$RESULTS_DIR/${target}/${target}_${group}_seed${seed}.json"
            if [ -f "$fn" ]; then
                log "SKIP (已完成) ${group}-seed${seed} $target"
                continue
            fi
            log "START ${group}-seed${seed} $target"
            if [ "$DRY_RUN" = "1" ]; then
                echo "  python3 scripts/experiment_v2_launcher.py --target $target --group $group --seed $seed --hours $HOURS"
            else
                python3 scripts/experiment_v2_launcher.py --target "$target" --group "$group" --seed "$seed" --hours "$HOURS"
            fi
            log "DONE  ${group}-seed${seed} $target"
        done
    done
}

case "$VM" in
    1) TARGETS=(free5gc-nrf free5gc-amf free5gc-smf free5gc-ausf free5gc-udm free5gc-udr free5gc-pcf free5gc-nssf) ;;
    2) TARGETS=(oai-nrf oai-amf oai-smf oai-ausf oai-udm oai-udr oai-nssf oai-pcf) ;;
    3) TARGETS=(open5gs-nrf open5gs-amf open5gs-smf open5gs-ausf open5gs-udm open5gs-udr open5gs-nssf open5gs-bsf open5gs-scp) ;;
    *) echo "VM must be 1,2,3" >&2; exit 1 ;;
esac

log "multi-seed targets(${#TARGETS[@]}): ${TARGETS[*]}"

for t in "${TARGETS[@]}"; do
    run_target "$t" &
done
wait

log "ALL DONE (VM$VM)"
