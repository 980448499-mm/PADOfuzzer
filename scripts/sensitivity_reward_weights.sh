#!/usr/bin/env bash
# Reward-weight sensitivity analysis (short 2h G2 runs).
# Runs 4 weight settings on 3 crash-prone targets (open5gs-nrf, open5gs-scp, open5gs-udm).
# Three targets run in parallel; the 4 weight settings run sequentially per target.
#
#   wA = baseline      30,25,15,5,0
#   wB = scale-up      60,50,30,10,0
#   wC = compress      10,5,3,1,0
#   wD = break-order   0,25,15,5,30
#
# Usage:  HOURS=2 SEED=42 bash scripts/sensitivity_reward_weights.sh

set -uo pipefail
cd "$(dirname "$0")/.."

HOURS="${HOURS:-2}"
SEED="${SEED:-42}"

declare -A WEIGHTS=(
  [wA]="30,25,15,5,0"
  [wB]="60,50,30,10,0"
  [wC]="10,5,3,1,0"
  [wD]="0,25,15,5,30"
)

run_target() {
    local t="$1"
    for w in wA wB wC wD; do
        echo "[$(date '+%F %T')] $t $w weights=${WEIGHTS[$w]}"
        python3 scripts/experiment_v2_launcher.py \
            --target "$t" --group G2 --hours "$HOURS" \
            --reward-weights "${WEIGHTS[$w]}" --tag "$w" --seed "$SEED"
        echo "[$(date '+%F %T')] $t $w DONE"
    done
}

run_target open5gs-nrf &
run_target open5gs-scp &
run_target open5gs-udm &
wait

echo "[$(date '+%F %T')] ALL DONE"
