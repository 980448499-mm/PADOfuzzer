#!/bin/bash
# Full parallel experiment: 6 ablation groups + 4 baselines across all 7 targets
set -e

HOURS=${1:-1}
MAX_PARALLEL=${2:-8}

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

LAUNCHER="python3 scripts/experiment_v2_launcher.py"
OUTDIR="results/experiment_v2"
LOGDIR="results/experiment_v2/logs"
mkdir -p "$LOGDIR"

total=0

echo "=== Full Experiment: ${HOURS}h per trial, max ${MAX_PARALLEL} parallel ==="
echo ""

# Ablation groups
for target in free5gc oai open5gs-ausf open5gs-udr open5gs-amf open5gs-udm open5gs-scp; do
    for group in "G0" "G1" "G2" "G3" "G4" "G5"; do
        while [ $(jobs -r | wc -l) -ge $MAX_PARALLEL ]; do
            sleep 5
        done
        LOG="$LOGDIR/${target}_${group}.log"
        echo "[$((total+1))/70] Launching: ${target} ${group}"
        $LAUNCHER --target "$target" --group "$group" --hours "$HOURS" --baseline none > "$LOG" 2>&1 &
        total=$((total + 1))
    done
done

# Baselines
for target in free5gc oai open5gs-ausf open5gs-udr open5gs-amf open5gs-udm open5gs-scp; do
    for baseline in aflnet stateafl schemathesis boofuzz; do
        while [ $(jobs -r | wc -l) -ge $MAX_PARALLEL ]; do
            sleep 5
        done
        LOG="$LOGDIR/${target}_baseline_${baseline}.log"
        echo "[$((total+1))/70] Launching: ${target} baseline_${baseline}"
        $LAUNCHER --target "$target" --group none --baseline "$baseline" --hours "$HOURS" > "$LOG" 2>&1 &
        total=$((total + 1))
    done
done

echo ""
echo "=== All $total experiments launched. Waiting... ==="
wait
echo "=== DONE! Results in $OUTDIR ==="
