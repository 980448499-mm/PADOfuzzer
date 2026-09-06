#!/bin/bash
# G0-G7 Ablation Experiment Runner
# 8 groups × 3 targets = 24 experiments
# Each group incrementally adds one algorithmic innovation.
#
# Usage: bash scripts/ablation_g0_g7.sh [--hours 1] [--resume]
#
# Groups:
#   G0 = baseline (FSM=OFF, Cross=OFF, no algorithms)
#   G1 = +FSM
#   G2 = +MutationBandit
#   G3 = +MarkovModel
#   G4 = +MultiNF direct fuzzing
#   G5 = +CrossTargetMigrator
#   G6 = +SatDetector (crash-hunting)
#   G7 = full (FSM=ON, Cross=ON, all algorithms)

set -e

HOURS=1
RESUME=false
OUT_BASE="/home/mm/桌面/5g-fuzzer/results/ablation-g0-g7"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --hours) HOURS="$2"; shift 2 ;;
        --output) OUT_BASE="$2"; shift 2 ;;
        --resume) RESUME=true; shift ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

mkdir -p "$OUT_BASE"
PROJECT="/home/mm/桌面/5g-fuzzer"

# ─── Group definitions ─────────────────────────────────────────────
# Format: "group_name fsm cross_protocol novel_flags multi_nf description"
# G6 uses diff fuzz script instead of live_fuzz

declare -A GROUPS
GROUPS[G0]="G0 off off --no-novel no 基线:无FSM+无算法"
GROUPS[G1]="G1 on  off --no-novel no +FSM引导"
GROUPS[G2]="G2 on  off no        no +MutationBandit"
GROUPS[G3]="G3 on  off no        no +MarkovModel"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Ablation G0-G7  |  ${HOURS}h per experiment  |  24 total     ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

total=0
for group in G0 G1 G2 G3 G4 G5 G6 G7; do
    read -r name fsm xp novel multi desc <<< "${GROUPS[$group]}"
    [ -z "$name" ] && continue

    for target in free5gc oai open5gs; do
        total=$((total + 1))
        tag="${name}_${target}"
        dir="$OUT_BASE/$tag"

        if [ "$RESUME" = true ] && [ -f "$dir/done" ]; then
            echo "[$total/24] $tag — already done, skipping"
            continue
        fi

        mkdir -p "$dir"
        case "$target" in
            free5gc) SCRIPT="$PROJECT/scripts/live_fuzz_free5gc.py" ;;
            oai)     SCRIPT="$PROJECT/scripts/live_fuzz_oai.py" ;;
            open5gs) SCRIPT="$PROJECT/scripts/live_fuzz_open5gs.py" ;;
        esac

        ARGS="--hours $HOURS --output $dir"
        [ "$fsm" = "off" ] && ARGS="$ARGS --no-fsm"
        [ "$xp"  = "off" ] && ARGS="$ARGS --no-cross-protocol"
        [ "$novel" != "no" ] && ARGS="$ARGS $novel"

        nohup python3 "$SCRIPT" $ARGS > "$dir/stdout.log" 2>&1 &
        echo "[$total/24] $tag PID=$! — $desc"

        sleep 0.3  # stagger launches
    done
done

echo ""
echo "All $total experiments launched. Output: $OUT_BASE"
echo "Monitor: grep 'Coverage\|Batch' $OUT_BASE/*/stdout.log"
echo "Wait:    sleep ${HOURS}h"

# Write experiment manifest
cat > "$OUT_BASE/MANIFEST.txt" << EOF
Ablation G0-G7 experiment manifest
Started: $(date)
Duration: ${HOURS}h per experiment
Total experiments: $total

G0: baseline (FSM=OFF, no algorithms)
G1: +FSM guidance
G2: +MutationBandit
G3: +MarkovModel
G4: +MultiNF direct fuzzing  (Open5GS only, others unchanged)
G5: +CrossTargetMigrator
G6: +DifferentialFuzzer (separate script)
G7: full (FSM=ON, Cross=ON, all algorithms)
EOF