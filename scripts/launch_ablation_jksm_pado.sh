#!/bin/bash
# Launch G5 (no JKSM) and G6 (no PADO) ablation trials
# 25 targets × 2 groups = 50 trials × 24h

LAUNCHER="/home/mm/桌面/5g-fuzzer/scripts/experiment_v2_launcher.py"
LOG_DIR="/tmp/ablation_v3"

mkdir -p "$LOG_DIR"

TARGETS=(
    "free5gc-nrf" "free5gc-amf" "free5gc-smf" "free5gc-ausf"
    "free5gc-udm" "free5gc-udr" "free5gc-pcf" "free5gc-nssf"
    "oai-nrf" "oai-amf" "oai-ausf" "oai-smf" "oai-udm" "oai-udr" "oai-nssf" "oai-pcf"
    "open5gs-nrf" "open5gs-amf" "open5gs-smf" "open5gs-ausf" "open5gs-udm"
    "open5gs-udr" "open5gs-nssf" "open5gs-bsf" "open5gs-scp"
)

echo "Launching G5 (no JKSM) + G6 (no PADO) = 50 trials"

for t in "${TARGETS[@]}"; do
    # G5: Full system without JKSM
    nohup python3 "$LAUNCHER" --target "$t" --group G4 --disable-jksm --hours 24 \
        > "$LOG_DIR/${t}_G5_nojksm.log" 2>&1 &

    # G6: Full system without PADO  
    nohup python3 "$LAUNCHER" --target "$t" --group G4 --disable-pado --hours 24 \
        > "$LOG_DIR/${t}_G6_nopado.log" 2>&1 &

    echo "  Launched: $t (G5 + G6)"
done

echo "Done. 50 trials running. Monitor: tail -f $LOG_DIR/*.log"
