#!/bin/bash
# Collect coverage snapshots from all 3 targets every 2 hours
TS=$(date +%Y%m%d_%H%M%S)
COV_DIR="/home/mm/桌面/5g-fuzzer/results/experiment_v2/coverage"
mkdir -p "$COV_DIR"

# free5GC — Go cover (live counters, no process restart needed)
echo "[$TS] Collecting free5GC Go cover..."
for nf in nrf amf smf ausf udm udr pcf nssf; do
    docker cp "fuzzing-free5gc-${nf}:/go/cover" "$COV_DIR/free5gc_${nf}_${TS}" 2>/dev/null
done

# OAI — gcov
echo "[$TS] Collecting OAI gcov..."
docker exec fuzzing-oai-nrf bash -c "cd /oai-nrf/build && gcov -r *.o 2>/dev/null | tail -1" > "$COV_DIR/oai_nrf_${TS}.gcov" 2>/dev/null

# Open5GS — gcov
echo "[$TS] Collecting Open5GS gcov..."
for nf in nrf ausf udr amf; do
    docker exec "fuzzing-open5gs-${nf}" bash -c "cd /open5gs && gcov -r build/**/*.o 2>/dev/null | tail -1" > "$COV_DIR/open5gs_${nf}_${TS}.gcov" 2>/dev/null
done

echo "[$TS] Coverage snapshot saved to $COV_DIR"