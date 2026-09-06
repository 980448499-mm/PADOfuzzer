#!/bin/bash
# Baseline 1: Schemathesis — OpenAPI-driven REST API fuzzer (RESTler equivalent)
# Runs against free5GC NRF endpoint using 3GPP OpenAPI spec
set -e

SPEC_DIR="/home/mm/桌面/5g-fuzzer/src/deployment/oai/component/oai-ausf/3gpp_specs"
OUT_DIR="/home/mm/桌面/5g-fuzzer/results/baselines"
mkdir -p "$OUT_DIR"

echo "=== Schemathesis Baseline ==="
echo "Target: free5GC NRF (172.24.0.10:8000)"
echo "Duration: 2 hours"
echo ""

# Load NRF OpenAPI spec and fuzz
# Schemathesis generates valid requests from the spec then mutates them
# This is value-space-only by design — it never mutates JSON key names
st run \
  --base-url http://172.24.0.10:8000 \
  --hypothesis-max-examples 50000 \
  --request-timeout 10000 \
  --max-response-time 10000 \
  --workers 2 \
  --cassette-path "$OUT_DIR/schemathesis_cassette.yaml" \
  --junit-xml "$OUT_DIR/schemathesis_junit.xml" \
  http://172.24.0.10:8000/nnrf-nfm/v1/nf-instances \
  http://172.24.0.10:8000/nnrf-disc/v1/nf-instances \
  2>&1 | tee "$OUT_DIR/schemathesis_free5gc.log"

echo ""
echo "Done. Results: $OUT_DIR/schemathesis_*"
