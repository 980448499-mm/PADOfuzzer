#!/usr/bin/env bash
# Export ALL 5GC Docker images (custom + public) so the target VM needs no
# internet access. Run this ONCE on the machine that already has the images.
#
# Usage:
#   bash scripts/save_5gc_images.sh [output.tar]

set -euo pipefail
cd "$(dirname "$0")/.."

OUT="${1:-5gc-images.tar}"

echo "Saving all 5GC images to $OUT ..."
echo "  custom:  free5gc-fuzz:v4.2.2, open5gs-fuzz:v2.7.7,"
echo "           oai-nrf-official:v2.2.0, oai-5gc-fuzz:latest (~7GB)"
echo "  public:  mongo:6.0, mongo:7.0, mysql:8.0, oaisoftwarealliance/oai-*:v2.2.0"

docker save \
    free5gc-fuzz:v4.2.2 \
    open5gs-fuzz:v2.7.7 \
    oai-nrf-official:v2.2.0 \
    oai-5gc-fuzz:latest \
    mongo:6.0 \
    mongo:7.0 \
    mysql:8.0 \
    oaisoftwarealliance/oai-amf:v2.2.0 \
    oaisoftwarealliance/oai-ausf:v2.2.0 \
    oaisoftwarealliance/oai-udr:v2.2.0 \
    oaisoftwarealliance/oai-smf:v2.2.0 \
    oaisoftwarealliance/oai-nssf:v2.2.0 \
    oaisoftwarealliance/oai-pcf:v2.2.0 \
    -o "$OUT"

ls -lh "$OUT"
echo "Done. Copy $OUT to each VM, then run scripts/deploy_5gc.sh there."
