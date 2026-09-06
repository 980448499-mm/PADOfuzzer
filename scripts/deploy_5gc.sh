#!/usr/bin/env bash
# Deploy the full 5GC testbed (free5GC + Open5GS + OAI) on THIS machine.
# Run this on each VM that needs the deployment.
#
# Prerequisites:
#   - Docker (with compose v2: `docker compose`)
#   - The repo checked out (or at least src/deployment/ + this script)
#   - Custom images loaded (either via the tarball from save_5gc_images.sh,
#     or built locally)
#   - Internet access for the public images (mongo, mysql, oaisoftwarealliance/oai-*)
#
# Usage:
#   bash scripts/deploy_5gc.sh [5gc-images.tar]

set -euo pipefail
cd "$(dirname "$0")/.."

IMAGES_TAR="${1:-5gc-images.tar}"

# 1. Load custom images (optional)
if [ -f "$IMAGES_TAR" ]; then
    echo "[1/4] Loading custom images from $IMAGES_TAR ..."
    docker load < "$IMAGES_TAR"
else
    echo "[1/4] No image tarball found; assuming images already present."
fi

# 2. Create the three external bridge networks (idempotent)
echo "[2/4] Creating bridge networks ..."
docker network inspect fuzzing-free5gc >/dev/null 2>&1 || \
    docker network create --driver bridge --subnet 172.24.0.0/24 fuzzing-free5gc
docker network inspect fuzzing-open5gs_fuzzing-open5gs >/dev/null 2>&1 || \
    docker network create --driver bridge --subnet 172.23.0.0/24 fuzzing-open5gs_fuzzing-open5gs
docker network inspect fuzzing-oai >/dev/null 2>&1 || \
    docker network create --driver bridge --subnet 172.25.0.0/24 fuzzing-oai

# 3. Bring up the three stacks
if docker compose version >/dev/null 2>&1; then
    COMPOSE="docker compose"
else
    COMPOSE="docker-compose"
fi
echo "[3/4] Starting free5GC ..."
$COMPOSE -p fuzzing-free5gc  -f src/deployment/free5gc/docker-compose.yml  up -d
echo "[3/4] Starting Open5GS ..."
$COMPOSE -p fuzzing-open5gs -f src/deployment/open5gs/docker-compose.yml up -d
echo "[3/4] Starting OAI ..."
$COMPOSE -p fuzzing-oai     -f src/deployment/oai/docker-compose.yml     up -d

# 4. Status
echo "[4/4] Container status:"
docker ps --format 'table {{.Names}}\t{{.Status}}' | grep -E 'fuzzing|NAMES' || true
