#!/usr/bin/env bash
# Build OAI fuzz image with conservative parallelism to reduce RAM spikes and OOM risk
# (see previous Cursor/systemd-oomd kills when make -j$(nproc) + other containers run).
#
# Usage:
#   ./build_image_safe.sh
#   BUILD_JOBS=1 ./build_image_safe.sh
#   IMAGE_TAG=oai-5gc-fuzz:dev ./build_image_safe.sh
#
# From repo root:
#   src/deployment/oai/build_image_safe.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

IMAGE_TAG="${IMAGE_TAG:-oai-5gc-fuzz:latest}"

pick_jobs() {
    if [ -n "${BUILD_JOBS:-}" ]; then
        echo "$BUILD_JOBS"
        return
    fi
    local jobs=2
    if [ -r /proc/meminfo ]; then
        local avail
        avail="$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)"
        if [ -n "$avail" ] && [ "$avail" -lt 8388608 ]; then
            jobs=1
            echo "Note: MemAvailable < 8 GiB — defaulting BUILD_JOBS=1 (override with BUILD_JOBS=N)." >&2
        fi
    fi
    echo "$jobs"
}

BUILD_JOBS="$(pick_jobs)"
if ! [[ "$BUILD_JOBS" =~ ^[0-9]+$ ]] || [ "$BUILD_JOBS" -lt 1 ]; then
    echo "Invalid BUILD_JOBS=$BUILD_JOBS" >&2
    exit 1
fi

running="$(docker ps -q 2>/dev/null | wc -l)"
if [ "${running:-0}" -gt 4 ]; then
    echo "Warning: ${running} containers running. Stopping unused 5GC stacks lowers OOM risk." >&2
fi

export DOCKER_BUILDKIT="${DOCKER_BUILDKIT:-1}"

# Use host network for git/github during build (default bridge often hits TLS/DNS issues).
BUILD_NET="${DOCKER_BUILD_NETWORK:-host}"

echo "Building ${IMAGE_TAG} with BUILD_JOBS=${BUILD_JOBS} (network=${BUILD_NET}) ..."
docker build \
    --network="${BUILD_NET}" \
    --build-arg "BUILD_JOBS=${BUILD_JOBS}" \
    -t "${IMAGE_TAG}" \
    .

echo "Done: ${IMAGE_TAG}"
