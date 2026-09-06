#!/bin/bash
set -e

BUILD_NFS="${BUILD_NFS:-nrf udm udr amf smf ausf pcf nssf nef}"
JOBS="${BUILD_JOBS:-2}"
if ! [[ "$JOBS" =~ ^[0-9]+$ ]] || [ "$JOBS" -lt 1 ]; then
    echo "Invalid BUILD_JOBS=$JOBS, using 1" >&2
    JOBS=1
fi
echo "Using BUILD_JOBS=$JOBS for OAI NF builds"

# Map NF name → cmake source directory (relative to component/<nf-dir>)
declare -A NF_CMAKE_DIR=(
    [nrf]="build/nrf"
    [udm]="build/udm"
    [udr]="build/udr"
    [amf]="build/amf"
    [smf]="build/smf"
    [ausf]="build/ausf"
    [pcf]="build/pcf"
    [nssf]="build/nssf"
    [nef]="build/nef"
)

for nf in ${BUILD_NFS}; do
    echo "=== Building OAI $nf ==="

    # Find component directory
    comp_dir=$(find /build/component -maxdepth 1 -name "*${nf}*" -type d 2>/dev/null | head -1)
    if [ -z "$comp_dir" ]; then
        echo "SKIP: No component directory found for $nf"
        continue
    fi

    cmake_subdir="${NF_CMAKE_DIR[$nf]:-build/$nf}"
    cmake_dir="${comp_dir}/${cmake_subdir}"

    if [ ! -f "$cmake_dir/CMakeLists.txt" ]; then
        # Fallback: search
        cmake_dir=$(find "$comp_dir" -name "CMakeLists.txt" -maxdepth 4 \
            -not -path "*/common-*" \
            -not -path "*/scripts/*" \
            -not -path "*/cmake_modules/*" \
            -not -path "*/tests/*" \
            -not -path "*/test/*" \
            2>/dev/null | head -1)
        if [ -n "$cmake_dir" ]; then
            cmake_dir=$(dirname "$cmake_dir")
        fi
    fi

    if [ -z "$cmake_dir" ] || [ ! -f "$cmake_dir/CMakeLists.txt" ]; then
        echo "SKIP: No CMakeLists.txt for $nf"
        continue
    fi

    mkdir -p /build/build/$nf
    cd /build/build/$nf
    export OPENAIRCN_DIR="$comp_dir"
    echo "Configuring $nf from $cmake_dir (OPENAIRCN_DIR=$OPENAIRCN_DIR)"

    if ! cmake "$cmake_dir" \
        -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DCMAKE_PREFIX_PATH="/usr/local" \
        2>&1; then
        echo "SKIP: cmake configure failed for $nf"
        continue
    fi

    echo "Building $nf"
    if ! cmake --build . --parallel "${JOBS}" 2>&1; then
        echo "FAILED: Build $nf had errors (check above)" >&2
        continue
    fi
    echo "Done building $nf"
done

echo "All builds complete"
