#!/bin/bash
# Build OAI NFs with gcov coverage flags. Per-NF success is tolerated —
# any NF that fails to compile is skipped and the build continues.
set +e

BUILD_NFS="${BUILD_NFS:-amf smf ausf}"
JOBS="${BUILD_JOBS:-2}"
[[ "$JOBS" =~ ^[0-9]+$ ]] || JOBS=2

declare -A NF_CMAKE_DIR=(
    [nrf]="build/nrf"
    [amf]="build/amf"
    [smf]="build/smf"
    [ausf]="build/ausf"
    [udm]="build/udm"
    [udr]="build/udr"
    [pcf]="build/pcf"
    [nssf]="build/nssf"
)

COV_FLAGS="-fprofile-arcs -ftest-coverage -DFMT_HEADER_ONLY=1"
COV_LINK="-fprofile-arcs -lgcov -lfmt"

OK_NFS=""
FAIL_NFS=""

for nf in ${BUILD_NFS}; do
    echo "=== Building OAI $nf with coverage ==="
    comp_dir=$(find /build/component -maxdepth 1 -name "*${nf}*" -type d 2>/dev/null | head -1)
    if [ -z "$comp_dir" ]; then
        echo "SKIP: $nf — no component dir"
        FAIL_NFS+="$nf "; continue
    fi

    cmake_subdir="${NF_CMAKE_DIR[$nf]:-build/$nf}"
    cmake_dir="${comp_dir}/${cmake_subdir}"

    if [ ! -f "$cmake_dir/CMakeLists.txt" ]; then
        cmake_dir=$(find "$comp_dir" -name "CMakeLists.txt" -maxdepth 4 \
            -not -path "*/common-*" -not -path "*/scripts/*" \
            -not -path "*/cmake_modules/*" -not -path "*/tests/*" \
            -not -path "*/test/*" 2>/dev/null | head -1)
        [ -n "$cmake_dir" ] && cmake_dir=$(dirname "$cmake_dir")
    fi

    if [ -z "$cmake_dir" ] || [ ! -f "$cmake_dir/CMakeLists.txt" ]; then
        echo "SKIP: $nf — no CMakeLists.txt"
        FAIL_NFS+="$nf "; continue
    fi

    rm -rf /build/build/$nf
    mkdir -p /build/build/$nf
    cd /build/build/$nf
    export OPENAIRCN_DIR="$comp_dir"

    if ! cmake "$cmake_dir" \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DCMAKE_PREFIX_PATH="/usr/local" \
        -DCMAKE_C_COMPILER=gcc-12 \
        -DCMAKE_CXX_COMPILER=g++-12 \
        -DCMAKE_C_FLAGS="$COV_FLAGS" \
        -DCMAKE_CXX_FLAGS="$COV_FLAGS" \
        -DCMAKE_EXE_LINKER_FLAGS="$COV_LINK" \
        2>&1 | tail -20; then
        echo "FAILED: cmake configure $nf"
        FAIL_NFS+="$nf "; continue
    fi

    if ! cmake --build . --parallel "$JOBS" 2>&1 | tail -50; then
        echo "FAILED: build $nf"
        FAIL_NFS+="$nf "; continue
    fi

    # Locate the produced binary — usually $nf or oai_$nf
    bin=""
    for cand in "$nf" "oai_$nf" "${nf}d"; do
        f=$(find /build/build/$nf -maxdepth 3 -name "$cand" -type f -executable 2>/dev/null | head -1)
        [ -n "$f" ] && bin="$f" && break
    done
    if [ -z "$bin" ]; then
        echo "FAILED: $nf built but binary not found"
        FAIL_NFS+="$nf "; continue
    fi
    cp "$bin" /usr/local/bin/oai_$nf
    echo "OK: $nf -> /usr/local/bin/oai_$nf"
    OK_NFS+="$nf "
done

echo ""
echo "BUILD SUMMARY"
echo "  OK:     $OK_NFS"
echo "  FAILED: $FAIL_NFS"

# Write summary so dockerfile can detect what was built
echo "$OK_NFS" > /build/built_nfs.txt
exit 0
