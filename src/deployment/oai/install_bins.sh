#!/bin/bash
# Install built OAI NF binaries into /usr/local/bin/
#
# The build tree may contain CMake probe executables (CMakeCCompilerId, etc.)
# that also match simple find patterns — exclude CMake/Testing paths and require
# a realistic binary size for real NFs.
#
# This script tolerates missing NFs (e.g. UDR needs mongocxx, UPF needs folly)
# and only fails if the essential NRF is missing.
set -euo pipefail

MIN_BIN_BYTES="${MIN_BIN_BYTES:-65536}"
ESSENTIAL_NFS="${ESSENTIAL_NFS:-nrf}"
failures=0

for d in /tmp/oai_build/*/; do
    [ -d "$d" ] || continue
    nf=$(basename "$d")
    case "$nf" in
        upf) names=(spgwu oai_spgwu spgw_u) ;;
        *)   names=("$nf" "oai_${nf}") ;;
    esac

    bin=""
    for name in "${names[@]}"; do
        while IFS= read -r -d '' candidate; do
            sz=$(stat -c%s "$candidate" 2>/dev/null || echo 0)
            if [ "$sz" -ge "$MIN_BIN_BYTES" ]; then
                bin=$candidate
                break 2
            fi
        done < <(find "$d" -type f -name "$name" -executable \
            ! -path '*/CMakeFiles/*' \
            ! -path '*/Testing/*' \
            ! -path '*/.cmake/*' \
            -print0 2>/dev/null)
    done

    if [ -n "$bin" ]; then
        cp "$bin" "/usr/local/bin/oai_${nf}"
        echo "Installed oai_${nf} from ${bin} ($(stat -c%s "$bin") bytes)"
    else
        is_essential=0
        for efn in ${ESSENTIAL_NFS}; do
            [ "$nf" = "$efn" ] && is_essential=1 && break
        done
        echo "WARNING: No suitable binary for ${nf} (tried: ${names[*]}; min ${MIN_BIN_BYTES} bytes)" >&2
        if [ "$is_essential" -eq 1 ]; then
            echo "FATAL: ${nf} is essential and build failed" >&2
            failures=$((failures + 1))
        else
            echo "SKIP: ${nf} is non-essential, continuing" >&2
        fi
    fi
done

rm -rf /tmp/oai_build

if [ "$failures" -gt 0 ]; then
    echo "ERROR: ${failures} essential NF build(s) failed" >&2
    exit 1
fi

echo "Binary installation complete"
