# Open5GS instrumented builds for fuzzing.
# Build variants (pick one build-arg):
#   docker build --build-arg LLVM_COVERAGE=1 -t open5gs-fuzz-coverage:llvm .   # clang sancov only
#   docker build --build-arg COVERAGE=1      -t open5gs-fuzz-coverage:latest . # gcov only
#   docker build --build-arg SANITIZE=1      -t open5gs-fuzz:v2.7.7-asan .      # ASan+UBSan
#   docker build --build-arg SANITIZE_COV=1  -t open5gs-fuzz:v2.7.7-asan-cov .  # ASan+UBSan+sancov

FROM ubuntu:22.04 AS builder

ARG COVERAGE=0
ARG LLVM_COVERAGE=0
ARG SANITIZE=0
ARG SANITIZE_COV=0
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake meson ninja-build pkg-config \
    git curl ca-certificates flex bison \
    libgnutls28-dev libgcrypt-dev libssl-dev libidn11-dev \
    libsctp-dev libmongoc-dev libyaml-dev libmicrohttpd-dev \
    libcurl4-gnutls-dev libtalloc-dev libnghttp2-dev \
    iproute2 iptables \
    clang-14 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN git clone --depth 1 --branch v2.7.7 https://github.com/open5gs/open5gs.git .

COPY sanitizer_cov.c /tmp/

# Build the SanitizerCoverage callback library unconditionally so the runtime
# COPY below always succeeds. It is inert in images whose binaries are not
# coverage-instrumented (nothing references its symbols / calls its init).
RUN cc -shared -fPIC -O2 -o /usr/lib/libsanitizer_cov.so /tmp/sanitizer_cov.c

RUN if [ "$LLVM_COVERAGE" = "1" ]; then \
    clang-14 -shared -fPIC -O2 -o /usr/lib/libsanitizer_cov.so /tmp/sanitizer_cov.c \
    && echo "libsanitizer_cov built"; \
    CC=clang-14 CXX=clang++-14 \
    meson setup build --prefix=/usr --buildtype=debug \
        -Dc_args="-fsanitize-coverage=trace-pc-guard -g -O1 -Wno-error=compound-token-split-by-macro -Wno-error=format" \
        -Db_lundef=false; \
    elif [ "$COVERAGE" = "1" ]; then \
    CFLAGS="-fprofile-arcs -ftest-coverage -g -O0" LDFLAGS="-lgcov" \
    meson setup build --prefix=/usr --buildtype=debug \
        -Dc_args="-fprofile-arcs -ftest-coverage -g -O0" \
        -Dc_link_args="-fprofile-arcs -lgcov"; \
    elif [ "$SANITIZE" = "1" ]; then \
    meson setup build --prefix=/usr --buildtype=debug \
        -Db_sanitize=address,undefined \
        -Db_lundef=false \
        -Dc_args="-g -O1 -fno-omit-frame-pointer -fno-sanitize=alignment"; \
    elif [ "$SANITIZE_COV" = "1" ]; then \
    clang-14 -shared -fPIC -O2 -o /usr/lib/libsanitizer_cov.so /tmp/sanitizer_cov.c; \
    CC=clang-14 CXX=clang++-14 \
    CFLAGS="-shared-libasan" LDFLAGS="-shared-libasan" \
    meson setup build --prefix=/usr --buildtype=debug \
        -Db_sanitize=address,undefined \
        -Db_lundef=false \
        -Dc_args="-g -O1 -fno-omit-frame-pointer -fno-sanitize=alignment -fsanitize-coverage=trace-pc-guard -Wno-error=compound-token-split-by-macro -Wno-error=format" \
        -Dc_link_args="-Wl,--no-as-needed -L/usr/lib -lsanitizer_cov"; \
    else \
    meson setup build --prefix=/usr --buildtype=debugoptimized; \
    fi

RUN ninja -C build install

# Stage clang's shared sanitizer runtimes to a fixed path so the runtime image
# can COPY them. Needed by SANITIZE_COV=1 (clang -shared-libasan) builds; for
# other variants these files are present but unused.
RUN cp "$(clang-14 -print-file-name=libclang_rt.asan-x86_64.so)" /usr/lib/ \
 && cp "$(clang-14 -print-file-name=libclang_rt.ubsan_standalone-x86_64.so)" /usr/lib/

FROM ubuntu:22.04
ARG DEBIAN_FRONTEND=noninteractive
# Empty by default; the combined build passes --build-arg SANITIZE_COV=1 which
# flips the conditional ENV expansions below on (LD_PRELOAD + link-order check).
ARG SANITIZE_COV=
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgnutls30 libgcrypt20 libssl3 libsctp1 libmongoc-1.0-0 \
    libyaml-0-2 libmicrohttpd12 libnghttp2-14 libcurl3-gnutls libtalloc2 \
    libidn12 lksctp-tools iproute2 iptables tcpdump gdb valgrind \
    libasan6 libubsan1 \
    && rm -rf /var/lib/apt/lists/*

# Sanitizer runtime behaviour (only takes effect for SANITIZE=1 builds):
#  - print full reports to stderr (captured by docker logs / ContainerMonitor)
#  - abort on error so the daemon crashes and the monitor flags a finding
#  - disable leak detection: a long-running daemon accrues benign "leaks"
# ASan stays fatal: a memory-corruption hit aborts the AMF, the crash is a finding.
# UBSan is recoverable: it logs "runtime error:" to stderr and keeps the AMF alive
# so fuzzing continues (the alignment check is disabled at compile time as it is
# non-exploitable on x86 and fires on every legitimate NAS message).
# For SANITIZE_COV=1 (clang ASan+sancov) the SanitizerCoverage callback library
# must be loaded *before* clang's ASan runtime so that its strong sancov symbols
# win over ASan's weak no-op versions (otherwise no coverage is recorded). That
# preload order trips ASan's "runtime must come first" guard, so it is disabled
# via verify_asan_link_order=0. Both expansions are empty for non-cov images.
ENV ASAN_OPTIONS="abort_on_error=1:halt_on_error=1:detect_leaks=0:log_path=stderr:print_stats=0:handle_abort=1:disable_coredump=1${SANITIZE_COV:+:verify_asan_link_order=0}"
ENV UBSAN_OPTIONS="halt_on_error=0:print_stacktrace=1:log_path=stderr"
ENV LD_PRELOAD="${SANITIZE_COV:+/usr/lib/libsanitizer_cov.so /usr/lib/libclang_rt.asan-x86_64.so}"

COPY --from=builder /usr/bin/open5gs-* /usr/bin/
COPY --from=builder /usr/lib/x86_64-linux-gnu/libogs* /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/lib/x86_64-linux-gnu/libprom* /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/lib/x86_64-linux-gnu/libfdcore* /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/lib/x86_64-linux-gnu/libfdproto* /usr/lib/x86_64-linux-gnu/
# SanitizerCoverage callback library (DT_NEEDED of SANITIZE_COV=1 binaries) and
# clang's shared ASan/UBSan runtimes (DT_NEEDED of -shared-libasan binaries).
COPY --from=builder /usr/lib/libsanitizer_cov.so /usr/lib/
COPY --from=builder /usr/lib/libclang_rt.asan-x86_64.so /usr/lib/
COPY --from=builder /usr/lib/libclang_rt.ubsan_standalone-x86_64.so /usr/lib/
RUN ldconfig && mkdir -p /etc/open5gs /var/log/open5gs /var/lib/open5gs

ENTRYPOINT ["/usr/bin/open5gs-amfd"]
CMD ["-c", "/etc/open5gs/amf.yaml"]
