# OAI 5G Core — per-NF fuzzing image with coverage instrumentation
#
# Build:
#   docker build -t oai-5gc-fuzz:latest .
#
# Low-memory / avoid OOM (recommended on laptops):
#   ./build_image_safe.sh
#   # or: docker build --build-arg BUILD_JOBS=2 -t oai-5gc-fuzz:latest .
#
# Coverage build:
#   docker build --build-arg COVERAGE=1 -t oai-5gc-fuzz-coverage:latest .

ARG BASE_IMAGE=ubuntu:22.04

# ─── Builder stage ─────────────────────────────────────────────
FROM ${BASE_IMAGE} AS builder

ARG DEBIAN_FRONTEND=noninteractive
ARG COVERAGE=0
ARG BUILD_NFS="nrf udm udr upf"
# Parallel compile jobs inside the builder (default 2 to reduce RAM spikes vs nproc)
ARG BUILD_JOBS=2
ENV BUILD_JOBS=${BUILD_JOBS} \
    CMAKE_BUILD_PARALLEL_LEVEL=${BUILD_JOBS}

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake git ca-certificates curl pkg-config \
    libssl-dev libcurl4-openssl-dev libmysqlclient-dev \
    libconfig++-dev libboost-all-dev libevent-dev \
    libgnutls28-dev libgcrypt-dev libsctp-dev libnghttp2-dev \
    libspdlog-dev libmicrohttpd-dev nettle-dev libfmt-dev \
    libyaml-cpp-dev rapidjson-dev nlohmann-json3-dev libcrypto++-dev gcc-12 g++-12 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# CPR + Pistache: try GitHub then gitclone.com mirror (common when direct GitHub is blocked/slow).
RUN git config --global http.version HTTP/1.1 \
    && git config --global http.postBuffer 524288000 \
    && set -e; ok=0; \
    for url in \
      "https://github.com/libcpr/cpr.git" \
      "https://github.com/libcpr/cpr" \
      "https://gitclone.com/github.com/libcpr/cpr.git" \
      "https://ghproxy.com/https://github.com/libcpr/cpr.git"; do \
      rm -rf /tmp/cpr; \
      echo "cpr: trying $url ..."; \
      if git clone --depth 1 --branch 1.10.0 "$url" /tmp/cpr 2>&1; then ok=1; break; fi; \
      echo "cpr: clone from $url failed, trying next..."; sleep 10; \
    done; \
    test "$ok" = 1 || { echo "ERROR: cpr clone failed from all URLs"; exit 1; }; \
    cd /tmp/cpr && mkdir -p build && cd build \
    && cmake .. -DCPR_USE_SYSTEM_CURL=ON -DCPR_BUILD_TESTS=OFF \
    && cmake --build . --parallel "${BUILD_JOBS}" \
    && cmake --install . \
    && rm -rf /tmp/cpr

RUN set -e; ok=0; \
    for url in \
      "https://github.com/oktal/pistache.git" \
      "https://github.com/oktal/pistache" \
      "https://gitclone.com/github.com/oktal/pistache.git" \
      "https://ghproxy.com/https://github.com/oktal/pistache.git"; do \
      rm -rf /tmp/pistache; \
      echo "pistache: trying $url ..."; \
      if git clone --depth 1 "$url" /tmp/pistache 2>&1; then ok=1; break; fi; \
      echo "pistache: clone from $url failed, trying next..."; sleep 10; \
    done; \
    test "$ok" = 1 || { echo "ERROR: pistache clone failed from all URLs"; exit 1; }; \
    cd /tmp/pistache && git checkout e18ed9baeb2145af6f9ea41246cf48054ffd9907 2>/dev/null || true; \
    mkdir -p _build && cd _build \
    && cmake .. -DCMAKE_BUILD_TYPE=Release \
        -DPISTACHE_BUILD_EXAMPLES=false \
        -DPISTACHE_BUILD_TESTS=false \
        -DPISTACHE_BUILD_DOCS=false \
    && make -j"${BUILD_JOBS}" \
    && make install \
    && rm -rf /tmp/pistache

# Copy component sources
COPY component/ /build/component/

# Build script (separate file avoids shell escaping issues)
COPY build_nfs.sh /build/
ARG CACHEBUST=0
RUN echo "Build timestamp: ${CACHEBUST}" && chmod +x /build/build_nfs.sh && /build/build_nfs.sh

# ─── Runtime stage ─────────────────────────────────────────────
FROM ${BASE_IMAGE}

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 libcurl4 libmysqlclient21 libconfig++9v5 \
    libboost-system1.74.0 libboost-thread1.74.0 \
    libevent-2.1-7 libgnutls30 libgcrypt20 libsctp1 \
    libnghttp2-14 libmicrohttpd12 libspdlog1 \
    libyaml-cpp0.7 libfmt8 libnettle8 \
    lksctp-tools iproute2 tcpdump gdb valgrind \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/oai /var/log/oai

# Shared libs installed by CPR/Pistache into /usr/local (not in Ubuntu base image)
COPY --from=builder /usr/local/lib/ /usr/local/lib/
RUN ldconfig

# Copy built binaries from builder (silently skip if not built)
COPY --from=builder /build/build/ /tmp/oai_build/
COPY install_bins.sh /tmp/
RUN chmod +x /tmp/install_bins.sh && /tmp/install_bins.sh

# Copy config templates
COPY configs/ /etc/oai/

WORKDIR /etc/oai
