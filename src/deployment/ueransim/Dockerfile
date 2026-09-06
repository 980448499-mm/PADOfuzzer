# UERANSIM — 5G UE/gNB Simulator for fuzzing
# Connects to our Open5GS AMF to register UEs and create PDU sessions
FROM ubuntu:22.04 AS builder

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake git g++ libsctp-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN git config --global http.sslverify false && \
    git clone --depth 1 --branch v3.2.6 https://github.com/aligungr/UERANSIM.git .

RUN make -j$(nproc)

FROM ubuntu:22.04
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsctp1 iproute2 tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/build/nr-gnb /usr/bin/
COPY --from=builder /build/build/nr-ue /usr/bin/
COPY --from=builder /build/build/libdevbnd.so /usr/lib/
COPY --from=builder /build/config/ /etc/ueransim/

RUN mkdir -p /var/log/ueransim
WORKDIR /etc/ueransim
