# free5GC fuzzing image — statically linked Go binaries (CGO_ENABLED=0)
# Build: docker build -t free5gc-fuzz:latest .
#
# Binaries are pre-compiled outside Docker and copied directly into
# a minimal Alpine image.

FROM alpine:3.19

RUN apk add --no-cache \
    ca-certificates \
    curl \
    bash \
    && rm -rf /var/cache/apk/*

# free5GC directories
RUN mkdir -p /free5gc/bin /free5gc/config /free5gc/log /free5gc/cert

# Copy all NF binaries
COPY bin/amf /free5gc/bin/amf
COPY bin/ausf /free5gc/bin/ausf
COPY bin/nrf /free5gc/bin/nrf
COPY bin/nssf /free5gc/bin/nssf
COPY bin/pcf /free5gc/bin/pcf
COPY bin/smf /free5gc/bin/smf
COPY bin/udm /free5gc/bin/udm
COPY bin/udr /free5gc/bin/udr
COPY bin/upf /free5gc/bin/upf
COPY bin/webconsole /free5gc/bin/webconsole

# Copy TLS certs
COPY cert/ /free5gc/cert/

WORKDIR /free5gc
ENV PATH=/free5gc/bin:$PATH
ENV GIN_MODE=release
