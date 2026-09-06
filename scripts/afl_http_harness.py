#!/usr/bin/env python3
"""AFL/AFLNet/StateAFL HTTP harness. Reads mutated seed from stdin/file,
sends as HTTP request, returns status code. AFL interprets non-zero exit as crash.

Usage:
  afl-fuzz -i seeds/ -o out/ -- python3 afl_http_harness.py @@

Environment variables:
  AFL_TARGET_HOST — target IP (default: 172.24.0.10)
  AFL_TARGET_PORT — target port (default: 8000)
  AFL_TARGET_PROTO — http1.1 or http2 (default: http1.1)
"""

import json, os, random, socket, subprocess, sys

HOST   = os.environ.get("AFL_TARGET_HOST", "172.24.0.10")
PORT   = int(os.environ.get("AFL_TARGET_PORT", "8000"))
PROTO  = os.environ.get("AFL_TARGET_PROTO", "http1.1")

# SBI seed templates
SEEDS = [
    (b"PUT", b"/nnrf-nfm/v1/nf-instances/NF-AFL-0001",
     b'{"nfInstanceId":"NF-AFL-0001","nfType":"AMF","nfStatus":"REGISTERED","heartBeatTimer":10,"ipv4Addresses":["172.23.0.1"]}'),
    (b"GET", b"/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=AMF", None),
    (b"POST", b"/nausf-auth/v1/ue-authentications",
     b'{"supiOrSuci":"imsi-901700000000001","servingNetworkName":"5G:mnc001.mcc001.3gppnetwork.org"}'),
    (b"PATCH", b"/nnrf-nfm/v1/nf-instances/NF-AFL-0001",
     b'{"nfStatus":"REGISTERED","heartBeatTimer":20}'),
    (b"DELETE", b"/nnrf-nfm/v1/nf-instances/NF-AFL-0001", None),
    (b"POST", b"/nnrf-nfm/v1/nf-instances/NF-AFL-0001/access-token",
     b'{"nfInstanceId":"NF-AFL-0001","grant_type":"client_credentials","scope":"nnrf-nfm"}'),
    (b"POST", b"/namf-comm/v1/ue-contexts/ue-001/n1-n2-messages",
     b'{"n1MessageContainer":{"n1MessageClass":"5GMM","n1MessageContent":{"contentId":"msg-1"}}}'),
    (b"GET", b"/nudm-sdm/v1/imsi-901700000000001/am-data", None),
    (b"GET", b"/nudr-dr/v1/subscription-data/imsi-901700000000001", None),
    (b"GET", b"/nnrf-nfm/v1/nf-instances", None),
    (b"POST", b"/nnrf-nfm/v1/subscriptions",
     b'{"nfInstanceId":"NF-AFL-0001","subscriptionId":"sub-1","notificationUri":"http://172.23.0.1:8080/notify"}'),
]


def http11(method, path, body):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((HOST, PORT))
        req = method + b" " + path + b" HTTP/1.1\r\nHost: " + HOST.encode() + b"\r\n"
        if body:
            req += b"Content-Type: application/json\r\nContent-Length: " + str(len(body)).encode() + b"\r\n"
        req += b"\r\n"
        if body: req += body
        s.send(req)
        resp = s.recv(2048)
        s.close()
        return int(resp.split(b"\r\n")[0].decode().split(" ")[1])
    except: return 0


def h2(method, path, body):
    try:
        cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
               "--max-time", "5", "--http2-prior-knowledge",
               "-X", method.decode(),
               f"http://{HOST}:{PORT}" + path.decode()]
        if body:
            cmd += ["-H", "Content-Type: application/json", "-d", body.decode(errors='replace')]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return int(r.stdout.strip()) if r.stdout.strip().isdigit() else 0
    except: return 0


def main():
    # Read mutated input from AFL (either stdin or @@ file)
    if len(sys.argv) > 1:
        with open(sys.argv[1], "rb") as f:
            data = f.read()
    else:
        data = sys.stdin.buffer.read()

    if len(data) < 2:
        sys.exit(0)

    # AFL uses the first byte to select seed template, rest for body mutation
    seed_idx = data[0] % len(SEEDS)
    method, path, body = SEEDS[seed_idx]

    # Apply AFL's byte mutation to the body (if any)
    if body and len(data) > 1:
        mutated_body = bytearray(body)
        # XOR each byte of the mutated body with data[1:] (cycling)
        for i, b in enumerate(data[1:]):
            if i < len(mutated_body):
                mutated_body[i] ^= (b & 0xFF)
        body = bytes(mutated_body)

    sender = h2 if PROTO == "http2" else http11
    status = sender(method, path, body)

    # AFL convention: non-zero exit = crash (status 0 = connection failure)
    if status == 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
