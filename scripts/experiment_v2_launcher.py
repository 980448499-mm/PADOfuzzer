#!/usr/bin/env python3
"""
V2 Experiment Launcher — Non-stationary online learning for 5G Core fuzzing.

Architecture (6-group ablation):
  G0 (Random):         Uniform random mutation, no learning
  G1 (SW-UCB):         NonStationaryMutationBandit (SW-UCB + crash reset)
  G2 (+CondTS):        G1 + ConditionalThompsonSampling (per-endpoint Dirichlet)
  G3 (+CrashReset):    G2 + explicit crash-triggered window reset
  G4 (+MTShare):       G3 + MultiTaskDirichletSharing (cross-target transfer)
  G5 (Full):           G4 + active endpoint query (max posterior variance)

Baselines:
  AFLNet:      byte-level havoc + coverage feedback
  StateAFL:    state-aware byte mutation + response-code state inference
  Schemathesis: OpenAPI schema-driven + value-space fuzzing
  Boofuzz:     network protocol primitive fuzzing + block-based mutation
"""

import argparse, json, os, random, socket, subprocess, sys, time, shutil
from collections import defaultdict, deque
from pathlib import Path
from datetime import datetime

# Ensure src/ is importable from project root
_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPT_DIR.parent
if str(_PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT / "src"))

# ── Config ──────────────────────────────────────────────────
EXPERIMENT_DIR = Path("/home/mm/桌面/5g-fuzzer/results/experiment_v2")
SCRIPTS = Path("/home/mm/桌面/5g-fuzzer/scripts")
RESULTS = Path("/home/mm/桌面/5g-fuzzer/results")

TARGETS = {
    # free5GC per-NF (HTTP/1.1, Go, all on port 8000)
    "free5gc-nrf":  {"host": "172.24.0.10", "port": 8000, "proto": "http1.1", "lang": "Go", "impl": "free5gc"},
    "free5gc-amf":  {"host": "172.24.0.20", "port": 8000, "proto": "http1.1", "lang": "Go", "impl": "free5gc"},
    "free5gc-smf":  {"host": "172.24.0.30", "port": 8000, "proto": "http1.1", "lang": "Go", "impl": "free5gc"},
    "free5gc-ausf": {"host": "172.24.0.50", "port": 8000, "proto": "http1.1", "lang": "Go", "impl": "free5gc"},
    "free5gc-udm":  {"host": "172.24.0.60", "port": 8000, "proto": "http1.1", "lang": "Go", "impl": "free5gc"},
    "free5gc-udr":  {"host": "172.24.0.70", "port": 8000, "proto": "http1.1", "lang": "Go", "impl": "free5gc"},
    "free5gc-pcf":  {"host": "172.24.0.80", "port": 8000, "proto": "http1.1", "lang": "Go", "impl": "free5gc"},
    "free5gc-nssf": {"host": "172.24.0.90", "port": 8000, "proto": "http1.1", "lang": "Go", "impl": "free5gc"},
    # OAI per-NF (HTTP/1.1, C++, all on port 80)
    "oai-nrf":      {"host": "172.25.0.10", "port": 80,   "proto": "http1.1", "lang": "C++", "impl": "oai"},
    "oai-amf":      {"host": "172.25.0.20", "port": 80,   "proto": "http1.1", "lang": "C++", "impl": "oai"},
    "oai-ausf":     {"host": "172.25.0.50", "port": 80,   "proto": "http1.1", "lang": "C++", "impl": "oai"},
    "oai-smf":      {"host": "172.25.0.30", "port": 80,   "proto": "http1.1", "lang": "C++", "impl": "oai"},
    "oai-udm":      {"host": "172.25.0.60", "port": 80,   "proto": "http1.1", "lang": "C++", "impl": "oai"},
    "oai-udr":      {"host": "172.25.0.70", "port": 80,   "proto": "http1.1", "lang": "C++", "impl": "oai"},
    "oai-nssf":     {"host": "172.25.0.90", "port": 80,   "proto": "http1.1", "lang": "C++", "impl": "oai"},
    "oai-pcf":      {"host": "172.25.0.100", "port": 80,  "proto": "http1.1", "lang": "C++", "impl": "oai"},
    # Open5GS per-NF (HTTP/2, C, all on port 7777)
    "open5gs-nrf":  {"host": "172.23.0.10", "port": 7777, "proto": "http2", "lang": "C", "impl": "open5gs"},
    "open5gs-amf":  {"host": "172.23.0.20", "port": 7777, "proto": "http2", "lang": "C", "impl": "open5gs"},
    "open5gs-smf":  {"host": "172.23.0.30", "port": 7777, "proto": "http2", "lang": "C", "impl": "open5gs"},
    "open5gs-ausf": {"host": "172.23.0.50", "port": 7777, "proto": "http2", "lang": "C", "impl": "open5gs"},
    "open5gs-udm":  {"host": "172.23.0.60", "port": 7777, "proto": "http2", "lang": "C", "impl": "open5gs"},
    "open5gs-udr":  {"host": "172.23.0.70", "port": 7777, "proto": "http2", "lang": "C", "impl": "open5gs"},
    "open5gs-nssf": {"host": "172.23.0.90", "port": 7777, "proto": "http2", "lang": "C", "impl": "open5gs"},
    "open5gs-bsf":  {"host": "172.23.0.100", "port": 7777, "proto": "http2", "lang": "C", "impl": "open5gs"},
    "open5gs-scp":  {"host": "172.23.0.110", "port": 7777, "proto": "http2", "lang": "C", "impl": "open5gs"},
}

OPEN5GS_TEMPLATES = {
    "ausf": [
        {"method": "POST", "path": "/nausf-auth/v1/ue-authentications", "op": "UEAuthenticate",
         "body": {"supiOrSuci": "imsi-901700000000001",
                  "servingNetworkName": "5G:mnc001.mcc001.3gppnetwork.org"}},
    ],
    "udr": [
        {"method": "GET", "path": "/nudr-dr/v1/subscription-data/imsi-901700000000001/authentication-data/authentication-subscription", "op": "UDRQuery", "body": None},
        {"method": "GET", "path": "/nudr-dr/v1/subscription-data/imsi-901700000000001/provisioned-data/am-data", "op": "UDRGetAM", "body": None},
    ],
    "amf": [
        {"method": "PUT", "path": "/namf-comm/v1/ue-contexts/imsi-901700000000001", "op": "UEContextCreate",
         "body": {"supi": "imsi-901700000000001", "guti": "test-guti", "ranUeNgapId": 1, "amfUeNgapId": 1}},
        {"method": "POST", "path": "/namf-comm/v1/ue-contexts/imsi-901700000000001/n1-n2-messages", "op": "N1N2Message",
         "body": {"n1MessageContainer": {"n1MessageClass": "5GMM", "n1MessageContent": {"contentId": "msg-1"}}}},
    ],
    "udm": [
        {"method": "GET", "path": "/nudm-sdm/v2/imsi-901700000000001/am-data", "op": "UDMGetAM", "body": None},
        {"method": "GET", "path": "/nudm-sdm/v2/imsi-901700000000001/sm-data", "op": "UDMGetSM", "body": None},
        {"method": "GET", "path": "/nudm-uecm/v1/imsi-901700000000001/registrations/amf-3gpp-access", "op": "UDMRegistrations", "body": None},
    ],
    "smf": [
        {"method": "POST", "path": "/nsmf-pdusession/v1/sm-contexts", "op": "PDUSessionCreate",
         "body": {"supi": "imsi-901700000000001", "dnn": "internet", "sNssai": {"sst": 1}}},
    ],
    "nrf": [
        {"method": "PUT", "path": "/nnrf-nfm/v1/nf-instances/{id}", "op": "NFRegister",
         "body": {"nfInstanceId": "{id}", "nfType": "AMF", "nfStatus": "REGISTERED",
                  "heartBeatTimer": 10, "ipv4Addresses": ["172.23.0.1"]}},
        {"method": "GET", "path": "/nnrf-nfm/v1/nf-instances", "op": "NFList", "body": None},
        {"method": "GET", "path": "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=AMF",
         "op": "NFDiscover", "body": None},
    ],
    "nssf": [
        {"method": "GET", "path": "/nnssf-nsselection/v1/network-slice-information?nf-type=AMF", "op": "SliceSelect", "body": None},
    ],
    "bsf": [
        {"method": "GET", "path": "/nbsf-management/v1/pcfBindings", "op": "BSFListBindings", "body": None},
    ],
    "scp": [
        {"method": "GET", "path": "/nnrf-disc/v1/nf-instances?target-nf-type=AMF", "op": "SCPDiscover", "body": None},
        {"method": "PUT", "path": "/nnrf-nfm/v1/nf-instances/SCP-test-001", "op": "SCPRegister",
         "body": {"nfInstanceId": "SCP-test-001", "nfType": "AMF", "nfStatus": "REGISTERED", "heartBeatTimer": 10,
                  "ipv4Addresses": ["172.23.0.1"]}},
    ],
}

SBI_TEMPLATES = [
    {"method": "PUT", "path": "/nnrf-nfm/v1/nf-instances/{id}", "op": "NFRegister",
     "body": {"nfInstanceId": "{id}", "nfType": "AMF", "nfStatus": "REGISTERED",
              "heartBeatTimer": 10, "ipv4Addresses": ["172.23.0.1"]}},
    {"method": "PATCH", "path": "/nnrf-nfm/v1/nf-instances/{id}", "op": "NFUpdate",
     "body": {"nfStatus": "REGISTERED", "heartBeatTimer": 20}},
    {"method": "DELETE", "path": "/nnrf-nfm/v1/nf-instances/{id}", "op": "NFDeregister", "body": {}},
    {"method": "GET", "path": "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=AMF",
     "op": "NFDiscover", "body": None},
    {"method": "POST", "path": "/nnrf-nfm/v1/nf-instances/{id}/access-token", "op": "NFAccessToken",
     "body": {"nfInstanceId": "{id}", "grant_type": "client_credentials", "scope": "nnrf-nfm"}},
    {"method": "GET", "path": "/nnrf-nfm/v1/nf-instances/{id}", "op": "NFProfile", "body": None},
    {"method": "GET", "path": "/nnrf-nfm/v1/nf-instances", "op": "NFList", "body": None},
    {"method": "POST", "path": "/nnrf-nfm/v1/subscriptions", "op": "NFSubscribe",
     "body": {"nfInstanceId": "{id}", "subscriptionId": "sub-1",
              "notificationUri": "http://172.23.0.1:8080/notify"}},
    {"method": "POST", "path": "/nausf-auth/v1/ue-authentications", "op": "UEAuthenticate",
     "body": {"supiOrSuci": "imsi-901700000000001",
              "servingNetworkName": "5G:mnc001.mcc001.3gppnetwork.org"}},
    {"method": "POST", "path": "/namf-comm/v1/ue-contexts/{id}/n1-n2-messages", "op": "N1N2Message",
     "body": {"n1MessageContainer": {"n1MessageClass": "5GMM",
              "n1MessageContent": {"contentId": "msg-1"}}}},
    {"method": "GET", "path": "/nudm-sdm/v1/imsi-901700000000001/am-data", "op": "SDMGetAmData", "body": None},
    {"method": "GET", "path": "/nudr-dr/v1/subscription-data/imsi-901700000000001",
     "op": "UDRQuery", "body": None},
]

# Per-implementation templates for non-Open5GS NFs
FREE5GC_TEMPLATES = {
    "nrf": [
        {"method": "PUT", "path": "/nnrf-nfm/v1/nf-instances/{id}", "op": "NFRegister",
         "body": {"nfInstanceId": "{id}", "nfType": "AMF", "nfStatus": "REGISTERED",
                  "heartBeatTimer": 10, "ipv4Addresses": ["172.24.0.1"]}},
        {"method": "PATCH", "path": "/nnrf-nfm/v1/nf-instances/{id}", "op": "NFUpdate",
         "body": {"nfStatus": "REGISTERED", "heartBeatTimer": 20}},
        {"method": "DELETE", "path": "/nnrf-nfm/v1/nf-instances/{id}", "op": "NFDeregister", "body": {}},
        {"method": "GET", "path": "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=AMF",
         "op": "NFDiscover", "body": None},
        {"method": "GET", "path": "/nnrf-nfm/v1/nf-instances", "op": "NFList", "body": None},
    ],
    "amf": [
        {"method": "PUT", "path": "/namf-comm/v1/ue-contexts/{id}", "op": "UEContextCreate",
         "body": {"supi": "imsi-901700000000001", "guti": "test-guti", "ranUeNgapId": 1, "amfUeNgapId": 1}},
        {"method": "POST", "path": "/namf-comm/v1/ue-contexts/{id}/n1-n2-messages", "op": "N1N2Message",
         "body": {"n1MessageContainer": {"n1MessageClass": "5GMM", "n1MessageContent": {"contentId": "msg-1"}}}},
        {"method": "GET", "path": "/namf-comm/v1/ue-contexts/{id}/transfer-status", "op": "TransferStatus", "body": None},
    ],
    "ausf": [
        {"method": "POST", "path": "/nausf-auth/v1/ue-authentications", "op": "UEAuthenticate",
         "body": {"supiOrSuci": "imsi-901700000000001",
                  "servingNetworkName": "5G:mnc001.mcc001.3gppnetwork.org"}},
        {"method": "PUT", "path": "/nausf-auth/v1/ue-authentications/{id}/5g-aka-confirmation", "op": "UEAuthConfirm",
         "body": {"resStar": "0000000000000000"}},
    ],
    "udm": [
        {"method": "GET", "path": "/nudm-sdm/v2/imsi-901700000000001/am-data", "op": "SDMGetAmData", "body": None},
        {"method": "GET", "path": "/nudm-sdm/v2/imsi-901700000000001/sm-data", "op": "SDMGetSmData", "body": None},
        {"method": "GET", "path": "/nudm-uecm/v1/imsi-901700000000001/registrations/amf-3gpp-access", "op": "UEContextGet", "body": None},
        {"method": "POST", "path": "/nudm-ueau/v1/imsi-901700000000001/security-information/generate-auth-data", "op": "GenerateAuth",
         "body": {"servingNetworkName": "5G:mnc001.mcc001.3gppnetwork.org", "ausfInstanceId": "{id}"}},
    ],
    "udr": [
        {"method": "GET", "path": "/nudr-dr/v1/subscription-data/imsi-901700000000001/authentication-data/authentication-subscription", "op": "UDRGetAuth", "body": None},
        {"method": "GET", "path": "/nudr-dr/v1/subscription-data/imsi-901700000000001/provisioned-data/am-data", "op": "UDRGetAM", "body": None},
    ],
    "nssf": [
        {"method": "GET", "path": "/nnssf-nsselection/v1/network-slice-information?nf-type=AMF", "op": "SliceSelect", "body": None},
    ],
    "pcf": [
        {"method": "POST", "path": "/npcf-am-policy-control/v1/policies", "op": "AMPolicyCreate",
         "body": {"supi": "imsi-901700000000001", "notificationUri": "http://172.25.0.1:8080/callback"}},
    ],
}

OAI_TEMPLATES = {
    "nrf": [
        {"method": "PUT", "path": "/nnrf-nfm/v1/nf-instances/{id}", "op": "NFRegister",
         "body": {"nfInstanceId": "{id}", "nfType": "AMF", "nfStatus": "REGISTERED",
                  "heartBeatTimer": 10, "ipv4Addresses": ["172.25.0.1"]}},
        {"method": "GET", "path": "/nnrf-nfm/v1/nf-instances", "op": "NFList", "body": None},
        {"method": "GET", "path": "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=AMF",
         "op": "NFDiscover", "body": None},
    ],
    "amf": [
        {"method": "PUT", "path": "/namf-comm/v1/ue-contexts/{id}", "op": "UEContextCreate",
         "body": {"supi": "imsi-901700000000001", "guti": "test-guti", "ranUeNgapId": 1, "amfUeNgapId": 1}},
        {"method": "POST", "path": "/namf-comm/v1/ue-contexts/{id}/n1-n2-messages", "op": "N1N2Message",
         "body": {"n1MessageContainer": {"n1MessageClass": "5GMM", "n1MessageContent": {"contentId": "msg-1"}}}},
    ],
    "ausf": [
        {"method": "POST", "path": "/nausf-auth/v1/ue-authentications", "op": "UEAuthenticate",
         "body": {"supiOrSuci": "imsi-901700000000001",
                  "servingNetworkName": "5G:mnc001.mcc001.3gppnetwork.org"}},
    ],
    "smf": [
        {"method": "POST", "path": "/nsmf-pdusession/v1/sm-contexts", "op": "PDUSessionCreate",
         "body": {"supi": "imsi-901700000000001", "dnn": "oai", "sNssai": {"sst": 1, "sd": "000001"}}},
        {"method": "POST", "path": "/nsmf-pdusession/v1/sm-contexts/{id}/modify", "op": "PDUSessionModify",
         "body": {"dnn": "oai", "sNssai": {"sst": 1}}},
    ],
    "udm": [
        {"method": "GET", "path": "/nudm-sdm/v2/imsi-901700000000001/am-data", "op": "SDMGetAmData", "body": None},
        {"method": "GET", "path": "/nudm-sdm/v2/imsi-901700000000001/sm-data", "op": "SDMGetSmData", "body": None},
        {"method": "POST", "path": "/nudm-ueau/v1/imsi-901700000000001/security-information/generate-auth-data", "op": "GenerateAuth",
         "body": {"servingNetworkName": "5G:mnc001.mcc001.3gppnetwork.org", "ausfInstanceId": "{id}"}},
    ],
    "udr": [
        {"method": "GET", "path": "/nudr-dr/v1/subscription-data/imsi-901700000000001/authentication-data/authentication-subscription", "op": "UDRGetAuth", "body": None},
        {"method": "GET", "path": "/nudr-dr/v1/subscription-data/imsi-901700000000001/provisioned-data/am-data", "op": "UDRGetAM", "body": None},
    ],
    "smf": [
        {"method": "POST", "path": "/nsmf-pdusession/v1/sm-contexts", "op": "PDUSessionCreate",
         "body": {"supi": "imsi-901700000000001", "dnn": "internet", "sNssai": {"sst": 1, "sd": "000001"}}},
    ],
    "pcf": [
        {"method": "POST", "path": "/npcf-am-policy-control/v1/policies", "op": "AMPolicyCreate",
         "body": {"supi": "imsi-901700000000001", "notificationUri": "http://172.24.0.1:8080/callback"}},
    ],
    "nssf": [
        {"method": "GET", "path": "/nnssf-nsselection/v1/network-slice-information?nf-type=AMF&nf-id={id}", "op": "SliceSelect", "body": None},
    ],
}

# 15 key-space mutation strategies (used by JKSM and our fuzzer)
KEY_STRATEGIES = [
    "lethal_char", "unicode_inject", "json_syntax", "key_overflow",
    "header_inject", "sql_inject_key", "key_truncation", "key_duplication",
    "case_mutation", "key_swap", "nul_prefix_suffix", "pattern_repeat",
    "numeric_key", "whitespace_key", "empty_key",
]

# 10 value-space mutation strategies
VALUE_STRATEGIES = [
    "type_confusion", "boundary_ints", "null_required", "empty_values",
    "oversized", "extra_fields", "special_chars_value", "missing_required",
    "duplicate_keys", "deep_nesting",
]

ALL_MUTATIONS = [f"key_{s}" for s in KEY_STRATEGIES] + [f"val_{s}" for s in VALUE_STRATEGIES]

# Operations (endpoints) for conditional TS
ALL_OPERATIONS = list(dict.fromkeys(t["op"] for t in SBI_TEMPLATES))


def apply_mutation(body: bytes, mutation_name: str) -> bytes:
    """Apply a named mutation strategy to a JSON body."""
    if not body:
        return body
    try:
        obj = json.loads(body.decode())
    except Exception:
        return body
    keys = list(obj.keys())
    if not keys:
        return body

    is_key = mutation_name.startswith("key_")
    strat = mutation_name[4:] if is_key else mutation_name[4:]

    if is_key:
        _apply_key_strat(obj, keys, strat)
    else:
        _apply_val_strat(obj, strat)

    return json.dumps(obj).encode()


def _apply_key_strat(obj, keys, strat):
    k = random.choice(keys)
    new_key = k
    if strat == "lethal_char":
        C = ["\x00", "../", "\x01", "\xff", "__proto__"]
        p = random.randint(0, len(k))
        new_key = k[:p] + random.choice(C) + k[p:]
    elif strat == "unicode_inject":
        new_key = k + random.choice([chr(0), chr(0x202E), chr(0xFEFF)])
    elif strat == "json_syntax":
        new_key = k + random.choice(["{", "}", "[", "]", ":", ","])
    elif strat == "key_overflow":
        new_key = k + "A" * random.choice([1000, 5000, 10000])
    elif strat == "header_inject":
        new_key = k + random.choice(["\r\n", "\r\nContent-Length: 0\r\n"])
    elif strat == "sql_inject_key":
        new_key = k + random.choice(["'; DROP TABLE--", "' OR '1'='1"])
    elif strat == "key_truncation":
        if len(k) > 1:
            new_key = k[:max(1, random.randint(1, len(k) - 1))]
    elif strat == "key_duplication":
        new_key = k + random.choice(["_copy", "_dup", "_bak"])
    elif strat == "case_mutation":
        chars = list(k)
        for i in range(len(chars)):
            if random.random() < 0.3:
                chars[i] = chars[i].upper() if chars[i].islower() else chars[i].lower()
        new_key = ''.join(chars)
    elif strat == "key_swap":
        if len(keys) >= 2:
            k2 = random.choice([x for x in keys if x != k])
            obj[k], obj[k2] = obj[k2], obj[k]
    elif strat == "nul_prefix_suffix":
        new_key = "\x00" + k + "\x00"
    elif strat == "pattern_repeat":
        new_key = k + random.choice(["//", "..", "\\\\"]) * random.randint(1, 5)
    elif strat == "numeric_key":
        new_key = k + str(random.choice([0, -1, 99999]))
    elif strat == "whitespace_key":
        new_key = k + random.choice([" ", "\t", "  "])
    elif strat == "empty_key":
        new_key = "" if random.random() < 0.5 else " " * 3
    if new_key != k and new_key not in obj:
        obj[new_key] = obj.pop(k)


def _apply_val_strat(obj, strat):
    vkeys = list(obj.keys())
    if not vkeys:
        return
    vk = random.choice(vkeys)
    if strat == "type_confusion":
        v = obj[vk]
        if isinstance(v, str):
            obj[vk] = random.choice([0, -1, True, None])
        elif isinstance(v, (int, float)):
            obj[vk] = "not_an_int"
    elif strat == "boundary_ints":
        if isinstance(obj[vk], (int, float)):
            obj[vk] = random.choice([-1, 0, 1, 2**31 - 1, -2**31])
    elif strat == "null_required":
        obj[vk] = None
    elif strat == "empty_values":
        if isinstance(obj[vk], str):
            obj[vk] = ""
        elif isinstance(obj[vk], list):
            obj[vk] = []
        elif isinstance(obj[vk], dict):
            obj[vk] = {}
    elif strat == "oversized":
        if isinstance(obj[vk], str):
            obj[vk] = "A" * random.choice([1000, 10000])
    elif strat == "extra_fields":
        obj[f"_extra_{random.randint(0,9999)}"] = random.choice(["test", 0, None])
    elif strat == "special_chars_value":
        if isinstance(obj[vk], str):
            obj[vk] += random.choice(["\x00", "\xff", "../"])
    elif strat == "missing_required" and len(vkeys) > 1:
        del obj[vk]
    elif strat == "duplicate_keys":
        obj["_dup_" + vk] = obj[vk]
    elif strat == "deep_nesting":
        nest = {}
        curr = nest
        for _ in range(random.randint(5, 50)):
            curr["a"] = {}
            curr = curr["a"]
        obj["_nested"] = nest


# Baseline mutation functions (unchanged)
def aflnet_havoc(data: bytes) -> bytes:
    if not data or len(data) < 4:
        return data
    d = bytearray(data)
    for _ in range(random.randint(1, 32)):
        op = random.randint(0, 8)
        pos = random.randint(0, len(d) - 1)
        if op == 0:    d[pos] ^= (1 << random.randint(0, 7))
        elif op == 1:  d[pos] = (d[pos] + random.randint(-35, 35)) & 0xFF
        elif op == 2:  d[pos] = random.choice([0, 0xFF, 0x01, 0x7F, 0x80])
        elif op == 3 and pos < len(d) - 1:
            d[pos:pos+2] = bytes([random.randint(0,255), random.randint(0,255)])
        elif op == 4 and pos < len(d) - 3:
            d[pos:pos+4] = random.choice([
                b'\x00\x00\x00\x00', b'\xff\xff\xff\xff', b'\x7f\xff\xff\xff',
                b'\x80\x00\x00\x00', b'\x00\x00\x00\x01'])
        elif op == 5 and pos > 0: del d[pos]
        elif op == 6 and pos > 0: d.insert(pos, d[pos-1])
        elif op == 7 and pos < len(d) - 2: d[pos], d[pos+1] = d[pos+1], d[pos]
        elif op == 8 and len(d) > 4:
            blk_len = random.randint(1, min(32, len(d) - pos))
            d[pos:pos+blk_len] = bytes([random.randint(0, 255) for _ in range(blk_len)])
    return bytes(d)


def schemathesis_mutate(body: bytes) -> bytes:
    if not body: return body
    try:
        obj = json.loads(body.decode())
    except Exception:
        return body
    keys = list(obj.keys())
    if not keys: return body
    strategy = random.choice([
        "type_confusion", "boundary_ints", "null_required", "empty_values",
        "oversized", "extra_fields", "special_chars_value", "missing_required",
        "duplicate_keys", "deep_nesting"
    ])
    _apply_val_strat(obj, strategy)
    return json.dumps(obj).encode()


def boofuzz_mutate(body: bytes) -> bytes:
    if not body: return body
    try:
        obj = json.loads(body.decode())
        s = json.dumps(obj)
    except Exception:
        s = body.decode(errors='replace')
    if random.random() < 0.3:
        return aflnet_havoc(s.encode())
    try:
        obj = json.loads(s)
        op = random.choice(["resize", "truncate", "repeat", "splice"])
        if op == "resize" and isinstance(obj, dict):
            for k in list(obj.keys()):
                if isinstance(obj[k], str):
                    obj[k] = obj[k] * random.randint(0, 10)
        elif op == "truncate" and isinstance(obj, dict):
            for k in list(obj.keys()):
                if isinstance(obj[k], str) and len(obj[k]) > 2:
                    obj[k] = obj[k][:random.randint(1, len(obj[k])-1)]
        return json.dumps(obj).encode()
    except Exception:
        return s.encode()


# ── HTTP Senders ────────────────────────────────────────────

import http.client as hc

_HTTP_POOLS = {}

def http11_request(host, port, method, path, body=None):
    pool_key = (host, port)
    for _attempt in (0, 1):
        conn = None
        try:
            conn = _HTTP_POOLS.get(pool_key)
            if conn is None:
                conn = hc.HTTPConnection(host, port, timeout=10)
                _HTTP_POOLS[pool_key] = conn
            if body:
                conn.request(method, path, body=body,
                             headers={"Content-Type": "application/json"})
            else:
                conn.request(method, path)
            resp = conn.getresponse()
            resp.read()
            status = resp.status
            # If the server closed the connection, drop it from the pool so the
            # next request does not reuse a stale connection.
            if resp.getheader("Connection", "").lower() == "close":
                conn.close()
                _HTTP_POOLS.pop(pool_key, None)
            return status
        except Exception:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
            _HTTP_POOLS.pop(pool_key, None)
    return 0


def h2_request(host, port, method, path, body=None):
    url = f"http://{host}:{port}{path}"
    cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
           "--max-time", "8", "--http2-prior-knowledge", "-X", method, url]
    if body:
        cmd += ["-H", "Content-Type: application/json", "-d", body.decode(errors='replace')]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
        code = r.stdout.strip()
        return int(code) if code.isdigit() and int(code) > 0 else 0
    except Exception:
        return 0


# ── PADO 5-tier divergence reward ────────────────────────────

def compute_pado_reward(statuses: list, weights=(30, 25, 15, 5, 0)) -> int:
    """5-tier reward from 3-way divergence; weights=(crash, 3-class, 2-class, same-class, uniform)."""
    w_crash, w_3cls, w_2cls, w_same, w_uniform = weights
    unique = set(statuses)
    if len(unique) <= 1:
        return w_uniform
    has_crash = any(s == 0 for s in statuses)
    has_alive = any(s > 0 for s in statuses)
    if has_crash and has_alive:
        return w_crash
    classes = [s // 100 for s in statuses]
    unique_classes = set(classes)
    if len(unique_classes) >= 3:
        return w_3cls
    if len(unique_classes) == 2:
        return w_2cls
    return w_same


def classify_pado_reason(statuses: list) -> str:
    """Classify the 3-way divergence reason from [free5gc, oai, primary] statuses."""
    unique = set(statuses)
    if len(unique) <= 1:
        return "uniform"
    has_crash = any(s == 0 for s in statuses)
    has_alive = any(s > 0 for s in statuses)
    if has_crash and has_alive:
        return "crash_vs_alive"
    has_5xx = any(s >= 500 for s in statuses)
    has_4xx = any(400 <= s < 500 for s in statuses)
    has_2xx = any(200 <= s < 300 for s in statuses)
    if has_5xx and has_2xx:
        return "success_vs_failure"
    if has_4xx and has_2xx:
        return "validation_diff"
    classes = {s // 100 for s in statuses}
    if len(classes) >= 3:
        return "all_different"
    return "status_mismatch"


# ── 3-way reference targets for differential reward ─────────
# NOTE: reference targets are resolved dynamically per primary NF (see the
# run loop). The same NF is compared across free5gc / OAI / Open5GS, rather
# than a fixed NRF endpoint.


# ── StateAFL seed pool ─────────────────────────────────────

class StateAwareSeedPool:
    def __init__(self, max_seeds=500):
        self.pool = []
        self.state_counts = {}
        self.max_seeds = max_seeds

    def state_label(self, status_code: int) -> str:
        if status_code == 0: return "CRASH"
        return f"{status_code // 100}xx"

    def record(self, method, path, body, status_code):
        state = self.state_label(status_code)
        self.state_counts[state] = self.state_counts.get(state, 0) + 1
        if random.random() < 0.1 or len(self.pool) < 100:
            self.pool.append((method, path, body, state, 1))
            if len(self.pool) > self.max_seeds:
                self.pool.pop(0)

    def select_seed(self):
        if not self.pool or random.random() < 0.3:
            return None
        total_states = sum(self.state_counts.values()) or 1
        scored = []
        for seed in self.pool:
            method, path, body, state, uses = seed
            rarity = 1.0 - (self.state_counts.get(state, 0) / total_states)
            scored.append((rarity, seed))
        scored.sort(key=lambda x: -x[0])
        top_n = max(1, len(scored) // 5)
        _, chosen = scored[random.randint(0, top_n - 1)]
        idx = self.pool.index(chosen)
        m, p, b, s, u = self.pool[idx]
        self.pool[idx] = (m, p, b, s, u + 1)
        return (chosen[0], chosen[1], chosen[2])


# ── Experiment Runner ────────────────────────────────────────

class ExperimentRunner:
    def __init__(self, target_name: str, hours: int = 24,
                 disable_jksm: bool = False, disable_pado: bool = False,
                 seed=None, pado_weights=(30, 25, 15, 5, 0), tag=""):
        self.target = TARGETS[target_name]
        self.name = target_name
        self.hours = hours
        self.state_pool = StateAwareSeedPool()
        self.disable_jksm = disable_jksm
        self.disable_pado = disable_pado
        self.seed = seed
        self.pado_weights = pado_weights
        self.tag = tag

        # If JKSM disabled, use only value-space strategies
        if disable_jksm:
            self.mutations = [f"val_{s}" for s in VALUE_STRATEGIES]
        else:
            self.mutations = ALL_MUTATIONS

        # Initialize novel algorithms (lazy import)
        self._ns_bandit = None
        self._cond_ts = None
        self._mt_sharing = None

    def _init_algorithms(self, group: str):
        """Initialize algorithms based on ablation group."""
        from fuzzing_engine.novel_algorithms import (
            NonStationaryMutationBandit,
            ConditionalThompsonSampling,
            MultiTaskDirichletSharing,
        )

        # G1+: SW-UCB bandit
        if group in ("G1", "G2", "G3", "G4", "G5"):
            self._ns_bandit = NonStationaryMutationBandit(
                self.mutations, window_size=200)

        # G2+: Conditional Thompson Sampling
        if group in ("G2", "G3", "G4", "G5"):
            self._cond_ts = ConditionalThompsonSampling(
                mutations=self.mutations,
                endpoints=ALL_OPERATIONS)

        # G3+: crash-triggered reset is built into NonStationaryMutationBandit
        # (already active when ns_bandit exists; G0/G1 use UCB1 without reset)

        # G4+: Multi-task Dirichlet sharing
        if group in ("G4", "G5"):
            target_id = self.name.lower().replace(" ", "-").replace("5g", "")
            self._mt_sharing = MultiTaskDirichletSharing(
                target_name=target_id,
                mutations=self.mutations,
                endpoints=ALL_OPERATIONS)

    def send(self, method, path, body=None):
        t = self.target
        if t["proto"] == "http2":
            return h2_request(t["host"], t["port"], method, path, body)
        return http11_request(t["host"], t["port"], method, path, body)

    def _get_templates(self):
        if self.name.startswith("open5gs-"):
            nf = self.name.split("-", 1)[1]
            return OPEN5GS_TEMPLATES.get(nf, SBI_TEMPLATES)
        elif self.name.startswith("free5gc-"):
            nf = self.name.split("-", 1)[1]
            return FREE5GC_TEMPLATES.get(nf, SBI_TEMPLATES)
        elif self.name.startswith("oai-"):
            nf = self.name.split("-", 1)[1]
            return OAI_TEMPLATES.get(nf, SBI_TEMPLATES)
        return SBI_TEMPLATES

    def _select_mutation(self, op_name: str, group: str) -> str:
        """Select mutation strategy based on ablation group.

        G2 (the full system) uses the same SW-UCB bandit as G1; the only
        difference between G1 and G2 is PADO's divergence reward, so the
        G1-vs-G2 comparison isolates PADO's contribution cleanly.
        """
        if group == "G0":
            return random.choice(self.mutations)

        if self._ns_bandit is not None:
            return self._ns_bandit.select()

        return random.choice(self.mutations)

    # ── Checkpoint / resume ─────────────────────────────────────
    def _checkpoint_path(self, out_dir: str, group: str, suffix: str) -> str:
        return f"{out_dir}/{self.name}_{group}{suffix}.checkpoint.json"

    def _save_checkpoint(self, out_dir, group, suffix, results, cumulative_regret,
                         iteration, start_time, context_id, last_crash_iter,
                         post_crash_peak_reward):
        ckpt = {
            "results": results,
            "cumulative_regret": cumulative_regret,
            "iteration": iteration,
            "elapsed_h": (time.time() - start_time) / 3600.0,
            "context_id": context_id,
            "last_crash_iter": last_crash_iter,
            "post_crash_peak_reward": post_crash_peak_reward,
        }
        if self._ns_bandit is not None:
            ckpt["ns_bandit"] = {
                "reward_window": {k: list(v) for k, v in self._ns_bandit.reward_window.items()},
                "total_rounds": self._ns_bandit.total_rounds,
                "outcomes": {k: dict(v) for k, v in self._ns_bandit.outcomes.items()},
            }
        if self._cond_ts is not None:
            ckpt["cond_ts"] = {
                "alpha": self._cond_ts.alpha,
                "obs_count": dict(self._cond_ts.obs_count),
            }
        path = self._checkpoint_path(out_dir, group, suffix)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(ckpt, f, default=list)
        os.replace(tmp, path)

    def _load_checkpoint(self, out_dir, group, suffix):
        path = self._checkpoint_path(out_dir, group, suffix)
        if not os.path.exists(path):
            return None
        try:
            with open(path) as f:
                return json.load(f)
        except Exception:
            return None

    def _container_restart_count(self):
        """Best-effort Docker restart count for the primary container.

        A non-increasing restart count means the code==0 non-response was a
        timeout/transport failure; an increment means a real container restart.
        """
        try:
            r = subprocess.run(
                ["docker", "inspect", "-f", "{{.RestartCount}}",
                 f"fuzzing-{self.name}"],
                capture_output=True, text=True, timeout=2)
            out = r.stdout.strip()
            return int(out) if out.isdigit() else None
        except Exception:
            return None

    def run(self, group: str, out_dir: str):
        """Run one ablation group for the full duration."""
        self._init_algorithms(group)

        suffix = ""
        if self.disable_jksm:
            suffix = "_nojksm"
        elif self.disable_pado:
            suffix = "_nopado"
        if self.seed is not None:
            suffix += f"_seed{self.seed}"
        if self.tag:
            suffix += f"_{self.tag}"

        os.makedirs(out_dir, exist_ok=True)
        ckpt = self._load_checkpoint(out_dir, group, suffix)

        if ckpt is not None:
            # ── Resume from checkpoint ──
            results = ckpt.get("results", {})
            cumulative_regret = ckpt.get("cumulative_regret", 0.0)
            iteration = ckpt.get("iteration", 0)
            context_id = ckpt.get("context_id", f"NF-{random.randint(1000, 9999)}")
            last_crash_iter = ckpt.get("last_crash_iter", -1000)
            post_crash_peak_reward = ckpt.get("post_crash_peak_reward", 0.0)
            results["unique_status_codes"] = set(results.get("unique_status_codes", []))
            results.setdefault("divergence_counter", {})
            results.setdefault("divergence_reason_counter", {})
            results.setdefault("divergence_samples", [])

            if "ns_bandit" in ckpt and self._ns_bandit is not None:
                b = ckpt["ns_bandit"]
                self._ns_bandit.reward_window = {
                    k: deque(v, maxlen=self._ns_bandit.window_size)
                    for k, v in b.get("reward_window", {}).items()}
                self._ns_bandit.total_rounds = b.get("total_rounds", 0)
                self._ns_bandit.outcomes = defaultdict(lambda: defaultdict(int))
                for k, v in b.get("outcomes", {}).items():
                    self._ns_bandit.outcomes[k] = defaultdict(int, v)
            if "cond_ts" in ckpt and self._cond_ts is not None:
                self._cond_ts.alpha = ckpt["cond_ts"].get("alpha", {})
                self._cond_ts.obs_count = defaultdict(
                    int, ckpt["cond_ts"].get("obs_count", {}))

            elapsed_h = ckpt.get("elapsed_h", 0.0)
            start_time = time.time() - elapsed_h * 3600.0
            print(f"[RESUME] {self.name} {group}: {elapsed_h:.2f}h done, "
                  f"{results.get('requests', 0)} reqs", flush=True)
        else:
            # ── Fresh start ──
            start_time = time.time()
            results = {
                "group": group, "target": self.name,
                "duration_h": self.hours, "started": datetime.now().isoformat(),
                "seed": self.seed,
                "requests": 0, "crashes": 0, "http_1xx": 0, "http_2xx": 0,
                "http_3xx": 0, "http_4xx": 0, "http_5xx": 0,
                "unique_status_codes": set(),
                "fsm_states": {},
                "crash_details": [],
                "timeline": [],
                "regret_curve": [],
                "grammar_precision": [],
                "crash_recovery_iters": [],
                "change_points": [],
                "cross_divergences": 0,
                "divergence_counter": {},
                "divergence_reason_counter": {},
                "divergence_samples": [],
            }
            fsm_state = "INIT"
            results["fsm_states"][fsm_state] = 1
            context_id = f"NF-{random.randint(1000, 9999)}"
            cumulative_regret = 0.0
            last_crash_iter = -1000
            post_crash_peak_reward = 0.0
            iteration = 0

        end_time = start_time + self.hours * 3600
        optimal_reward = 30.0  # theoretical max per iteration (crash vs alive)

        msg = (f"\n{'='*60}\n"
               f"[{group}] {self.name} ({self.target['lang']}, "
               f"{self.target['proto']}) — {self.hours}h\n"
               f"{'='*60}")
        print(msg, flush=True)

        last_snapshot = start_time
        snapshot_interval = 300
        last_checkpoint = time.time()
        checkpoint_interval = 600  # 10 min

        while time.time() < end_time:
            iteration += 1

            # Select template
            tmpl = random.choice(self._get_templates())
            path = tmpl["path"].replace("{id}", f"{context_id}-{random.randint(0,9999)}")
            method = tmpl["method"]
            op_name = tmpl["op"]

            # Select mutation strategy
            mutation_name = self._select_mutation(op_name, group)

            # Build and mutate request body
            if tmpl["body"]:
                body_str = json.dumps(tmpl["body"]).replace(
                    "{id}", f"{context_id}-{random.randint(0,9999)}")
                body_bytes = apply_mutation(body_str.encode(), mutation_name)
            else:
                body_bytes = None
            body_s = body_bytes.decode('utf-8', errors='replace') if body_bytes else None

            # Send to primary target
            code = self.send(method, path, body_bytes)

            # Detect crash event
            is_crash = (code == 0)

            # ── 3-way divergence reward (for G2+, unless PADO disabled) ──
            # Compare the SAME NF across free5gc / OAI / Open5GS, resolved
            # dynamically from the primary target's NF type.
            pado_reward = 0.0
            reason = "uniform"
            if group in ("G2", "G3", "G4", "G5") and not self.disable_pado:
                nf = self.name.split("-", 1)[1]
                impl = self.target.get("impl")
                statuses = {"free5gc": None, "oai": None, "open5gs": None}
                statuses[impl] = code  # primary response (already sent above)
                for other in ("free5gc", "oai", "open5gs"):
                    if other == impl:
                        continue
                    ep = TARGETS.get(f"{other}-{nf}")
                    if ep is None:
                        continue  # NF absent in this implementation (e.g. bsf/scp)
                    if ep["proto"] == "http2":
                        statuses[other] = h2_request(ep["host"], ep["port"], method, path, body_bytes)
                    else:
                        statuses[other] = http11_request(ep["host"], ep["port"], method, path, body_bytes)

                vals = [s for s in statuses.values() if s is not None]
                if len(vals) == 3:
                    pado_reward = compute_pado_reward(vals, self.pado_weights)
                    reason = classify_pado_reason(vals)
                else:
                    # Fewer than three implementations expose this NF; no
                    # 3-way divergence signal is available (reward stays 0).
                    reason = "no_reference"

                if pado_reward > 0:
                    results["cross_divergences"] += 1

                if reason not in ("uniform", "no_reference"):
                    key = f"{op_name}|{mutation_name}|{statuses['free5gc']}|{statuses['oai']}|{statuses['open5gs']}|{reason}"
                    results["divergence_counter"][key] = results["divergence_counter"].get(key, 0) + 1
                    results["divergence_reason_counter"][reason] = \
                        results["divergence_reason_counter"].get(reason, 0) + 1
                    if len(results["divergence_samples"]) < 200:
                        results["divergence_samples"].append({
                            "method": method,
                            "path": path,
                            "mutation": mutation_name,
                            "op": op_name,
                            "body": body_s,
                            "free5gc": statuses["free5gc"],
                            "oai": statuses["oai"],
                            "open5gs": statuses["open5gs"],
                            "primary": code,
                            "reason": reason,
                            "reward": pado_reward,
                        })

            # ── Compute reward ──
            if self.disable_pado:
                # Crash-only reward: no divergence taxonomy
                reward_val = 20.0 if is_crash else (5.0 if code >= 500 else (1.0 if code >= 400 else 0.0))
            else:
                reward_val = (
                    pado_reward if pado_reward > 0 else
                    20.0 if is_crash else
                    5.0 if code >= 500 else
                1.0 if 400 <= code < 500 else 0.0)

            if self._ns_bandit is not None:
                self._ns_bandit.reward(mutation_name, reward_val,
                                       crash_event=is_crash)
                # Regret tracking
                cumulative_regret += (optimal_reward - reward_val) / optimal_reward

            if self._cond_ts is not None:
                is_divergent = pado_reward > 0 or is_crash
                self._cond_ts.refine(op_name, mutation_name, code, is_divergent)

            if self._mt_sharing is not None:
                boost = (
                    5.0 if is_crash else
                    2.0 if pado_reward >= 15 else
                    0.5 if 400 <= code < 500 else 0.1)
                self._mt_sharing.update_local(op_name, mutation_name, boost)
                if iteration % 200 == 0:
                    self._mt_sharing.export_stats(iteration)
                    self._mt_sharing.import_stats()

            # Crash recovery tracking
            if is_crash:
                last_crash_iter = iteration
                post_crash_peak_reward = 0.0
                if self._ns_bandit is not None:
                    results["change_points"].append({
                        "iter": iteration, "type": "crash_restart",
                        "ns_bandit_cps": self._ns_bandit.num_change_points,
                    })
            elif iteration - last_crash_iter < 50 and reward_val > post_crash_peak_reward:
                post_crash_peak_reward = reward_val
                if post_crash_peak_reward >= 15:
                    recovery_iters = iteration - last_crash_iter
                    results["crash_recovery_iters"].append(recovery_iters)
                    last_crash_iter = -1000  # reset tracking

            # ── Record metrics ──
            results["requests"] += 1
            if is_crash:
                results["crashes"] += 1
                # Cap crash_details to bound memory + docker inspect overhead on
                # deterministic-crash targets (count is still tracked above).
                if len(results["crash_details"]) < 2000:
                    results["crash_details"].append({
                        "time": time.time(), "op": op_name,
                        "method": method, "path": path,
                        "mutation": mutation_name,
                        "body": body_s,
                        "container": f"fuzzing-{self.name}",
                        "restart_count": self._container_restart_count(),
                    })
            elif code < 200: results["http_1xx"] += 1
            elif code < 300: results["http_2xx"] += 1
            elif code < 400: results["http_3xx"] += 1
            elif code < 500: results["http_4xx"] += 1
            else: results["http_5xx"] += 1
            results["unique_status_codes"].add(code)

            new_state = f"{op_name}_{code//100}xx"
            results["fsm_states"][new_state] = results["fsm_states"].get(new_state, 0) + 1

            # Periodic snapshot
            if time.time() - last_snapshot > snapshot_interval:
                elapsed = (time.time() - start_time) / 3600
                snapshot = {
                    "elapsed_h": round(elapsed, 2),
                    "requests": results["requests"],
                    "crashes": results["crashes"],
                    "fsm_states": len(results["fsm_states"]),
                    "unique_codes": len(results["unique_status_codes"]),
                    "cumulative_regret": round(cumulative_regret, 1),
                }
                results["timeline"].append(snapshot)
                results["regret_curve"].append(
                    {"elapsed_h": round(elapsed, 2), "regret": round(cumulative_regret, 1)})

                # Grammar precision snapshot
                if self._cond_ts is not None:
                    precision = self._cond_ts.snapshot_precision()
                    results["grammar_precision"].append(precision)

                print(f"  [{elapsed:.1f}h] {results['requests']} reqs, "
                      f"{results['crashes']} crashes, "
                      f"{len(results['fsm_states'])} FSM states, "
                      f"regret={cumulative_regret:.0f}", flush=True)
                last_snapshot = time.time()

            # Periodic checkpoint (resume support, every 10 min)
            if time.time() - last_checkpoint > checkpoint_interval:
                self._save_checkpoint(out_dir, group, suffix, results,
                                      cumulative_regret, iteration, start_time,
                                      context_id, last_crash_iter,
                                      post_crash_peak_reward)
                last_checkpoint = time.time()

        # Finalize
        results["unique_status_codes"] = sorted(list(results["unique_status_codes"]))
        results["fsm_state_count"] = len(results["fsm_states"])
        results["completed"] = datetime.now().isoformat()

        # Algorithm-specific final stats
        if self._ns_bandit is not None:
            results["ns_bandit_stats"] = self._ns_bandit.get_stats()
            results["ns_bandit_change_points"] = self._ns_bandit.num_change_points
        if self._cond_ts is not None:
            results["cond_ts_stats"] = self._cond_ts.stats
        if self._mt_sharing is not None:
            results["mt_sharing_stats"] = self._mt_sharing.stats
            results["mt_transfer_benefit"] = self._mt_sharing.transfer_benefit()

        fn = f"{out_dir}/{self.name}_{group}{suffix}.json"
        with open(fn, "w") as f:
            json.dump(results, f, indent=2, default=list)
        ckpt_path = self._checkpoint_path(out_dir, group, suffix)
        if os.path.exists(ckpt_path):
            os.remove(ckpt_path)
        print(f"  -> {fn}")
        return results

    def run_baseline(self, baseline_name: str, mutator, out_dir: str):
        """Run an external baseline (AFLNet, StateAFL, Schemathesis, Boofuzz)."""
        start_time = time.time()
        end_time = start_time + self.hours * 3600
        is_stateafl = (baseline_name == "StateAFL")

        results = {
            "baseline": baseline_name, "target": self.name,
            "duration_h": self.hours, "started": datetime.now().isoformat(),
            "requests": 0, "crashes": 0, "http_1xx": 0, "http_2xx": 0,
            "http_3xx": 0, "http_4xx": 0, "http_5xx": 0,
            "unique_status_codes": set(), "crash_details": [],
            "timeline": [],
        }

        context_id = f"NF-{random.randint(1000, 9999)}"
        print(f"\n[{baseline_name}] {self.name} — {self.hours}h", flush=True)

        last_snapshot = start_time
        snapshot_interval = 300

        while time.time() < end_time:
            seed = self.state_pool.select_seed() if is_stateafl else None

            if seed and random.random() < 0.7:
                method, path, body_bytes = seed
                body_bytes = mutator(body_bytes) if body_bytes else None
            else:
                tmpl = random.choice(self._get_templates())
                path = tmpl["path"].replace("{id}", f"{context_id}-{random.randint(0,9999)}")
                method = tmpl["method"]
                body_str = json.dumps(tmpl["body"]).replace("{id}", f"{context_id}-{random.randint(0,9999)}") if tmpl["body"] else None
                body_bytes = mutator(body_str.encode()) if body_str else None

            code = self.send(method, path, body_bytes)

            if is_stateafl:
                self.state_pool.record(method, path, body_bytes, code)

            results["requests"] += 1
            if code == 0:
                results["crashes"] += 1
                results["crash_details"].append({"time": time.time(), "op": "unknown", "method": method, "path": path})
            elif code < 200: results["http_1xx"] += 1
            elif code < 300: results["http_2xx"] += 1
            elif code < 400: results["http_3xx"] += 1
            elif code < 500: results["http_4xx"] += 1
            else: results["http_5xx"] += 1
            results["unique_status_codes"].add(code)

            if time.time() - last_snapshot > snapshot_interval:
                elapsed = (time.time() - start_time) / 3600
                results["timeline"].append({
                    "elapsed_h": round(elapsed, 2),
                    "requests": results["requests"],
                    "crashes": results["crashes"],
                })
                print(f"  [{elapsed:.1f}h] {results['requests']} reqs, "
                      f"{results['crashes']} crashes", flush=True)
                last_snapshot = time.time()

        results["unique_status_codes"] = sorted(list(results["unique_status_codes"]))
        results["completed"] = datetime.now().isoformat()

        os.makedirs(out_dir, exist_ok=True)
        fn = f"{out_dir}/{self.name}_baseline_{baseline_name}.json"
        with open(fn, "w") as f:
            json.dump(results, f, indent=2, default=list)
        print(f"  -> {fn}")
        return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target",
                        choices=["free5gc-nrf", "free5gc-amf", "free5gc-smf", "free5gc-ausf",
                                 "free5gc-udm", "free5gc-udr", "free5gc-pcf", "free5gc-nssf",
                                 "oai-nrf", "oai-amf", "oai-ausf", "oai-smf", "oai-udm", "oai-udr", "oai-nssf", "oai-pcf",
                                 "open5gs-nrf", "open5gs-amf", "open5gs-smf", "open5gs-ausf", "open5gs-udm",
                                 "open5gs-udr", "open5gs-nssf", "open5gs-bsf", "open5gs-scp"],
                        required=True)
    parser.add_argument("--group",
                        choices=["G0", "G1", "G2", "G3", "G4", "G5", "all", "none"],
                        default="all",
                        help="Ablation group: G0=random, G1=SW-UCB, G2=+CondTS, "
                             "G3=+CrashReset, G4=+MTShare, G5=Full, none=skip ablation")
    parser.add_argument("--baseline",
                        choices=["aflnet", "stateafl", "schemathesis", "boofuzz", "all", "none"],
                        default="none",
                        help="External baselines to run")
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--disable-jksm", action="store_true",
                        help="Disable JSON key-space mutation (G4 minus JKSM ablation)")
    parser.add_argument("--disable-pado", action="store_true",
                        help="Disable PADO divergence oracle (G4 minus PADO ablation)")
    parser.add_argument("--seed", type=int, default=None,
                        help="Random seed (None = system default)")
    parser.add_argument("--reward-weights", type=str, default="30,25,15,5,0",
                        help="PADO reward weights: crash,3class,2class,sameclass,uniform")
    parser.add_argument("--tag", type=str, default="",
                        help="Extra suffix tag for output files")
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    pado_weights = tuple(int(x) for x in args.reward_weights.split(","))

    out_dir = f"{EXPERIMENT_DIR}/{args.target}"
    runner = ExperimentRunner(args.target, args.hours,
                              disable_jksm=args.disable_jksm,
                              disable_pado=args.disable_pado,
                              seed=args.seed,
                              pado_weights=pado_weights,
                              tag=args.tag)

    # Run ablation groups
    groups = ["G0", "G1", "G2", "G3", "G4", "G5"] if args.group == "all" else (
        [] if args.group == "none" else [args.group])
    for g in groups:
        runner.run(g, out_dir)

    # Run external baselines
    baselines = {
        "aflnet": aflnet_havoc,
        "stateafl": aflnet_havoc,
        "schemathesis": schemathesis_mutate,
        "boofuzz": boofuzz_mutate,
    }
    to_run = list(baselines.keys()) if args.baseline == "all" else (
        [] if args.baseline == "none" else [args.baseline])

    for key in to_run:
        runner.run_baseline(key, baselines[key], out_dir)

    print(f"\nDone. Results: {out_dir}/")


if __name__ == "__main__":
    main()
