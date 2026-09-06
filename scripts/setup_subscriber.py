#!/usr/bin/env python3
"""Insert test subscriber into 5GC database for fuzzing.

This is required before running fuzzing — the 5GC needs
at least one provisioned UE to accept registration attempts.

Supports: Open5GS (MongoDB), free5GC (WebUI API), OAI (MySQL)

Usage:
  python scripts/setup_subscriber.py --target open5gs --supi 001010123456789 --key 00112233445566778899aabbccddeeff
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def setup_open5gs_subscriber(supi: str, key: str, opc: str) -> bool:
    """Insert a subscriber into Open5GS MongoDB."""
    try:
        from pymongo import MongoClient
    except ImportError:
        print("ERROR: pymongo not installed. Run: pip install pymongo")
        return False

    client = MongoClient("mongodb://172.23.0.120:27017/")
    db = client.open5gs

    # Subscriber document per Open5GS schema
    subscriber = {
        "_id": supi,
        "imsi": supi if supi.startswith("imsi-") else f"imsi-{supi}",
        "security": {
            "k": key,
            "opc": opc,
            "amf": "8000",
            "sqn": 0,
        },
        "ambr": {"downlink": {"value": 1, "unit": 3},
                  "uplink": {"value": 1, "unit": 3}},  # 1 Gbps
        "slice": [
            {
                "sst": 1,
                "sd": "000001",
                "default_indicator": True,
                "session": [
                    {
                        "name": "internet",
                        "type": 1,  # IPv4
                        "ambr": {"downlink": {"value": 1, "unit": 3},
                                  "uplink": {"value": 1, "unit": 3}},
                        "qos": {
                            "index": 9,  # 5QI 9
                            "arp": {"priority_level": 8,
                                     "pre_emption_capability": 1,
                                     "pre_emption_vulnerability": 1},
                        },
                        "pcc_rule": [],
                    }
                ],
            }
        ],
        "access_restriction_data": 32,  # NR not allowed
        "subscriber_status": 0,  # SERVICE_GRANTED
        "network_access_mode": 0,  # PACKET_AND_CIRCUIT
    }

    result = db.subscribers.replace_one(
        {"_id": supi}, subscriber, upsert=True
    )
    print(f"Subscriber {supi}: {'updated' if result.matched_count else 'inserted'}")
    client.close()
    return True


def setup_free5gc_subscriber(supi: str, key: str, opc: str) -> bool:
    """Insert subscriber via free5GC WebConsole API.

    Provisions a complete subscriber with authentication, access &
    mobility, and session management subscription data — the same
    triple required by the orchestrator's internal provisioning.
    """
    import httpx

    webui_url = "http://172.24.0.130:5000"
    ue_id = f"imsi-{supi}" if not supi.startswith("imsi-") else supi
    plmn_id = "00101"

    subscriber = {
        "plmnID": plmn_id,
        "ueId": ue_id,
        "AuthenticationSubscription": {
            "authenticationMethod": "5G_AKA",
            "permanentKey": {"permanentKeyValue": key},
            "sequenceNumber": "000000000000",
            "authenticationManagementField": "8000",
            "milenage": {"op": {"opValue": ""}},
            "opc": {"opcValue": opc},
        },
        "AccessAndMobilitySubscriptionData": {
            "servingPlmnId": plmn_id,
            "subscribedUeAmbr": {
                "uplink": "1 Gbps",
                "downlink": "1 Gbps",
            },
            "nssai": {
                "defaultSingleNssais": [
                    {"sst": 1, "sd": "010203"},
                ],
            },
        },
        "SessionManagementSubscriptionData": [
            {
                "singleNssai": {"sst": 1, "sd": "010203"},
                "dnnConfigurations": {
                    "internet": {
                        "pduSessionTypes": {
                            "defaultSessionType": "IPV4",
                            "allowedSessionTypes": ["IPV4"],
                        },
                        "sscModes": {
                            "defaultSscMode": "SSC_MODE_1",
                            "allowedSscModes": ["SSC_MODE_1"],
                        },
                        "5gQosProfile": {
                            "5qi": 9,
                            "arp": {"priorityLevel": 8},
                            "priorityLevel": 8,
                        },
                        "sessionAmbr": {
                            "uplink": "1 Gbps",
                            "downlink": "1 Gbps",
                        },
                    },
                },
            },
        ],
    }

    try:
        resp = httpx.post(
            f"{webui_url}/api/subscriber/{ue_id}/{plmn_id}",
            json=subscriber, timeout=10,
        )
        if resp.status_code in (200, 201):
            print(f"free5GC subscriber {supi}: created (full profile)")
            return True
        else:
            print(f"free5GC API error: {resp.status_code} {resp.text[:200]}")
            return False
    except httpx.ConnectError:
        print("ERROR: Cannot connect to free5GC WebUI. Is it deployed?")
        return False


def setup_oai_subscriber(supi: str, key: str, opc: str) -> bool:
    """Insert subscriber into OAI 5G Core MySQL database (oai_db).

    OAI stores subscriber authentication and subscription data in
    MySQL.  The AMF reads these tables directly at UE registration
    time — there is no intermediate WebUI.

    Uses ``docker exec`` to run the ``mysql`` CLI inside the OAI
    MySQL container so that networking / credentials are handled
    automatically.
    """
    import subprocess

    # Locate the OAI MySQL container
    for fallback in ("oai-mysql", "mysql"):
        try:
            result = subprocess.run(
                ["docker", "ps", "-q", "-f", f"name=^{fallback}$"],
                capture_output=True, text=True, timeout=10,
            )
            container_id = result.stdout.strip()
            if container_id:
                break
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print("ERROR: docker not available")
            return False
    else:
        print(
            "ERROR: OAI MySQL container not found. "
            "Deploy OAI first: "
            "python scripts/deploy_and_fuzz.py --target oai --deploy-only"
        )
        return False

    sql = (
        # ── Ensure tables exist ──────────────────────────────
        "CREATE TABLE IF NOT EXISTS AuthenticationSubscription ("
        "  ueid VARCHAR(20) NOT NULL PRIMARY KEY,"
        "  authenticationMethod VARCHAR(20) NOT NULL DEFAULT '5G_AKA',"
        "  encPermanentKey VARCHAR(128) NOT NULL,"
        "  protectionParameterId VARCHAR(128) NOT NULL,"
        "  sequenceNumber VARCHAR(128) NOT NULL,"
        "  authenticationManagementField VARCHAR(10) NOT NULL DEFAULT '8000',"
        "  algorithmId VARCHAR(10) NOT NULL DEFAULT 'milenage',"
        "  encOpcKey VARCHAR(128) NOT NULL,"
        "  encTopcKey VARCHAR(128) DEFAULT NULL,"
        "  vectorGenerationInHss VARCHAR(1) NOT NULL DEFAULT '1',"
        "  n5gcAuthMethod VARCHAR(20) NOT NULL DEFAULT 'EAP_AKA_PRIME',"
        "  rgAuthenticationInd VARCHAR(1) NOT NULL DEFAULT '0',"
        "  supi VARCHAR(20) DEFAULT NULL"
        ");"
        ""
        "CREATE TABLE IF NOT EXISTS AccessAndMobilitySubscriptionData ("
        "  ueid VARCHAR(20) NOT NULL PRIMARY KEY,"
        "  servingPlmnId VARCHAR(15) NOT NULL DEFAULT '00101',"
        "  subscribedUeAmbrDown VARCHAR(20) DEFAULT '1 Gbps',"
        "  subscribedUeAmbrUp VARCHAR(20) DEFAULT '1 Gbps',"
        "  nssaiDefaultSst INT DEFAULT 1,"
        "  nssaiDefaultSd VARCHAR(6) DEFAULT '010203'"
        ");"
        ""
        "CREATE TABLE IF NOT EXISTS SessionManagementSubscriptionData ("
        "  id INT AUTO_INCREMENT PRIMARY KEY,"
        "  ueid VARCHAR(20) NOT NULL,"
        "  servingPlmnId VARCHAR(15) DEFAULT '00101',"
        "  singleNssaiSst INT DEFAULT 1,"
        "  singleNssaiSd VARCHAR(6) DEFAULT '010203',"
        "  dnn VARCHAR(50) DEFAULT 'default',"
        "  defaultSessionType VARCHAR(10) DEFAULT 'IPV4',"
        "  sscMode VARCHAR(20) DEFAULT 'SSC_MODE_1',"
        "  5qi INT DEFAULT 9,"
        "  priorityLevel INT DEFAULT 8,"
        "  sessionAmbrDown VARCHAR(20) DEFAULT '1 Gbps',"
        "  sessionAmbrUp VARCHAR(20) DEFAULT '1 Gbps'"
        ");"
        ""
        # ── Upsert authentication subscription ───────────────
        f"REPLACE INTO AuthenticationSubscription ("
        f"  ueid, authenticationMethod, encPermanentKey,"
        f"  protectionParameterId, sequenceNumber,"
        f"  authenticationManagementField, algorithmId,"
        f"  encOpcKey, vectorGenerationInHss,"
        f"  n5gcAuthMethod, rgAuthenticationInd, supi"
        f") VALUES ("
        f"  '{supi}', '5G_AKA',"
        f"  '{key}',"
        f"  '{key}',"
        f"  '000000000000', '8000', 'milenage',"
        f"  '{opc}',"
        f"  '1', 'EAP_AKA_PRIME', '0', '{supi}'"
        f");"
        ""
        # ── Upsert AM subscription data ──────────────────────
        f"REPLACE INTO AccessAndMobilitySubscriptionData ("
        f"  ueid, servingPlmnId, subscribedUeAmbrDown,"
        f"  subscribedUeAmbrUp, nssaiDefaultSst, nssaiDefaultSd"
        f") VALUES ("
        f"  '{supi}', '00101', '1 Gbps', '1 Gbps', 1, '010203'"
        f");"
        ""
        # ── Upsert SM subscription data ──────────────────────
        f"REPLACE INTO SessionManagementSubscriptionData ("
        f"  id, ueid, servingPlmnId, singleNssaiSst, singleNssaiSd,"
        f"  dnn, defaultSessionType, sscMode, 5qi,"
        f"  priorityLevel, sessionAmbrDown, sessionAmbrUp"
        f") VALUES ("
        f"  1, '{supi}', '00101', 1, '010203',"
        f"  'default', 'IPV4', 'SSC_MODE_1', 9, 8, '1 Gbps', '1 Gbps'"
        f");"
    )

    cmd = [
        "docker", "exec", "-i", container_id,
        "mysql", "-u", "root", "-poai_password", "oai_db",
    ]
    try:
        result = subprocess.run(
            cmd, input=sql, capture_output=True, text=True, timeout=60,
        )
    except subprocess.TimeoutExpired:
        print("ERROR: MySQL insert timed out")
        return False

    if result.returncode == 0:
        print(f"OAI subscriber {supi}: provisioned")
        print(
            "  Tables: AuthenticationSubscription, "
            "AccessAndMobilitySubscriptionData, "
            "SessionManagementSubscriptionData"
        )
        return True

    print(f"OAI MySQL error (exit {result.returncode}):")
    print(result.stderr[:800] if result.stderr else "(no stderr)")
    return False


def main():
    parser = argparse.ArgumentParser(description="Setup 5GC test subscriber")
    parser.add_argument("--target", choices=["open5gs", "free5gc", "oai"],
                       default="open5gs")
    parser.add_argument("--supi", default="001010000000001")
    parser.add_argument("--key", default="00112233445566778899aabbccddeeff")
    parser.add_argument("--opc", default="63bfa50ee6523365ff14c1f45f88737d")
    args = parser.parse_args()

    setup_funcs = {
        "open5gs": setup_open5gs_subscriber,
        "free5gc": setup_free5gc_subscriber,
        "oai": setup_oai_subscriber,
    }

    func = setup_funcs[args.target]
    success = func(args.supi, args.key, args.opc)

    if success:
        print(f"Subscriber {args.supi} ready for fuzzing")


if __name__ == "__main__":
    main()
