"""PDU Session Establishment scenario — TS 23.502 Section 4.3.2.

Standard PDU Session Establishment flow:
  1. UE → AMF: PDU Session Establishment Request (NAS-SM in NAS-MM)
  2. AMF → SMF: Nsmf_PDUSession_CreateSMContext (SBI)
  3. SMF → UPF: PFCP Session Establishment (N4)
  4. SMF → AMF: N1N2MessageTransfer (SBI)
  5. AMF → UE: PDU Session Establishment Accept (NAS)
  6. UE → AMF: PDU Session Establishment Complete (optional)

Also includes the NGAP-level PDU Session Resource Setup
between AMF and gNB for the N3 tunnel.
"""

from src import ProtocolType
from src.stimulus.scenarios.common import (
    BenignScenario, Direction, ScenarioStep,
)


def make_pdu_session_scenario(
    pdu_session_id: int = 1,
    dnn: str = "internet",
    sst: int = 1,
    sd: str = "0x000001",
    supi: str = "001010123456789",
    n_runs: int = 20,
) -> BenignScenario:
    """Build a complete PDU Session Establishment trace.

    Covers NAS-SM, NGAP (PDU Session Resource Setup),
    and optionally PFCP (N4 session) and SBI (SMF-AMF).
    """
    return BenignScenario(
        name="PDU Session Establishment",
        description="Establish a PDU Session for user-plane connectivity",
        protocol=ProtocolType.NAS,
        procedure="pdu_session_establishment",
        n_runs=n_runs,
        steps=[
            # ─── NAS-SM: PDU Session Establishment Request ───
            ScenarioStep(
                "PDU Session Establishment Request",
                Direction.UPLINK,
                ProtocolType.NAS,
                fields={
                    "pdu_session_id": pdu_session_id,
                    "request_type": 1,  # Initial request
                    "ssc_mode": 1,  # SSC Mode 1
                    "pdu_session_type": 1,  # IPv4
                    "dnn": dnn,
                    "s_nssai": bytes([sst]),
                },
                description="UE initiates PDU Session via NAS-SM",
            ),
            # ─── NGAP: PDU Session Resource Setup (AMF → gNB) ───
            ScenarioStep(
                "PDUSessionResourceSetup",
                Direction.DOWNLINK,
                ProtocolType.NGAP,
                fields={
                    "amf_ue_ngap_id": 1,
                    "ran_ue_ngap_id": 1,
                    "pdu_session_id": pdu_session_id,
                    "pdu_session_resource_setup_list": bytes([0x00, 0x01, 0x02]),
                    "pdu_session_aggregate_maximum_bitrate": bytes(8),
                },
                description="AMF requests gNB to setup N3 tunnel resources",
            ),
            # ─── NGAP: PDU Session Resource Setup Response ───
            ScenarioStep(
                "PDUSessionResourceSetupResponse",
                Direction.UPLINK,
                ProtocolType.NGAP,
                fields={
                    "amf_ue_ngap_id": 1,
                    "ran_ue_ngap_id": 1,
                    "pdu_session_resource_setup_response_list": bytes([0x00, 0x01]),
                },
                description="gNB confirms N3 tunnel setup",
            ),
            # ─── NAS-SM: PDU Session Establishment Accept ───
            ScenarioStep(
                "PDU Session Establishment Accept",
                Direction.DOWNLINK,
                ProtocolType.NAS,
                fields={
                    "pdu_session_id": pdu_session_id,
                    "selected_pdu_session_type": 1,
                    "selected_ssc_mode": 1,
                    "qos_rules": bytes([0x01, 0x02]),
                    "session_ambr": bytes(8),
                    "pdu_address": bytes([0x0A, 0x00, 0x00, 0x01]),
                },
                description="SMF/AMF accept PDU Session via NAS",
            ),
        ],
    )


def make_pfcp_session_scenario(
    seid: int = 0x12345678,
    node_id: str = "10.0.0.1",
    n_runs: int = 20,
) -> BenignScenario:
    """Build a PFCP (N4) session establishment trace.

    Represents the SMF-UPF interaction during PDU Session setup.
    """
    from src import ProtocolType as Pt
    return BenignScenario(
        name="PFCP Session Establishment",
        description="SMF establishes an N4 session with UPF",
        protocol=ProtocolType.PFCP,
        procedure="pfcp_session_establishment",
        n_runs=n_runs,
        steps=[
            ScenarioStep(
                "PFCP Session Establishment Request",
                Direction.DOWNLINK,
                ProtocolType.PFCP,
                fields={
                    "node_id": node_id.encode(),
                    "f_seid": (seid.to_bytes(8, 'big') + b'\x00' * 8),
                    "create_pdr": bytes([0x01, 0x02, 0x00, 0x04]),
                    "create_far": bytes([0x02, 0x01, 0x00, 0x04]),
                    "pdn_type": 1,  # IPv4
                },
                description="SMF requests UPF to create forwarding rules",
            ),
            ScenarioStep(
                "PFCP Session Establishment Response",
                Direction.UPLINK,
                ProtocolType.PFCP,
                fields={
                    "f_seid": (seid.to_bytes(8, 'big') + b'\x00' * 8),
                    "cause": 1,  # Request accepted
                    "node_id": node_id.encode(),
                },
                description="UPF confirms N4 session with created rules",
            ),
        ],
    )
