"""5G Registration scenario — TS 23.502 Section 4.2.2.2.

Standard 5-step registration flow:
  1. UE → AMF: Registration Request
  2. AMF → AUSF/UDM: Authentication (AKA)
  3. AMF → UE: Authentication Request
  4. UE → AMF: Authentication Response
  5. AMF → UE: Security Mode Command
  6. UE → AMF: Security Mode Complete
  7. AMF → UE: Registration Accept
  8. UE → AMF: Registration Complete
"""

from src import ProtocolType
from src.stimulus.scenarios.common import (
    BenignScenario, Direction, ScenarioStep,
)


def make_registration_scenario(
    supi: str = "001010123456789",
    plmn: str = "00101",
    n_runs: int = 20,
) -> BenignScenario:
    """Build a complete 5G registration scenario trace.

    Args:
        supi: Subscriber Permanent Identifier
        plmn: PLMN ID (MCC+MNC)
        n_runs: Number of trace variants
    """
    return BenignScenario(
        name="5G Registration",
        description="Standard 5G initial registration with AKA authentication",
        protocol=ProtocolType.NAS,
        procedure="registration",
        n_runs=n_runs,
        steps=[
            ScenarioStep(
                "Registration Request",
                Direction.UPLINK,
                ProtocolType.NAS,
                fields={
                    "5gs_registration_type": 1,  # Initial Registration
                    "ng_ksi": 0,
                    "5gs_mobile_identity_supi": supi,
                },
                description="UE sends Registration Request to AMF",
            ),
            ScenarioStep(
                "Authentication Request",
                Direction.DOWNLINK,
                ProtocolType.NAS,
                fields={
                    "ng_ksi": 1,
                    "abba": bytes([0x00, 0x00]),
                    "authentication_parameter_rand": bytes(16),
                    "authentication_parameter_autn": bytes(16),
                },
                description="AMF forwards AKA challenge from AUSF",
            ),
            ScenarioStep(
                "Authentication Response",
                Direction.UPLINK,
                ProtocolType.NAS,
                fields={
                    "authentication_response_parameter": bytes(16),
                },
                description="UE responds with RES (authentication response)",
            ),
            ScenarioStep(
                "Security Mode Command",
                Direction.DOWNLINK,
                ProtocolType.NAS,
                fields={
                    "selected_nas_security_algorithms": bytes([0x02, 0x02]),  # NEA2, NIA2
                    "ng_ksi": 1,
                    "replayed_ue_security_capabilities": bytes([0x07, 0x00, 0x02, 0x02]),
                },
                description="AMF initiates NAS security setup",
            ),
            ScenarioStep(
                "Security Mode Complete",
                Direction.UPLINK,
                ProtocolType.NAS,
                fields={
                    "imei_sv": bytes([0x00]),  # optional IMEISV
                },
                description="UE confirms security mode",
            ),
            ScenarioStep(
                "Registration Accept",
                Direction.DOWNLINK,
                ProtocolType.NAS,
                fields={
                    "5gs_registration_result": 1,  # 3GPP Access
                    "equivalent_plmns": bytes([0x00, 0x00, 0x00]),
                    "tai_list": bytes(8),
                },
                description="AMF accepts registration",
            ),
            ScenarioStep(
                "Registration Complete",
                Direction.UPLINK,
                ProtocolType.NAS,
                fields={},
                description="UE acknowledges registration accept",
            ),
        ],
    )
