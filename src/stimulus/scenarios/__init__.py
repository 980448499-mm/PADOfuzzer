"""Benign 5G scenario definitions for training trace generation.

Scenarios produce sequences of (message_type, direction, fields)
used to train FSM models and seed the fuzzing corpus.
"""

from src.stimulus.scenarios.common import ScenarioStep, BenignScenario
from src.stimulus.scenarios.registration import make_registration_scenario
from src.stimulus.scenarios.pdu_session import make_pdu_session_scenario, make_pfcp_session_scenario
