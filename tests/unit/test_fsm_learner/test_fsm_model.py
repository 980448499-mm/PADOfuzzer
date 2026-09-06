"""Unit tests for FSM model."""

import pytest
from src.fsm_learner.fsm_model import FSMState, FSMTransition, ProtocolFSM


class TestFSMState:
    def test_create_state(self):
        s = FSMState(name="INIT", is_initial=True)
        assert s.name == "INIT"
        assert s.is_initial is True

    def test_defaults(self):
        s = FSMState(name="TEST")
        assert s.is_accepting is False
        assert s.is_error is False

    def test_metadata(self):
        s = FSMState(name="S", metadata={"count": 5})
        assert s.metadata["count"] == 5


class TestFSMTransition:
    def test_create_transition(self):
        t = FSMTransition(
            from_state="INIT", to_state="REGISTERING",
            trigger="Registration Request",
        )
        assert t.from_state == "INIT"
        assert t.to_state == "REGISTERING"
        assert t.trigger == "Registration Request"
        assert t.probability == 1.0


class TestProtocolFSM:
    def test_create_empty_fsm(self):
        fsm = ProtocolFSM(protocol="nas-5gs", name="Registration")
        assert fsm.protocol == "nas-5gs"
        assert fsm.name == "Registration"
        assert fsm.initial_state is None

    def test_add_state(self):
        fsm = ProtocolFSM(protocol="nas", name="test")
        fsm.add_state("INIT", is_initial=True)
        assert "INIT" in fsm.states
        assert fsm.states["INIT"].is_initial
        assert fsm.initial_state == "INIT"

    def test_lookup_state(self):
        fsm = ProtocolFSM(protocol="nas", name="test")
        fsm.add_state("INIT")
        assert fsm.states.get("INIT") is not None
        assert "NONEXIST" not in fsm.states

    def test_state_count(self):
        fsm = ProtocolFSM(protocol="nas", name="test")
        fsm.add_state("S1")
        fsm.add_state("S2")
        fsm.add_state("S3")
        assert len(fsm.states) == 3

    def test_add_transition(self):
        fsm = ProtocolFSM(protocol="nas-5gs", name="Reg")
        fsm.add_transition("INIT", "REGISTERING", "Registration Request")
        assert len(fsm.transitions) == 1
        assert fsm.states["INIT"].name == "INIT"
        assert fsm.states["REGISTERING"].name == "REGISTERING"

    def test_get_outgoing(self):
        fsm = ProtocolFSM(protocol="nas", name="F")
        fsm.add_transition("S1", "S2", "msg_a")
        fsm.add_transition("S1", "S3", "msg_b")
        fsm.add_transition("S2", "S3", "msg_c")
        outgoing = fsm.get_outgoing("S1")
        assert len(outgoing) == 2

    def test_allowed_messages(self):
        fsm = ProtocolFSM(protocol="nas", name="F")
        fsm.message_type_map = {1: "msg_a", 2: "msg_b", 3: "msg_c"}
        fsm.add_transition("S1", "S2", "msg_a")
        allowed = fsm.get_allowed_messages("S1")
        assert "msg_a" in allowed
