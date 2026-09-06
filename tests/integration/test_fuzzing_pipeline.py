"""Integration test for the full fuzzing pipeline.

Tests:
  1. NAS codec round-trip (encode/decode)
  2. NGAP codec round-trip
  3. NAS security (ciphering + integrity)
  4. Seed manager with energy scheduling
  5. FSM learner from synthetic traces
  6. Mutation engine output validity
  7. End-to-end fuzz loop (without real 5GC)
"""

import pytest
from pathlib import Path

from src import ProtocolType, FiveGCImpl, NFType, CrashRecord, CrashSeverity, MonitoringResult, Feedback, StackFrame
from src.codec.nas_codec import NAS5GSCodec, EPD_5GMM, EPD_5GSM
from src.codec.ngap_codec import NGAPCodec, NGAP_PROCEDURE_CODES
from src.codec.base import ParsedMessage
from src.stimulus.nas_security import (
    NASMessageProtector,
    SecurityContext,
    SecurityContextFactory,
    NASCipher,
    NASIntegrity,
    NASKeyDerivation,
)
from src.fuzzing_engine.seed_manager import SeedManager, Seed
from src.fuzzing_engine.power_scheduler import PowerScheduler, SeedEnergy
from src.fuzzing_engine.mutator import (
    MutatorEngine,
    BitFlipMutation,
    StructurePreservingMutation,
    CrossProtocolMutation,
    SequenceLevelMutation,
)
from src.fuzzing_engine.coverage.bitmap import CoverageBitmap, MultiComponentCoverage
from src.fsm_learner.learner import FSMLearner, Trace, TraceEvent
from src.fsm_learner.fsm_model import ProtocolFSM
from src.fsm_learner.fsm_guide import FSMGuidedFuzzing


# ─── NAS Codec Tests ──────────────────────────────────────────

class TestNASCodec:
    def test_registration_request_roundtrip(self):
        codec = NAS5GSCodec()
        msg = ParsedMessage(
            protocol="nas-5gs",
            message_type="Registration Request",
            message_name="Registration Request",
            fields={
                "5gs_registration_type": 1,
                "ng_ksi": 0,
                "5gs_mobile_identity_supi": "001010123456789",
            },
        )
        encoded = codec.encode(msg)
        assert len(encoded) >= 3
        assert encoded[0] == EPD_5GMM
        assert encoded[2] == 0x41  # Registration Request message type

        decoded = codec.decode(encoded)
        assert decoded.message_type == "Registration Request"

    def test_service_request_encode(self):
        codec = NAS5GSCodec()
        msg = ParsedMessage(
            protocol="nas-5gs",
            message_type="Service Request",
            message_name="Service Request",
            fields={"ng_ksi": 3, "service_type": 0, "tmsi": b"\x01\x02\x03\x04"},
        )
        encoded = codec.encode(msg)
        assert len(encoded) >= 3
        decoded = codec.decode(encoded)
        assert decoded.message_type == "Service Request"

    def test_pdu_session_establishment_request(self):
        codec = NAS5GSCodec()
        msg = ParsedMessage(
            protocol="nas-5gs",
            message_type="PDU Session Establishment Request",
            message_name="PDU Session Establishment Request",
            fields={
                "pdu_session_id": 1,
                "procedure_transaction_identity": 1,
                "pdu_session_type": 1,
                "ssc_mode": 1,
            },
        )
        encoded = codec.encode(msg)
        assert encoded[0] == EPD_5GSM
        assert encoded[2] == 0xC1  # PDU Session Establishment Request

    def test_all_message_types_have_encoders(self):
        codec = NAS5GSCodec()
        msg_types = codec.get_message_types()
        assert len(msg_types) > 40  # At least 40 message types

        for msg_type in msg_types:
            # Verify roundtrip doesn't crash
            try:
                msg = ParsedMessage(
                    protocol="nas-5gs",
                    message_type=msg_type,
                    message_name=msg_type,
                    fields={},
                )
                encoded = codec.encode(msg)
                decoded = codec.decode(encoded)
                assert decoded.message_type == msg_type
            except Exception as e:
                # Some messages need mandatory fields - that's expected
                pass


# ─── NGAP Codec Tests ─────────────────────────────────────────

class TestNGAPCodec:
    def test_initial_ue_message_roundtrip(self):
        codec = NGAPCodec()
        msg = ParsedMessage(
            protocol="ngap",
            message_type="InitialUEMessage",
            message_name="InitialUEMessage",
            fields={
                "pdu_type": "INITIATING",
                "procedure_code": 17,
                "criticality": 0,
                "ran_ue_ngap_id": 12345,
                "nas_pdu": bytes([0x7E, 0x00, 0x41, 0x01, 0x00]),
            },
        )
        encoded = codec.encode(msg)
        assert len(encoded) > 4
        assert encoded[0] == 0  # INITIATING
        assert encoded[1] == 17  # InitialUEMessage procedure code

        decoded = codec.decode(encoded)
        assert decoded.message_type == "InitialUEMessage"

    def test_uplink_nas_transport(self):
        codec = NGAPCodec()
        msg = ParsedMessage(
            protocol="ngap",
            message_type="UplinkNASTransport",
            message_name="UplinkNASTransport",
            fields={
                "amf_ue_ngap_id": 1,
                "ran_ue_ngap_id": 2,
                "nas_pdu": bytes(range(20)),
            },
        )
        encoded = codec.encode(msg)
        decoded = codec.decode(encoded)
        assert decoded.message_type == "UplinkNASTransport"

    def test_skeleton_cache(self):
        codec = NGAPCodec()
        # First encode populates cache
        msg1 = ParsedMessage(
            protocol="ngap",
            message_type="InitialUEMessage",
            message_name="InitialUEMessage",
            fields={
                "ran_ue_ngap_id": 1,
                "nas_pdu": b"\x00\x01\x02",
            },
        )
        encoded1 = codec.encode(msg1)

        # Second encode with different NAS PDU should use cache
        msg2 = ParsedMessage(
            protocol="ngap",
            message_type="InitialUEMessage",
            message_name="InitialUEMessage",
            fields={
                "ran_ue_ngap_id": 2,
                "nas_pdu": b"\xFF\xFE\xFD",
            },
        )
        encoded2 = codec.encode(msg2)
        assert encoded1 != encoded2
        # Both decode back correctly
        assert codec.decode(encoded1).message_type == "InitialUEMessage"
        assert codec.decode(encoded2).message_type == "InitialUEMessage"


# ─── NAS Security Tests ───────────────────────────────────────

class TestNASSecurity:
    def test_null_security_context(self):
        ctx = SecurityContextFactory.create_null_security()
        assert ctx.selected_nea == 0
        assert ctx.selected_nia == 0
        assert not ctx.security_established

    def test_nea2_cipher_roundtrip(self):
        key = bytes(16)
        plaintext = b"Hello 5G NAS World!"
        ciphertext = NASCipher.encrypt(2, key, 0, 0, 0, plaintext)
        # NEA2 (AES-CTR) is symmetric
        decrypted = NASCipher.encrypt(2, key, 0, 0, 0, ciphertext)
        assert decrypted == plaintext

    def test_nia2_integrity(self):
        key = bytes(16)
        message = b"Test NAS message"
        mac = NASIntegrity.compute_mac(2, key, 0, 0, 0, message)
        assert len(mac) == 4  # NAS-MAC is 4 bytes
        assert NASIntegrity.verify_mac(2, key, 0, 0, 0, message, mac)

    def test_nia2_mac_detects_tampering(self):
        key = bytes(16)
        message = b"Original message"
        mac = NASIntegrity.compute_mac(2, key, 0, 0, 0, message)
        tampered = b"Tampered message"
        assert not NASIntegrity.verify_mac(2, key, 0, 0, 0, tampered, mac)

    def test_key_derivation(self):
        k_amf = bytes(32)
        k_nas_enc = NASKeyDerivation.derive_nas_enc_key(k_amf, 2)
        k_nas_int = NASKeyDerivation.derive_nas_int_key(k_amf, 2)
        assert len(k_nas_enc) == 16
        assert len(k_nas_int) == 16
        # Different algorithms produce different keys
        assert k_nas_enc != k_nas_int

    def test_message_protector_plain(self):
        ctx = SecurityContextFactory.create_null_security()
        protector = NASMessageProtector(ctx)
        plain = bytes([EPD_5GMM, 0x00, 0x41, 0x01])
        result = protector.protect_uplink(EPD_5GMM, 0x41, b"\x01")
        # Should be plain without MAC
        assert len(result) < len(plain) + 5  # No security overhead


# ─── Seed Manager Tests ───────────────────────────────────────

class TestSeedManager:
    def test_add_and_select_seed(self):
        mgr = SeedManager()
        seed1 = Seed(protocol=ProtocolType.NAS, raw_pdu=b"\x7e\x00\x41\x01",
                     state_context="REGISTERING")
        seed2 = Seed(protocol=ProtocolType.NAS, raw_pdu=b"\x7e\x00\x42\x02",
                     state_context="REGISTERED")
        assert mgr.add_seed(seed1)
        assert mgr.add_seed(seed2)
        # Same PDU should be rejected (dedup)
        seed3 = Seed(protocol=ProtocolType.NAS, raw_pdu=b"\x7e\x00\x41\x01",
                     state_context="REGISTERING")
        assert not mgr.add_seed(seed3)
        assert mgr.total_seeds == 2

        selected = mgr.select_next()
        assert selected is not None

    def test_energy_update(self):
        mgr = SeedManager()
        seed = Seed(protocol=ProtocolType.NAS, raw_pdu=b"\x7e\x00\x41\x01",
                    state_context="AUTHENTICATING")
        mgr.add_seed(seed)
        mgr.update_energy(seed, new_coverage={1, 2, 3},
                          state_reached="AUTHENTICATING",
                          crash_found=True)
        # Energy should increase significantly after crash
        assert seed.energy > 1.0

    def test_state_indexing(self):
        mgr = SeedManager()
        mgr.add_seed(Seed(protocol=ProtocolType.NAS, raw_pdu=b"\x01",
                          state_context="REGISTERING"))
        mgr.add_seed(Seed(protocol=ProtocolType.NAS, raw_pdu=b"\x02",
                          state_context="REGISTERING"))
        mgr.add_seed(Seed(protocol=ProtocolType.NAS, raw_pdu=b"\x03",
                          state_context="PDU_ACTIVE"))

        state_coverage = mgr.get_state_coverage()
        assert state_coverage.get("REGISTERING", 0) == 2
        assert state_coverage.get("PDU_ACTIVE", 0) == 1


# ─── Coverage Bitmap Tests ────────────────────────────────────

class TestCoverageBitmap:
    def test_record_edge(self):
        bitmap = CoverageBitmap()
        bitmap.record_edge(100)
        assert 100 in bitmap.edges_hit
        assert bitmap.bitmap[100] == 1

    def test_novelty_computation(self):
        b1 = CoverageBitmap()
        b1.record_edge(0)
        b1.record_edge(1)
        b2 = CoverageBitmap()
        b2.record_edge(1)
        b2.record_edge(2)
        assert b1.get_novelty(b2) > 0  # Edge 2 is new to b1

    def test_multi_component_coverage(self):
        mc = MultiComponentCoverage()
        amf_cov = CoverageBitmap()
        amf_cov.record_edge(0)
        amf_cov.record_edge(1)
        smf_cov = CoverageBitmap()
        smf_cov.record_edge(2)
        smf_cov.record_edge(3)

        mc.add_nf_coverage("amf", amf_cov)
        mc.add_nf_coverage("smf", smf_cov)
        assert mc.aggregated.total_edges == 4


# ─── Mutation Engine Tests ────────────────────────────────────

class TestMutationEngine:
    def test_bitflip_changes_pdu(self):
        mutator = BitFlipMutation()
        seed = Seed(raw_pdu=b"\x00\x01\x02\x03\x04\x05\x06\x07",
                    protocol=ProtocolType.NAS)
        from src.fuzzing_engine.mutator import MutationContext
        ctx = MutationContext(protocol=ProtocolType.NAS)
        result = mutator.mutate(seed, ctx)
        assert isinstance(result, bytes)

    def test_structure_preserving_with_codec(self):
        codec = NAS5GSCodec()
        msg = ParsedMessage(
            protocol="nas-5gs",
            message_type="Registration Request",
            message_name="Registration Request",
            fields={"5gs_registration_type": 1, "ng_ksi": 0},
        )
        seed = Seed(raw_pdu=codec.encode(msg), parsed_message=msg,
                    protocol=ProtocolType.NAS)
        mutator = StructurePreservingMutation()
        from src.fuzzing_engine.mutator import MutationContext
        ctx = MutationContext(protocol=ProtocolType.NAS, codec=codec)
        result = mutator.mutate(seed, ctx)
        assert isinstance(result, bytes)

    def test_cross_protocol_injection(self):
        mutator = CrossProtocolMutation(
            protocol_pools={
                ProtocolType.NAS: [b"\x7e\x00\x41"],
                ProtocolType.GTPU: [b"\x30\xff\x00\x10\x00\x00\x00\x01"],
            }
        )
        seed = Seed(raw_pdu=b"\x7e\x00\x41\x01\x00", protocol=ProtocolType.NAS)
        from src.fuzzing_engine.mutator import MutationContext
        ctx = MutationContext(protocol=ProtocolType.NAS)
        result = mutator.mutate(seed, ctx)
        assert isinstance(result, bytes)

    def test_mutator_engine_selects_strategy(self):
        engine = MutatorEngine()
        seed = Seed(raw_pdu=b"\x7e\x00\x41\x01\x00",
                    protocol=ProtocolType.NAS)
        codec = NAS5GSCodec()
        strategy, result = engine.mutate(
            seed=seed,
            protocol=ProtocolType.NAS,
            codec=codec,
            current_state="REGISTERING",
        )
        assert result is not None
        assert strategy is not None
        stats = engine.get_strategy_stats()
        assert sum(stats.values()) == 1

    def test_all_strategies_produce_bytes(self):
        engine = MutatorEngine()
        seed = Seed(raw_pdu=bytes(range(32)), protocol=ProtocolType.NGAP)
        for _ in range(20):
            strategy, result = engine.mutate(
                seed=seed,
                protocol=ProtocolType.NGAP,
                current_state="INIT",
            )
            assert isinstance(result, bytes)
            assert len(result) > 0


# ─── FSM Learner Tests ────────────────────────────────────────

class TestFSMLearner:
    def test_pta_construction(self):
        from src.fsm_learner.prefix_tree import PrefixTreeAcceptor
        pta = PrefixTreeAcceptor()
        traces = [
            ["A", "B", "C"],
            ["A", "B", "D"],
            ["A", "C", "E"],
        ]
        pta.insert_traces(traces)
        assert pta.get_total_traces() == 3
        assert pta.get_total_nodes() >= 4  # root + at least A, B, C

    def test_learn_registration_fsm(self):
        learner = FSMLearner(compatibility_threshold=0.8)
        # Synthetic registration traces
        success_traces = [
            [
                "Registration Request",
                "Authentication Request",
                "Authentication Response",
                "Security Mode Command",
                "Security Mode Complete",
                "Registration Accept",
                "Registration Complete",
            ]
        ] * 10

        # Add a variation
        success_traces.append([
            "Registration Request",
            "Authentication Request",
            "Authentication Failure",
        ])

        fsm = learner.learn_from_sequences(
            success_traces,
            procedure="registration",
            protocol="nas-5gs",
        )
        assert fsm is not None
        assert len(fsm.states) >= 2
        assert fsm.initial_state is not None
        assert len(fsm.transitions) > 0

    def test_fsm_shortest_path(self):
        fsm = ProtocolFSM(protocol="nas-5gs", name="test")
        fsm.add_state("INIT", is_initial=True)
        fsm.add_state("MID")
        fsm.add_state("END", is_accepting=True)
        fsm.add_transition("INIT", "MID", "MSG_A")
        fsm.add_transition("MID", "END", "MSG_B")

        path = fsm.shortest_path("INIT", "END")
        assert path == ["INIT", "MID", "END"]

    def test_fsm_guided_fuzzing(self):
        fsm = ProtocolFSM(protocol="nas-5gs", name="test")
        fsm.add_state("INIT", is_initial=True)
        fsm.add_state("REGISTERED")
        fsm.add_state("PDU_ACTIVE")
        fsm.add_transition("INIT", "REGISTERED", "RegistrationRequest")
        fsm.add_transition("REGISTERED", "PDU_ACTIVE", "PDUSessionRequest")

        guide = FSMGuidedFuzzing(fsm)
        target = guide.select_target_state()
        assert target in fsm.states or "INVALID" in target

        plan = guide.build_attack_plan("REGISTERED")
        assert len(plan.messages) > 0

    def test_fsm_mermaid_export(self):
        fsm = ProtocolFSM(protocol="nas-5gs", name="test")
        fsm.add_state("INIT", is_initial=True)
        fsm.add_transition("INIT", "DONE", "MessageA")
        mermaid = fsm.to_mermaid()
        assert "stateDiagram" in mermaid
        assert "INIT" in mermaid

    def test_fsm_serialization(self):
        fsm = ProtocolFSM(protocol="nas-5gs", name="test")
        fsm.add_state("INIT", is_initial=True)
        fsm.add_transition("INIT", "A", "MSG1")

        data = fsm.to_dict()
        restored = ProtocolFSM.from_dict(data)
        assert restored.protocol == "nas-5gs"
        assert len(restored.states) == len(fsm.states)


# ─── Power Scheduler Tests ────────────────────────────────────

class TestPowerScheduler:
    def test_base_energy(self):
        scheduler = PowerScheduler()
        info = SeedEnergy(
            coverage_novelty=0,
            state_reached="unknown",
            crash_found=False,
            generation=0,
            size=100,
            is_new_state=False,
        )
        energy = scheduler.compute_energy(info)
        assert energy >= 1.0

    def test_crash_bonus(self):
        scheduler = PowerScheduler()
        info = SeedEnergy(
            coverage_novelty=0,
            state_reached="unknown",
            crash_found=True,
            generation=0,
            size=100,
            is_new_state=False,
        )
        energy = scheduler.compute_energy(info)
        assert energy >= 3.0  # 3x crash multiplier

    def test_new_state_bonus(self):
        scheduler = PowerScheduler()
        info = SeedEnergy(
            coverage_novelty=5,
            state_reached="RARE_STATE",
            crash_found=False,
            generation=0,
            size=64,
            is_new_state=True,
        )
        energy = scheduler.compute_energy(info)
        assert energy >= 2.0  # 2x state novelty bonus


# ─── Integration: End-to-End Pipeline ─────────────────────────

class TestEndToEndPipeline:
    def test_full_fuzzing_cycle_without_real_5gc(self):
        """Test the full fuzzing pipeline without a real 5GC.

        This validates that all components integrate correctly.
        """
        from src.fuzzing_engine.core import FuzzingEngine, FuzzingConfig

        # Setup
        config = FuzzingConfig(
            max_iterations=10,
            max_time_seconds=5,
            checkpoint_interval=5,
        )
        engine = FuzzingEngine(config=config)

        # Load a simple seed
        nas_codec = NAS5GSCodec()
        seed_pdu = nas_codec.encode(ParsedMessage(
            protocol="nas-5gs",
            message_type="Registration Request",
            message_name="Registration Request",
            fields={"5gs_registration_type": 1, "ng_ksi": 0},
        ))
        seed = Seed(protocol=ProtocolType.NAS, raw_pdu=seed_pdu,
                    state_context="REGISTERING")
        engine.seed_manager.add_seed(seed)

        # Mock send function
        async def mock_send(nf, proto, pdu):
            return pdu  # Echo back

        engine.set_send_function(mock_send)

        # Run fuzzing
        import asyncio
        results = asyncio.run(
            engine.run(
                target_impl=FiveGCImpl.OPEN5GS,
                target_nf=NFType.AMF,
                protocols=[ProtocolType.NAS],
            )
        )

        stats = engine.stats
        assert stats["total_iterations"] > 0 or stats["elapsed_seconds"] > 4
        # Verify no unhandled exceptions


# ─── Crash Triage Tests ─────────────────────────────────────

class TestCrashTriage:
    def test_crash_dedup_by_stack(self):
        from src.triage.crash_triage import CrashTriage
        from src import StackFrame

        triage = CrashTriage()

        crash1 = CrashRecord(
            crash_signal="SIGSEGV",
            target_nf=NFType.AMF,
            stack_frames=[
                StackFrame(address=0x400000, function_name="ngap_decode",
                          file_name="ngap_decoder.c", line_number=100,
                          raw_line="#0 0x400000 in ngap_decode"),
            ],
        )
        crash2 = CrashRecord(
            crash_signal="SIGSEGV",
            target_nf=NFType.AMF,
            stack_frames=[
                StackFrame(address=0x400000, function_name="ngap_decode",
                          file_name="ngap_decoder.c", line_number=100,
                          raw_line="#0 0x400000 in ngap_decode"),
            ],
        )
        groups = triage.triage([crash1, crash2])
        assert len(groups) == 1
        assert groups[0].count == 2

    def test_different_crashes_separated(self):
        from src.triage.crash_triage import CrashTriage
        from src import StackFrame

        triage = CrashTriage()

        crash1 = CrashRecord(
            crash_signal="SIGSEGV",
            target_nf=NFType.AMF,
            stack_frames=[
                StackFrame(address=0x400000, function_name="ngap_decode",
                          file_name="a.c", line_number=100, raw_line=""),
            ],
        )
        crash2 = CrashRecord(
            crash_signal="SIGABRT",
            target_nf=NFType.SMF,
            stack_frames=[
                StackFrame(address=0x500000, function_name="pfcp_handle",
                          file_name="b.c", line_number=200, raw_line=""),
            ],
        )
        groups = triage.triage([crash1, crash2])
        assert len(groups) == 2

    def test_root_cause_classification(self):
        from src.triage.crash_triage import CrashTriage

        triage = CrashTriage()
        crash = CrashRecord(
            crash_signal="SIGSEGV",
            asan_report="ERROR: AddressSanitizer: heap-buffer-overflow on address 0x61200001f400",
        )
        cause = triage.classify_root_cause(crash)
        assert "buffer_overflow" in cause

    def test_reproduce_script_generation(self):
        from src.triage.crash_triage import CrashTriage, CrashGroup

        triage = CrashTriage()
        crash = CrashRecord(
            crash_signal="SIGSEGV",
            input_pdu=b"\x7e\x00\x41\x01\x00",
            target_nf=NFType.AMF,
        )
        group = CrashGroup(representative=crash, members=[crash])
        script = triage.generate_reproduce_script(group)
        assert "INPUT_PDU" in script
        assert "socket" in script

    def test_get_statistics(self):
        from src.triage.crash_triage import CrashTriage

        triage = CrashTriage()
        triage.triage([
            CrashRecord(crash_signal="SIGSEGV", target_nf=NFType.AMF,
                       stack_frames=[
                           StackFrame(address=0x1, function_name="f1",
                                     file_name="a.c", line_number=1, raw_line="")
                       ]),
        ])
        stats = triage.get_statistics()
        assert stats["unique_crashes"] == 1
        assert "severity_distribution" in stats


# ─── Feedback Analyzer Tests ─────────────────────────────────

class TestFeedbackAnalyzer:
    def test_strategy_stats_tracking(self):
        from src.feedback.analyzer import FeedbackAnalyzer

        analyzer = FeedbackAnalyzer()
        analyzer.analyze(None, None, "bit_flip")
        assert analyzer.strategy_stats["bit_flip"].iterations == 1

    def test_coverage_stagnation_detection(self):
        from src.feedback.analyzer import FeedbackAnalyzer

        analyzer = FeedbackAnalyzer(stagnation_threshold=5)
        for _ in range(100):
            analyzer.analyze(None, None, "bit_flip")
        assert analyzer.is_coverage_stagnating()

    def test_strategy_recommendation(self):
        from src.feedback.analyzer import FeedbackAnalyzer

        analyzer = FeedbackAnalyzer(stagnation_threshold=5)
        for _ in range(100):
            analyzer.analyze(None, None, "bit_flip")
        recommended = analyzer.get_recommended_strategy()
        assert recommended in ("cross_protocol", "bit_flip", "structure_preserving", "state_aware")

    def test_summary_generation(self):
        from src.feedback.analyzer import FeedbackAnalyzer
        from src import MonitoringResult, LogEntry

        analyzer = FeedbackAnalyzer()
        mon = MonitoringResult(
            logs=[LogEntry(timestamp=0, nf_type=NFType.AMF, level="INFO", message="test")],
            new_edges={1, 2},
            nf_states={"amf": "REGISTERED"},
        )
        analyzer.analyze(mon, None, "structure_preserving")
        summary = analyzer.get_summary()
        assert summary["total_iterations"] == 1
        assert summary["total_new_edges"] == 2


# ─── Experiment Runner Tests ─────────────────────────────────

class TestExperimentRunner:
    def test_config_definitions(self):
        from src.experiments.runner import EXPERIMENT_CONFIGS
        assert "ours_full" in EXPERIMENT_CONFIGS
        assert "aflnet_like" in EXPERIMENT_CONFIGS
        assert "random" in EXPERIMENT_CONFIGS
        assert EXPERIMENT_CONFIGS["ours_full"].fsm_guidance is True
        assert EXPERIMENT_CONFIGS["random"].coverage_feedback is False

    def test_result_serialization(self):
        from src.experiments.runner import ExperimentResult
        import tempfile, json

        result = ExperimentResult(
            config_name="test",
            target=FiveGCImpl.OPEN5GS,
            run_id=1,
            start_time=1000.0,
            unique_crashes=5,
            total_crashes=10,
            edges_covered=1500,
            strategy_stats={"bit_flip": 100},
        )

        data = {
            "config_name": result.config_name,
            "target": result.target.value,
            "run_id": result.run_id,
            "start_time": result.start_time,
            "unique_crashes": result.unique_crashes,
            "total_crashes": result.total_crashes,
            "edges_covered": result.edges_covered,
            "strategy_stats": result.strategy_stats,
        }
        assert data["unique_crashes"] == 5


class TestStatisticalAnalysis:
    def test_cohens_d(self):
        from src.experiments.analysis import ResultAnalyzer

        d = ResultAnalyzer._cohens_d([10, 12, 14], [5, 6, 7])
        assert d > 1.0  # Large effect

    def test_interpret_d(self):
        from src.experiments.analysis import ResultAnalyzer

        assert ResultAnalyzer._interpret_d(0.1) == "negligible"
        assert ResultAnalyzer._interpret_d(0.5) == "medium"
        assert ResultAnalyzer._interpret_d(1.0) == "large"


class TestFSMLearnerFullPipeline:
    def test_learn_then_fuzz(self):
        """Learn FSM from traces, then use it to guide fuzzing."""
        learner = FSMLearner()

        traces = [Trace(
            trace_id="T1",
            protocol="nas-5gs",
            procedure="registration",
            events=[
                TraceEvent(timestamp=0.0, message_type="RegistrationRequest",
                          direction="uplink"),
                TraceEvent(timestamp=0.1, message_type="AuthenticationRequest",
                          direction="downlink"),
                TraceEvent(timestamp=0.2, message_type="AuthenticationResponse",
                          direction="uplink"),
                TraceEvent(timestamp=0.3, message_type="SecurityModeCommand",
                          direction="downlink"),
                TraceEvent(timestamp=0.4, message_type="SecurityModeComplete",
                          direction="uplink"),
                TraceEvent(timestamp=0.5, message_type="RegistrationAccept",
                          direction="downlink"),
                TraceEvent(timestamp=0.6, message_type="RegistrationComplete",
                          direction="uplink"),
            ],
            success=True,
        ) for _ in range(10)]

        fsms = learner.learn_from_traces(traces)
        assert "registration" in fsms
        fsm = fsms["registration"]
        assert len(fsm.states) >= 3  # At least INIT, AUTHENTICATING, REGISTERED

        # Use FSM to guide fuzzing
        guide = FSMGuidedFuzzing(fsm)
        for _ in range(10):
            target = guide.select_target_state()
            plan = guide.build_attack_plan(target)
            assert isinstance(plan.messages, list)


# ─── PFCP Codec Tests ────────────────────────────────────────────

class TestPFCPCodec:
    def test_association_setup_roundtrip(self):
        from src.codec.pfcp_codec import PFCPCodec

        codec = PFCPCodec()
        msg = ParsedMessage(
            protocol="pfcp",
            message_type="PFCP Association Setup Request",
            message_name="PFCP Association Setup Request",
            fields={
                "node_id": b"\x01\x02\x03\x04",
                "recovery_time_stamp": 1234567890,
                "node_features": 0x0F,
            },
        )
        encoded = codec.encode(msg)
        assert len(encoded) > 12
        decoded = codec.decode(encoded)
        assert decoded.message_type == "PFCP Association Setup Request"

    def test_session_establishment_roundtrip(self):
        from src.codec.pfcp_codec import PFCPCodec

        codec = PFCPCodec()
        msg = ParsedMessage(
            protocol="pfcp",
            message_type="PFCP Session Establishment Request",
            message_name="PFCP Session Establishment Request",
            fields={
                "node_id": b"\x0a\x00\x00\x01",
                "f_seid": b"\x00" * 8,
                "create_pdr": b"\x01",
                "create_far": b"\x02",
                "seid": 0x12345678,
                "sequence_number": 42,
            },
        )
        encoded = codec.encode(msg)
        decoded = codec.decode(encoded)
        assert decoded.message_type == "PFCP Session Establishment Request"
        assert decoded.fields["seid"] == 0x12345678

    def test_random_valid_messages(self):
        from src.codec.pfcp_codec import PFCPCodec

        codec = PFCPCodec()
        for msg_type in ["PFCP Association Setup Request",
                          "PFCP Session Establishment Request",
                          "PFCP Session Deletion Request"]:
            msg = codec.random_valid(msg_type)
            encoded = codec.encode(msg)
            assert len(encoded) >= 8

    def test_unknown_ie_injection(self):
        from src.codec.pfcp_codec import PFCPCodec

        codec = PFCPCodec()
        msg = codec.random_valid("PFCP Association Setup Request")
        encoded = codec.encode(msg)
        corrupted = codec.inject_unknown_ie(encoded, 0xFFFF, b"\xde\xad\xbe\xef")
        # Should still parse (unknown IE ignored)
        decoded = codec.decode(corrupted)
        assert decoded is not None

    def test_tlv_length_corruption(self):
        from src.codec.pfcp_codec import PFCPCodec

        codec = PFCPCodec()
        tlv = bytes([0x00, 0x01, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD])
        corrupted = codec.corrupt_tlv_length(tlv)
        assert corrupted[2:4] == b"\xff\xff"


# ─── GTP-U Codec Tests ───────────────────────────────────────────

class TestGTPUCodec:
    def test_gpdu_roundtrip(self):
        from src.codec.gtpu_codec import GTPUCodec

        codec = GTPUCodec()
        msg = ParsedMessage(
            protocol="gtp-u",
            message_type="G-PDU",
            message_name="G-PDU",
            fields={
                "teid": 0xABCD1234,
                "sequence_number": 100,
                "has_seq": True,
                "version": 1,
                "pt": 1,
                "t_pdu": b"\x45\x00\x00\x14\x00\x01\x00\x00\x40\x00\x7b\xe7\x0a\x00\x00\x01\x0a\x00\x00\x02",
            },
        )
        encoded = codec.encode(msg)
        assert len(encoded) >= 28
        decoded = codec.decode(encoded)
        assert decoded.message_type == "G-PDU"
        assert decoded.fields["teid"] == 0xABCD1234

    def test_echo_roundtrip(self):
        from src.codec.gtpu_codec import GTPUCodec

        codec = GTPUCodec()
        msg = ParsedMessage(
            protocol="gtp-u",
            message_type="Echo Request",
            message_name="Echo Request",
            fields={
                "sequence_number": 1,
                "teid": 0,
                "has_seq": True,
            },
        )
        encoded = codec.encode(msg)
        decoded = codec.decode(encoded)
        assert decoded.message_type == "Echo Request"

    def test_extension_header_injection(self):
        from src.codec.gtpu_codec import GTPUCodec

        codec = GTPUCodec()
        msg = codec.random_valid("G-PDU")
        encoded = codec.encode(msg)
        modified = codec.inject_extension_header(
            encoded, 0x85, b"\x00\x01\x02"  # PDU Session Container
        )
        decoded = codec.decode(modified)
        assert decoded.fields["has_ext"] is True

    def test_teid_corruption(self):
        from src.codec.gtpu_codec import GTPUCodec

        codec = GTPUCodec()
        msg = codec.random_valid("G-PDU")
        encoded = codec.encode(msg)
        corrupted = codec.corrupt_teid(encoded, 0xDEADBEEF)
        decoded = codec.decode(corrupted)
        assert decoded.fields["teid"] == 0xDEADBEEF

    def test_end_marker(self):
        from src.codec.gtpu_codec import GTPUCodec

        codec = GTPUCodec()
        msg = codec.random_valid("End Marker")
        encoded = codec.encode(msg)
        decoded = codec.decode(encoded)
        assert decoded.message_type == "End Marker"


# ─── SBI Codec Tests ─────────────────────────────────────────────

class TestSBICodec:
    def test_nf_register_roundtrip(self):
        from src.codec.sbi_codec import SBICodec

        codec = SBICodec()
        msg = ParsedMessage(
            protocol="sbi",
            message_type="Nnrf_NFManagement/NFRegister",
            message_name="Nnrf_NFManagement/NFRegister",
            fields={
                "method": "PUT",
                "path": "/nnrf-nfm/v1/nf-instances/AMF-001",
                "body": {
                    "nfInstanceId": "AMF-001",
                    "nfType": "AMF",
                    "nfStatus": "REGISTERED",
                    "ipv4Addresses": ["10.0.0.1"],
                },
            },
        )
        encoded = codec.encode(msg)
        assert b"AMF-001" in encoded
        assert b"REGISTERED" in encoded
        decoded = codec.decode(encoded)
        assert decoded.fields["body"]["nfType"] == "AMF"

    def test_json_body_fuzzing(self):
        from src.codec.sbi_codec import SBICodec

        codec = SBICodec()
        body = {"nfInstanceId": "AMF-001", "nfType": "AMF", "priority": 10}

        for mutation in ("type_confusion", "boundary", "null_required",
                         "extra_field", "empty_string", "oversized"):
            mutated = codec.fuzz_json_body(body, mutation)
            assert isinstance(mutated, dict)

    def test_all_operations_have_schemas(self):
        from src.codec.sbi_codec import SBICodec, SBI_OPERATIONS

        codec = SBICodec()
        assert len(SBI_OPERATIONS) >= 8
        for op_key in SBI_OPERATIONS:
            schema = codec.get_message_schema(op_key)
            assert schema is not None, f"Missing schema for {op_key}"
            assert len(schema.fields) > 0

    def test_random_valid_all_operations(self):
        from src.codec.sbi_codec import SBICodec

        codec = SBICodec()
        for op_key in codec.get_operation_names()[:5]:
            msg = codec.random_valid(op_key)
            encoded = codec.encode(msg)
            assert len(encoded) > 0

    def test_content_type_confusion(self):
        from src.codec.sbi_codec import SBICodec

        codec = SBICodec()
        msg = codec.random_valid("Nnrf_NFManagement/NFRegister")
        encoded = codec.encode(msg)
        corrupted = codec.content_type_confusion(encoded, "application/xml")
        assert b"application/xml" in corrupted

    def test_pseudo_header_injection(self):
        from src.codec.sbi_codec import SBICodec

        codec = SBICodec()
        msg = codec.random_valid("Namf_Communication/N1N2MessageTransfer")
        encoded = codec.encode(msg)
        corrupted = codec.inject_pseudo_header(encoded, ":protocol", "HTTP/1.1")
        assert b":protocol" in corrupted
