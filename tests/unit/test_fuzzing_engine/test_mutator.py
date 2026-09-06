"""Unit tests for mutation engine."""

import pytest
from src import ProtocolType
from src.fuzzing_engine.mutator import (
    MutationContext,
    MutationStrategy,
    RandomMutation,
    MutatorEngine,
)
from src.fuzzing_engine.mutations import (
    BitFlipMutation,
    StructurePreservingMutation,
    StateAwareMutation,
    CrossProtocolMutation,
    SequenceLevelMutation,
    HTTP2Mutation,
)
from src.fuzzing_engine.seed_manager import Seed


class TestMutationContext:
    def test_create_context(self):
        ctx = MutationContext(protocol=ProtocolType.NAS)
        assert ctx.protocol == ProtocolType.NAS
        assert ctx.coverage_stagnation is False
        assert ctx.current_state == "unknown"

    def test_context_random_is_independent(self):
        ctx1 = MutationContext(ProtocolType.NGAP)
        ctx2 = MutationContext(ProtocolType.NGAP)
        # Each context has its own Random instance
        assert ctx1.random is not ctx2.random


class TestBitFlipMutation:
    def test_name(self):
        m = BitFlipMutation()
        assert m.name == "bit_flip"

    def test_mutate_returns_bytes(self):
        m = BitFlipMutation()
        seed = Seed(raw_pdu=b"\x00\x11\x22\x33\x44\x55\x66\x77", protocol="ngap")
        ctx = MutationContext(ProtocolType.NGAP)
        result = m.mutate(seed, ctx)
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_empty_input(self):
        m = BitFlipMutation()
        seed = Seed(raw_pdu=b"", protocol="nas")
        ctx = MutationContext(ProtocolType.NAS)
        result = m.mutate(seed, ctx)
        assert result == bytes([0xFF])


class TestStructurePreservingMutation:
    def test_name(self):
        m = StructurePreservingMutation()
        assert m.name == "structure_preserving"

    def test_fallback_without_codec(self):
        m = StructurePreservingMutation()
        seed = Seed(raw_pdu=b"\x01\x02\x03\x04", protocol="pfcp")
        ctx = MutationContext(ProtocolType.PFCP)
        result = m.mutate(seed, ctx)
        assert isinstance(result, bytes)


class TestCrossProtocolMutation:
    def test_name(self):
        m = CrossProtocolMutation()
        assert m.name == "cross_protocol"

    def test_empty_pool_fallback(self):
        m = CrossProtocolMutation()
        seed = Seed(raw_pdu=b"\x10\x20\x30\x40", protocol="nas")
        ctx = MutationContext(ProtocolType.NAS)
        result = m.mutate(seed, ctx)
        assert isinstance(result, bytes)

    def test_add_sample(self):
        m = CrossProtocolMutation()
        m.add_protocol_sample(ProtocolType.NAS, b"\x01\x02\x03")
        assert ProtocolType.NAS in m.protocol_pools
        assert len(m.protocol_pools[ProtocolType.NAS]) == 1


class TestSequenceLevelMutation:
    def test_name(self):
        m = SequenceLevelMutation()
        assert m.name == "sequence_level"

    def test_single_message_no_mutation(self):
        m = SequenceLevelMutation()
        seed = Seed(raw_pdu=b"\xAA\xBB", protocol="ngap")
        ctx = MutationContext(ProtocolType.NGAP)
        # First message shouldn't change (buffer too small)
        result = m.mutate(seed, ctx)
        assert result == b"\xAA\xBB"


class TestHTTP2Mutation:
    def test_name(self):
        m = HTTP2Mutation()
        assert m.name == "http2"

    def test_json_mutation(self):
        m = HTTP2Mutation()
        seed = Seed(
            raw_pdu=b'{"nfInstanceId":"test123","nfType":"AMF"}', protocol="sbi"
        )
        ctx = MutationContext(ProtocolType.SBI)
        result = m.mutate(seed, ctx)
        assert isinstance(result, bytes)


class TestMutatorEngine:
    def test_all_strategies_registered(self):
        engine = MutatorEngine()
        names = {s.name for s in engine.strategies}
        assert "bit_flip" in names
        assert "structure_preserving" in names
        assert "state_aware" in names
        assert "cross_protocol" in names
        assert "sequence_level" in names
        assert "http2" in names
        assert "random" in names

    def test_mutate_returns_both(self):
        engine = MutatorEngine()
        seed = Seed(raw_pdu=b"\x00" * 10, protocol="nas")
        strategy, result = engine.mutate(seed, ProtocolType.NAS)
        assert isinstance(strategy, MutationStrategy)
        assert isinstance(result, bytes)

    def test_mutate_sbi_prefers_http2(self):
        engine = MutatorEngine()
        seed = Seed(raw_pdu=b'{"test": true}', protocol="sbi")
        # SBI protocol should select HTTP2 strategy
        strategy, result = engine.mutate(seed, ProtocolType.SBI)
        assert strategy.name == "http2"

    def test_stats_tracking(self):
        engine = MutatorEngine()
        seed = Seed(raw_pdu=b"\x01\x02\x03", protocol="ngap")
        engine.mutate(seed, ProtocolType.NGAP)
        stats = engine.get_strategy_stats()
        assert sum(stats.values()) == 1

    def test_reset_stats(self):
        engine = MutatorEngine()
        seed = Seed(raw_pdu=b"\x01", protocol="nas")
        engine.mutate(seed, ProtocolType.NAS)
        engine.reset_stats()
        stats = engine.get_strategy_stats()
        assert sum(stats.values()) == 0

    def test_add_custom_strategy(self):
        engine = MutatorEngine()
        custom = RandomMutation()
        custom.name = "custom_test"
        engine.add_strategy(custom)
        assert "custom_test" in engine._strategy_map
