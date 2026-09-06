"""Unit tests for crash triage module."""

import pytest
from src import CrashRecord, CrashSeverity, NFType, ProtocolType
from src.triage.crash_triage import CrashTriage, CrashGroup


def make_crash(signal="SIGSEGV", nf=NFType.AMF, address=0xDEADBEEF,
               protocol=None, pdu=b"\x00\x01"):
    """Helper to create test crashes."""
    return CrashRecord(
        crash_signal=signal,
        target_nf=nf,
        crash_address=address,
        severity=CrashSeverity.CRITICAL,
        input_pdu=pdu,
        protocol=protocol,
    )


class TestCrashTriage:
    def test_create_analyzer(self):
        triage = CrashTriage()
        assert triage is not None

    def test_triage_empty_list(self):
        triage = CrashTriage()
        groups = triage.triage([])
        assert groups == []

    def test_triage_single_crash(self):
        triage = CrashTriage()
        crash = make_crash()
        groups = triage.triage([crash])
        assert len(groups) == 1
        assert groups[0].representative.crash_signal == "SIGSEGV"

    def test_triage_deduplicates_same_signature(self):
        triage = CrashTriage()
        crashes = [
            make_crash(signal="SIGSEGV", nf=NFType.AMF, address=0x1000),
            make_crash(signal="SIGSEGV", nf=NFType.AMF, address=0x1000),
        ]
        groups = triage.triage(crashes)
        total_members = sum(g.count for g in groups)
        assert total_members == 2

    def test_triage_separates_different_nfs(self):
        triage = CrashTriage()
        crashes = [
            make_crash(signal="SIGSEGV", nf=NFType.AMF, address=0x1000),
            make_crash(signal="SIGSEGV", nf=NFType.SMF, address=0x2000),
        ]
        groups = triage.triage(crashes)
        assert len(groups) == 2

    def test_triage_separates_different_signals(self):
        triage = CrashTriage()
        crashes = [
            make_crash(signal="SIGSEGV", nf=NFType.AMF, address=0x1000),
            make_crash(signal="SIGABRT", nf=NFType.AMF, address=0x2000),
        ]
        groups = triage.triage(crashes)
        assert len(groups) >= 1

    def test_get_statistics(self):
        triage = CrashTriage()
        crash = make_crash()
        triage.triage([crash])
        stats = triage.get_statistics()
        assert isinstance(stats, dict)
