"""Unit tests for base codec types."""

import pytest
from src.codec.base import ParsedMessage, CodecContext


class TestParsedMessage:
    def test_create_message(self):
        msg = ParsedMessage(
            protocol="nas-5gs",
            message_type="Registration Request",
            message_name="Registration Request",
            fields={"5gs_registration_type": 1, "ng_ksi": 0},
        )
        assert msg.protocol == "nas-5gs"
        assert msg.message_type == "Registration Request"
        assert msg.fields["5gs_registration_type"] == 1

    def test_raw_bytes_default_is_none(self):
        msg = ParsedMessage(
            protocol="ngap",
            message_type="InitialUEMessage",
            message_name="InitialUEMessage",
        )
        assert msg.raw_bytes is None

    def test_raw_bytes_settable(self):
        msg = ParsedMessage(
            protocol="pfcp",
            message_type="Association Setup",
            message_name="Association Setup",
            raw_bytes=b"\x01\x02\x03",
        )
        assert msg.raw_bytes == b"\x01\x02\x03"

    def test_get_field_nested(self):
        msg = ParsedMessage(
            protocol="sbi",
            message_type="NFRegister",
            message_name="NFRegister",
            fields={"nfProfile": {"nfInstanceId": "abc123", "nfType": "AMF"}},
        )
        assert msg.get_field("nfProfile.nfInstanceId") == "abc123"


class TestCodecContext:
    def test_defaults(self):
        ctx = CodecContext()
        assert ctx.security_enabled is False

    def test_security_enabled(self):
        ctx = CodecContext(security_enabled=True)
        assert ctx.security_enabled is True
