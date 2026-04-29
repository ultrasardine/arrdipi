"""Tests for arrdipi/pdu/base.py: ByteReader, ByteWriter, and PduParseError."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Self

import pytest

from arrdipi.errors import PduParseError
from arrdipi.pdu.base import ByteReader, ByteWriter, Pdu


# ---------------------------------------------------------------------------
# ByteReader tests
# ---------------------------------------------------------------------------


class TestByteReaderBasicReads:
    """Test ByteReader reads correct values from valid data."""

    def test_read_u8(self) -> None:
        reader = ByteReader(b"\x42")
        assert reader.read_u8() == 0x42
        assert reader.offset == 1

    def test_read_u16_le(self) -> None:
        reader = ByteReader(b"\x01\x02")
        assert reader.read_u16_le() == 0x0201
        assert reader.offset == 2

    def test_read_u32_le(self) -> None:
        reader = ByteReader(b"\x01\x02\x03\x04")
        assert reader.read_u32_le() == 0x04030201
        assert reader.offset == 4

    def test_read_bytes(self) -> None:
        reader = ByteReader(b"\xAA\xBB\xCC\xDD")
        assert reader.read_bytes(3) == b"\xAA\xBB\xCC"
        assert reader.offset == 3

    def test_remaining(self) -> None:
        reader = ByteReader(b"\x01\x02\x03\x04\x05")
        assert reader.remaining() == 5
        reader.read_u8()
        assert reader.remaining() == 4
        reader.read_u16_le()
        assert reader.remaining() == 2


    def test_sequential_reads(self) -> None:
        data = struct.pack("<BHI", 0xFF, 0x1234, 0xDEADBEEF)
        reader = ByteReader(data)
        assert reader.read_u8() == 0xFF
        assert reader.read_u16_le() == 0x1234
        assert reader.read_u32_le() == 0xDEADBEEF
        assert reader.remaining() == 0


class TestByteReaderBoundsChecking:
    """Test ByteReader raises PduParseError on out-of-bounds reads."""

    def test_read_u8_empty(self) -> None:
        reader = ByteReader(b"", pdu_type="TestPdu")
        with pytest.raises(PduParseError) as exc_info:
            reader.read_u8()
        assert exc_info.value.pdu_type == "TestPdu"
        assert exc_info.value.offset == 0
        assert "1 bytes" in exc_info.value.description

    def test_read_u16_le_insufficient(self) -> None:
        reader = ByteReader(b"\x01", pdu_type="TestPdu")
        with pytest.raises(PduParseError) as exc_info:
            reader.read_u16_le()
        assert exc_info.value.pdu_type == "TestPdu"
        assert exc_info.value.offset == 0
        assert "2 bytes" in exc_info.value.description

    def test_read_u32_le_insufficient(self) -> None:
        reader = ByteReader(b"\x01\x02", pdu_type="TestPdu")
        with pytest.raises(PduParseError) as exc_info:
            reader.read_u32_le()
        assert exc_info.value.pdu_type == "TestPdu"
        assert exc_info.value.offset == 0
        assert "4 bytes" in exc_info.value.description

    def test_read_bytes_insufficient(self) -> None:
        reader = ByteReader(b"\x01\x02\x03", pdu_type="TestPdu")
        with pytest.raises(PduParseError) as exc_info:
            reader.read_bytes(5)
        assert exc_info.value.pdu_type == "TestPdu"
        assert exc_info.value.offset == 0
        assert "5 bytes" in exc_info.value.description

    def test_bounds_error_after_partial_read(self) -> None:
        reader = ByteReader(b"\x01\x02\x03", pdu_type="ShareControl")
        reader.read_u8()  # offset now 1
        with pytest.raises(PduParseError) as exc_info:
            reader.read_u32_le()  # needs 4, only 2 remaining
        assert exc_info.value.offset == 1
        assert exc_info.value.pdu_type == "ShareControl"


# ---------------------------------------------------------------------------
# ByteWriter tests
# ---------------------------------------------------------------------------


class TestByteWriterOutput:
    """Test ByteWriter produces correct binary output."""

    def test_write_u8(self) -> None:
        w = ByteWriter()
        w.write_u8(0x42)
        assert w.to_bytes() == b"\x42"

    def test_write_u16_le(self) -> None:
        w = ByteWriter()
        w.write_u16_le(0x1234)
        assert w.to_bytes() == b"\x34\x12"

    def test_write_u32_le(self) -> None:
        w = ByteWriter()
        w.write_u32_le(0xDEADBEEF)
        assert w.to_bytes() == b"\xEF\xBE\xAD\xDE"

    def test_write_bytes(self) -> None:
        w = ByteWriter()
        w.write_bytes(b"\xAA\xBB\xCC")
        assert w.to_bytes() == b"\xAA\xBB\xCC"

    def test_sequential_writes(self) -> None:
        w = ByteWriter()
        w.write_u8(0xFF)
        w.write_u16_le(0x1234)
        w.write_u32_le(0xDEADBEEF)
        w.write_bytes(b"\x00\x01")
        expected = b"\xFF\x34\x12\xEF\xBE\xAD\xDE\x00\x01"
        assert w.to_bytes() == expected

    def test_empty_writer(self) -> None:
        w = ByteWriter()
        assert w.to_bytes() == b""


# ---------------------------------------------------------------------------
# PduParseError tests
# ---------------------------------------------------------------------------


class TestPduParseError:
    """Test PduParseError formatting and attributes."""

    def test_attributes(self) -> None:
        err = PduParseError(
            pdu_type="ShareControlHeader",
            offset=4,
            description="unexpected end of data",
        )
        assert err.pdu_type == "ShareControlHeader"
        assert err.offset == 4
        assert err.description == "unexpected end of data"

    def test_str_format(self) -> None:
        err = PduParseError(
            pdu_type="ClientInfo",
            offset=12,
            description="invalid flags field",
        )
        msg = str(err)
        assert "ClientInfo" in msg
        assert "12" in msg
        assert "invalid flags field" in msg

    def test_inherits_from_base(self) -> None:
        err = PduParseError("Test", 0, "test")
        assert isinstance(err, Exception)


# ---------------------------------------------------------------------------
# Pdu ABC tests
# ---------------------------------------------------------------------------


class TestPduABC:
    """Test that Pdu ABC enforces abstract methods."""

    def test_cannot_instantiate_abstract(self) -> None:
        with pytest.raises(TypeError):

            @dataclass
            class IncompletePdu(Pdu):
                pass

            IncompletePdu()  # type: ignore[abstract]

    def test_concrete_subclass(self) -> None:
        @dataclass
        class SimplePdu(Pdu):
            value: int = 0

            @classmethod
            def parse(cls, data: bytes) -> Self:
                reader = ByteReader(data, pdu_type="SimplePdu")
                return cls(value=reader.read_u8())

            def serialize(self) -> bytes:
                w = ByteWriter()
                w.write_u8(self.value)
                return w.to_bytes()

        # Round-trip: construct -> serialize -> parse -> compare
        original = SimplePdu(value=42)
        serialized = original.serialize()
        parsed = SimplePdu.parse(serialized)
        assert parsed == original

        # Round-trip: parse -> serialize -> compare bytes
        raw = b"\x7F"
        parsed2 = SimplePdu.parse(raw)
        assert parsed2.serialize() == raw
