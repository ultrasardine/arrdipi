"""Tests for arrdipi/pdu/core.py: ShareControlHeader, ShareDataHeader, SecurityHeader."""

from __future__ import annotations

import struct

import pytest

from arrdipi.errors import PduParseError
from arrdipi.pdu.core import SecurityHeader, ShareControlHeader, ShareDataHeader
from arrdipi.pdu.types import ShareControlPduType, ShareDataPduType


# ---------------------------------------------------------------------------
# ShareControlHeader tests
# ---------------------------------------------------------------------------


class TestShareControlHeaderRoundTrip:
    """Round-trip: construct → serialize → parse → compare equality (Req 3, AC 4–5)."""

    def test_demand_active(self) -> None:
        original = ShareControlHeader(
            total_length=100,
            pdu_type=ShareControlPduType.DEMAND_ACTIVE,
            pdu_source=1003,
        )
        serialized = original.serialize()
        parsed = ShareControlHeader.parse(serialized)
        assert parsed == original

    def test_confirm_active(self) -> None:
        original = ShareControlHeader(
            total_length=256,
            pdu_type=ShareControlPduType.CONFIRM_ACTIVE,
            pdu_source=1004,
        )
        serialized = original.serialize()
        parsed = ShareControlHeader.parse(serialized)
        assert parsed == original

    def test_data_pdu(self) -> None:
        original = ShareControlHeader(
            total_length=50,
            pdu_type=ShareControlPduType.DATA,
            pdu_source=1005,
        )
        serialized = original.serialize()
        parsed = ShareControlHeader.parse(serialized)
        assert parsed == original

    def test_deactivate_all(self) -> None:
        original = ShareControlHeader(
            total_length=6,
            pdu_type=ShareControlPduType.DEACTIVATE_ALL,
            pdu_source=0,
        )
        serialized = original.serialize()
        parsed = ShareControlHeader.parse(serialized)
        assert parsed == original

    def test_server_redir(self) -> None:
        original = ShareControlHeader(
            total_length=200,
            pdu_type=ShareControlPduType.SERVER_REDIR,
            pdu_source=2000,
        )
        serialized = original.serialize()
        parsed = ShareControlHeader.parse(serialized)
        assert parsed == original

    def test_wire_format_correctness(self) -> None:
        """Verify the exact wire bytes match the expected encoding."""
        header = ShareControlHeader(
            total_length=0x0032,
            pdu_type=ShareControlPduType.DATA,  # 0x0007
            pdu_source=0x03EB,
        )
        serialized = header.serialize()
        # total_length: 0x0032 LE = 32 00
        # pdu_type | version: 0x0007 | 0x0010 = 0x0017 LE = 17 00
        # pdu_source: 0x03EB LE = EB 03
        assert serialized == b"\x32\x00\x17\x00\xEB\x03"

    def test_parse_known_bytes(self) -> None:
        """Parse known wire bytes and verify field values."""
        # total_length=100 (0x0064), type=DEMAND_ACTIVE (0x0001)|version(0x0010)=0x0011, source=1003 (0x03EB)
        data = struct.pack("<HHH", 0x0064, 0x0011, 0x03EB)
        parsed = ShareControlHeader.parse(data)
        assert parsed.total_length == 100
        assert parsed.pdu_type == ShareControlPduType.DEMAND_ACTIVE
        assert parsed.pdu_source == 0x03EB
        assert parsed.version == 0x0010


class TestShareControlHeaderMalformed:
    """Truncated headers raise PduParseError with correct offset (Req 3, AC 6)."""

    def test_empty_data(self) -> None:
        with pytest.raises(PduParseError) as exc_info:
            ShareControlHeader.parse(b"")
        assert exc_info.value.pdu_type == "ShareControlHeader"
        assert exc_info.value.offset == 0

    def test_truncated_at_2_bytes(self) -> None:
        with pytest.raises(PduParseError) as exc_info:
            ShareControlHeader.parse(b"\x32\x00")
        assert exc_info.value.pdu_type == "ShareControlHeader"
        assert exc_info.value.offset == 2

    def test_truncated_at_4_bytes(self) -> None:
        with pytest.raises(PduParseError) as exc_info:
            ShareControlHeader.parse(b"\x32\x00\x17\x00")
        assert exc_info.value.pdu_type == "ShareControlHeader"
        assert exc_info.value.offset == 4

    def test_truncated_at_5_bytes(self) -> None:
        with pytest.raises(PduParseError) as exc_info:
            ShareControlHeader.parse(b"\x32\x00\x17\x00\xEB")
        assert exc_info.value.pdu_type == "ShareControlHeader"
        assert exc_info.value.offset == 4


# ---------------------------------------------------------------------------
# ShareDataHeader tests
# ---------------------------------------------------------------------------


class TestShareDataHeaderRoundTrip:
    """Round-trip: construct → serialize → parse → compare equality (Req 3, AC 4–5)."""

    def test_synchronize(self) -> None:
        original = ShareDataHeader(
            share_id=0x00040006,
            pad1=0,
            stream_id=1,
            uncompressed_length=12,
            pdu_type=ShareDataPduType.SYNCHRONIZE,
            compressed_type=0,
            compressed_length=0,
        )
        serialized = original.serialize()
        parsed = ShareDataHeader.parse(serialized)
        assert parsed == original

    def test_control(self) -> None:
        original = ShareDataHeader(
            share_id=0x00040006,
            pad1=0,
            stream_id=2,
            uncompressed_length=20,
            pdu_type=ShareDataPduType.CONTROL,
            compressed_type=0,
            compressed_length=0,
        )
        serialized = original.serialize()
        parsed = ShareDataHeader.parse(serialized)
        assert parsed == original

    def test_input(self) -> None:
        original = ShareDataHeader(
            share_id=0xDEADBEEF,
            pad1=0,
            stream_id=1,
            uncompressed_length=100,
            pdu_type=ShareDataPduType.INPUT,
            compressed_type=0x01,
            compressed_length=80,
        )
        serialized = original.serialize()
        parsed = ShareDataHeader.parse(serialized)
        assert parsed == original

    def test_font_list(self) -> None:
        original = ShareDataHeader(
            share_id=0x12345678,
            pad1=0,
            stream_id=1,
            uncompressed_length=4,
            pdu_type=ShareDataPduType.FONT_LIST,
            compressed_type=0,
            compressed_length=0,
        )
        serialized = original.serialize()
        parsed = ShareDataHeader.parse(serialized)
        assert parsed == original

    def test_bitmap_update(self) -> None:
        original = ShareDataHeader(
            share_id=0xAABBCCDD,
            pad1=0,
            stream_id=2,
            uncompressed_length=500,
            pdu_type=ShareDataPduType.BITMAP_UPDATE,
            compressed_type=0x02,
            compressed_length=300,
        )
        serialized = original.serialize()
        parsed = ShareDataHeader.parse(serialized)
        assert parsed == original

    def test_wire_format_correctness(self) -> None:
        """Verify the exact wire bytes match the expected encoding."""
        header = ShareDataHeader(
            share_id=0x00040006,
            pad1=0,
            stream_id=1,
            uncompressed_length=12,
            pdu_type=ShareDataPduType.SYNCHRONIZE,  # 0x1F
            compressed_type=0,
            compressed_length=0,
        )
        serialized = header.serialize()
        expected = struct.pack("<IBBHBBH", 0x00040006, 0, 1, 12, 0x1F, 0, 0)
        assert serialized == expected

    def test_serialized_length_is_12(self) -> None:
        """ShareDataHeader is always exactly 12 bytes."""
        header = ShareDataHeader(
            share_id=0,
            pad1=0,
            stream_id=0,
            uncompressed_length=0,
            pdu_type=ShareDataPduType.SYNCHRONIZE,
            compressed_type=0,
            compressed_length=0,
        )
        assert len(header.serialize()) == 12


class TestShareDataHeaderMalformed:
    """Truncated headers raise PduParseError with correct offset (Req 3, AC 6)."""

    def test_empty_data(self) -> None:
        with pytest.raises(PduParseError) as exc_info:
            ShareDataHeader.parse(b"")
        assert exc_info.value.pdu_type == "ShareDataHeader"
        assert exc_info.value.offset == 0

    def test_truncated_at_4_bytes(self) -> None:
        # Only share_id (4 bytes), missing the rest
        with pytest.raises(PduParseError) as exc_info:
            ShareDataHeader.parse(b"\x06\x00\x04\x00")
        assert exc_info.value.pdu_type == "ShareDataHeader"
        assert exc_info.value.offset == 4

    def test_truncated_at_8_bytes(self) -> None:
        # share_id + pad1 + stream_id + uncompressed_length = 8 bytes
        data = struct.pack("<IBBH", 0x00040006, 0, 1, 12)
        with pytest.raises(PduParseError) as exc_info:
            ShareDataHeader.parse(data)
        assert exc_info.value.pdu_type == "ShareDataHeader"
        assert exc_info.value.offset == 8

    def test_truncated_at_10_bytes(self) -> None:
        # Missing compressed_length (last 2 bytes)
        data = struct.pack("<IBBHBB", 0x00040006, 0, 1, 12, 0x1F, 0)
        with pytest.raises(PduParseError) as exc_info:
            ShareDataHeader.parse(data)
        assert exc_info.value.pdu_type == "ShareDataHeader"
        assert exc_info.value.offset == 10


# ---------------------------------------------------------------------------
# SecurityHeader tests
# ---------------------------------------------------------------------------


class TestSecurityHeaderRoundTrip:
    """Round-trip: construct → serialize → parse → compare equality (Req 3, AC 4–5)."""

    def test_no_encryption(self) -> None:
        """SecurityHeader without MAC (no SEC_ENCRYPT flag)."""
        original = SecurityHeader(flags=0x0000, flags_hi=0x0000, mac=None)
        serialized = original.serialize()
        parsed = SecurityHeader.parse(serialized)
        assert parsed == original

    def test_with_encryption(self) -> None:
        """SecurityHeader with MAC (SEC_ENCRYPT flag set)."""
        mac_data = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        original = SecurityHeader(
            flags=SecurityHeader.SEC_ENCRYPT,
            flags_hi=0x0000,
            mac=mac_data,
        )
        serialized = original.serialize()
        parsed = SecurityHeader.parse(serialized)
        assert parsed == original

    def test_with_multiple_flags(self) -> None:
        """SecurityHeader with multiple flags set including SEC_ENCRYPT."""
        mac_data = b"\xAA\xBB\xCC\xDD\xEE\xFF\x11\x22"
        original = SecurityHeader(
            flags=0x0008 | 0x0001,  # SEC_ENCRYPT | some other flag
            flags_hi=0x0002,
            mac=mac_data,
        )
        serialized = original.serialize()
        parsed = SecurityHeader.parse(serialized)
        assert parsed == original

    def test_flags_hi_nonzero(self) -> None:
        """SecurityHeader with non-zero flags_hi and no encryption."""
        original = SecurityHeader(flags=0x0001, flags_hi=0x0040, mac=None)
        serialized = original.serialize()
        parsed = SecurityHeader.parse(serialized)
        assert parsed == original

    def test_wire_format_no_mac(self) -> None:
        """Verify exact wire bytes for header without MAC."""
        header = SecurityHeader(flags=0x0001, flags_hi=0x0000, mac=None)
        serialized = header.serialize()
        assert serialized == b"\x01\x00\x00\x00"
        assert len(serialized) == 4

    def test_wire_format_with_mac(self) -> None:
        """Verify exact wire bytes for header with MAC."""
        mac_data = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        header = SecurityHeader(
            flags=SecurityHeader.SEC_ENCRYPT,
            flags_hi=0x0000,
            mac=mac_data,
        )
        serialized = header.serialize()
        # flags=0x0008 LE = 08 00, flags_hi=0x0000 LE = 00 00, mac = 8 bytes
        assert serialized == b"\x08\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08"
        assert len(serialized) == 12


class TestSecurityHeaderMalformed:
    """Truncated headers raise PduParseError with correct offset (Req 3, AC 6)."""

    def test_empty_data(self) -> None:
        with pytest.raises(PduParseError) as exc_info:
            SecurityHeader.parse(b"")
        assert exc_info.value.pdu_type == "SecurityHeader"
        assert exc_info.value.offset == 0

    def test_truncated_at_2_bytes(self) -> None:
        with pytest.raises(PduParseError) as exc_info:
            SecurityHeader.parse(b"\x08\x00")
        assert exc_info.value.pdu_type == "SecurityHeader"
        assert exc_info.value.offset == 2

    def test_truncated_mac(self) -> None:
        """SEC_ENCRYPT set but MAC data is truncated."""
        # flags=0x0008 (SEC_ENCRYPT), flags_hi=0x0000, only 4 bytes of MAC
        data = b"\x08\x00\x00\x00\x01\x02\x03\x04"
        with pytest.raises(PduParseError) as exc_info:
            SecurityHeader.parse(data)
        assert exc_info.value.pdu_type == "SecurityHeader"
        assert exc_info.value.offset == 4

    def test_truncated_mac_partial(self) -> None:
        """SEC_ENCRYPT set but only 2 bytes of MAC available."""
        data = b"\x08\x00\x00\x00\x01\x02"
        with pytest.raises(PduParseError) as exc_info:
            SecurityHeader.parse(data)
        assert exc_info.value.pdu_type == "SecurityHeader"
        assert exc_info.value.offset == 4
