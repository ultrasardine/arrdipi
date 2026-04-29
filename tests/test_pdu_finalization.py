"""Tests for arrdipi/pdu/finalization.py: Connection finalization PDUs.

Validates Requirement 8 (AC 1–4): Connection Finalization PDU round-trip
correctness per [MS-RDPBCGR] 2.2.1.14–2.2.1.22.
"""

from __future__ import annotations

import struct

import pytest

from arrdipi.errors import PduParseError
from arrdipi.pdu.finalization import (
    ControlAction,
    ControlPdu,
    FontListPdu,
    FontMapPdu,
    PersistentKeyListFlag,
    PersistentKeyListPdu,
    SynchronizePdu,
)


# ---------------------------------------------------------------------------
# SynchronizePdu tests
# ---------------------------------------------------------------------------


class TestSynchronizePduRoundTrip:
    """Round-trip: construct → serialize → parse → compare equality (Req 8, AC 1)."""

    def test_basic_sync(self) -> None:
        original = SynchronizePdu(message_type=1, target_user=1003)
        serialized = original.serialize()
        parsed = SynchronizePdu.parse(serialized)
        assert parsed == original

    def test_target_user_zero(self) -> None:
        original = SynchronizePdu(message_type=1, target_user=0)
        serialized = original.serialize()
        parsed = SynchronizePdu.parse(serialized)
        assert parsed == original

    def test_target_user_max(self) -> None:
        original = SynchronizePdu(message_type=1, target_user=0xFFFF)
        serialized = original.serialize()
        parsed = SynchronizePdu.parse(serialized)
        assert parsed == original

    def test_wire_format(self) -> None:
        """Verify exact wire bytes match expected encoding."""
        pdu = SynchronizePdu(message_type=1, target_user=0x03EB)
        serialized = pdu.serialize()
        # message_type=1 LE = 01 00, target_user=0x03EB LE = EB 03
        assert serialized == b"\x01\x00\xEB\x03"
        assert len(serialized) == 4

    def test_parse_known_bytes(self) -> None:
        """Parse known wire bytes and verify field values."""
        data = struct.pack("<HH", 1, 1003)
        parsed = SynchronizePdu.parse(data)
        assert parsed.message_type == 1
        assert parsed.target_user == 1003


class TestSynchronizePduMalformed:
    """Truncated data raises PduParseError (Req 3, AC 6)."""

    def test_empty_data(self) -> None:
        with pytest.raises(PduParseError) as exc_info:
            SynchronizePdu.parse(b"")
        assert exc_info.value.pdu_type == "SynchronizePdu"
        assert exc_info.value.offset == 0

    def test_truncated_at_2_bytes(self) -> None:
        with pytest.raises(PduParseError) as exc_info:
            SynchronizePdu.parse(b"\x01\x00")
        assert exc_info.value.pdu_type == "SynchronizePdu"
        assert exc_info.value.offset == 2


# ---------------------------------------------------------------------------
# ControlPdu tests
# ---------------------------------------------------------------------------


class TestControlPduRoundTrip:
    """Round-trip: construct → serialize → parse → compare equality (Req 8, AC 1)."""

    def test_cooperate(self) -> None:
        original = ControlPdu(
            action=ControlAction.COOPERATE, grant_id=0, control_id=0
        )
        serialized = original.serialize()
        parsed = ControlPdu.parse(serialized)
        assert parsed == original

    def test_request_control(self) -> None:
        original = ControlPdu(
            action=ControlAction.REQUEST_CONTROL, grant_id=0, control_id=0
        )
        serialized = original.serialize()
        parsed = ControlPdu.parse(serialized)
        assert parsed == original

    def test_granted_control(self) -> None:
        original = ControlPdu(
            action=ControlAction.GRANTED_CONTROL, grant_id=1003, control_id=0x00040006
        )
        serialized = original.serialize()
        parsed = ControlPdu.parse(serialized)
        assert parsed == original

    def test_detach(self) -> None:
        original = ControlPdu(
            action=ControlAction.DETACH, grant_id=0, control_id=0
        )
        serialized = original.serialize()
        parsed = ControlPdu.parse(serialized)
        assert parsed == original

    def test_wire_format_cooperate(self) -> None:
        """Verify exact wire bytes for Cooperate action."""
        pdu = ControlPdu(action=ControlAction.COOPERATE, grant_id=0, control_id=0)
        serialized = pdu.serialize()
        # action=0x0004 LE = 04 00, grant_id=0 LE = 00 00, control_id=0 LE = 00 00 00 00
        assert serialized == b"\x04\x00\x00\x00\x00\x00\x00\x00"
        assert len(serialized) == 8

    def test_wire_format_granted_control(self) -> None:
        """Verify exact wire bytes for Granted Control."""
        pdu = ControlPdu(
            action=ControlAction.GRANTED_CONTROL, grant_id=0x03EB, control_id=0x00040006
        )
        serialized = pdu.serialize()
        expected = struct.pack("<HHI", 0x0002, 0x03EB, 0x00040006)
        assert serialized == expected

    def test_parse_known_bytes(self) -> None:
        """Parse known wire bytes and verify field values."""
        data = struct.pack("<HHI", 0x0001, 0, 0)
        parsed = ControlPdu.parse(data)
        assert parsed.action == ControlAction.REQUEST_CONTROL
        assert parsed.grant_id == 0
        assert parsed.control_id == 0


class TestControlPduMalformed:
    """Truncated data raises PduParseError (Req 3, AC 6)."""

    def test_empty_data(self) -> None:
        with pytest.raises(PduParseError) as exc_info:
            ControlPdu.parse(b"")
        assert exc_info.value.pdu_type == "ControlPdu"
        assert exc_info.value.offset == 0

    def test_truncated_at_2_bytes(self) -> None:
        with pytest.raises(PduParseError) as exc_info:
            ControlPdu.parse(b"\x04\x00")
        assert exc_info.value.pdu_type == "ControlPdu"
        assert exc_info.value.offset == 2

    def test_truncated_at_4_bytes(self) -> None:
        with pytest.raises(PduParseError) as exc_info:
            ControlPdu.parse(b"\x04\x00\x00\x00")
        assert exc_info.value.pdu_type == "ControlPdu"
        assert exc_info.value.offset == 4


# ---------------------------------------------------------------------------
# PersistentKeyListPdu tests
# ---------------------------------------------------------------------------


class TestPersistentKeyListPduRoundTrip:
    """Round-trip: construct → serialize → parse → compare equality (Req 8, AC 2)."""

    def test_empty_key_list(self) -> None:
        original = PersistentKeyListPdu(
            num_entries_cache0=0,
            num_entries_cache1=0,
            num_entries_cache2=0,
            num_entries_cache3=0,
            num_entries_cache4=0,
            total_entries_cache0=100,
            total_entries_cache1=50,
            total_entries_cache2=25,
            total_entries_cache3=10,
            total_entries_cache4=5,
            b_bit_mask=PersistentKeyListFlag.PERSIST_FIRST_PDU | PersistentKeyListFlag.PERSIST_LAST_PDU,
            pad2=0,
            pad3=0,
            entries=[],
        )
        serialized = original.serialize()
        parsed = PersistentKeyListPdu.parse(serialized)
        assert parsed == original

    def test_single_cache_with_keys(self) -> None:
        original = PersistentKeyListPdu(
            num_entries_cache0=3,
            num_entries_cache1=0,
            num_entries_cache2=0,
            num_entries_cache3=0,
            num_entries_cache4=0,
            total_entries_cache0=100,
            total_entries_cache1=0,
            total_entries_cache2=0,
            total_entries_cache3=0,
            total_entries_cache4=0,
            b_bit_mask=PersistentKeyListFlag.PERSIST_FIRST_PDU | PersistentKeyListFlag.PERSIST_LAST_PDU,
            pad2=0,
            pad3=0,
            entries=[0xDEADBEEFCAFEBABE, 0x1234567890ABCDEF, 0x0000000000000001],
        )
        serialized = original.serialize()
        parsed = PersistentKeyListPdu.parse(serialized)
        assert parsed == original

    def test_multiple_caches_with_keys(self) -> None:
        original = PersistentKeyListPdu(
            num_entries_cache0=2,
            num_entries_cache1=1,
            num_entries_cache2=1,
            num_entries_cache3=0,
            num_entries_cache4=0,
            total_entries_cache0=50,
            total_entries_cache1=30,
            total_entries_cache2=20,
            total_entries_cache3=10,
            total_entries_cache4=5,
            b_bit_mask=PersistentKeyListFlag.PERSIST_FIRST_PDU,
            pad2=0,
            pad3=0,
            entries=[0x1111111111111111, 0x2222222222222222, 0x3333333333333333, 0x4444444444444444],
        )
        serialized = original.serialize()
        parsed = PersistentKeyListPdu.parse(serialized)
        assert parsed == original

    def test_first_pdu_flag_only(self) -> None:
        original = PersistentKeyListPdu(
            num_entries_cache0=1,
            num_entries_cache1=0,
            num_entries_cache2=0,
            num_entries_cache3=0,
            num_entries_cache4=0,
            total_entries_cache0=200,
            total_entries_cache1=0,
            total_entries_cache2=0,
            total_entries_cache3=0,
            total_entries_cache4=0,
            b_bit_mask=PersistentKeyListFlag.PERSIST_FIRST_PDU,
            pad2=0,
            pad3=0,
            entries=[0xFFFFFFFFFFFFFFFF],
        )
        serialized = original.serialize()
        parsed = PersistentKeyListPdu.parse(serialized)
        assert parsed == original

    def test_wire_format_header_size(self) -> None:
        """Header without entries is 24 bytes (10 u16 + u8 + u8 + u16)."""
        pdu = PersistentKeyListPdu(
            num_entries_cache0=0,
            num_entries_cache1=0,
            num_entries_cache2=0,
            num_entries_cache3=0,
            num_entries_cache4=0,
            total_entries_cache0=0,
            total_entries_cache1=0,
            total_entries_cache2=0,
            total_entries_cache3=0,
            total_entries_cache4=0,
            b_bit_mask=0x03,
            pad2=0,
            pad3=0,
            entries=[],
        )
        serialized = pdu.serialize()
        assert len(serialized) == 24

    def test_wire_format_with_entries(self) -> None:
        """Each entry adds 8 bytes (u64 LE)."""
        pdu = PersistentKeyListPdu(
            num_entries_cache0=2,
            num_entries_cache1=0,
            num_entries_cache2=0,
            num_entries_cache3=0,
            num_entries_cache4=0,
            total_entries_cache0=10,
            total_entries_cache1=0,
            total_entries_cache2=0,
            total_entries_cache3=0,
            total_entries_cache4=0,
            b_bit_mask=0x03,
            pad2=0,
            pad3=0,
            entries=[0x0102030405060708, 0x090A0B0C0D0E0F10],
        )
        serialized = pdu.serialize()
        # 24 bytes header + 2 * 8 bytes entries = 40 bytes
        assert len(serialized) == 40


class TestPersistentKeyListPduMalformed:
    """Truncated data raises PduParseError (Req 3, AC 6)."""

    def test_empty_data(self) -> None:
        with pytest.raises(PduParseError) as exc_info:
            PersistentKeyListPdu.parse(b"")
        assert exc_info.value.pdu_type == "PersistentKeyListPdu"
        assert exc_info.value.offset == 0

    def test_truncated_header(self) -> None:
        # Only 10 bytes of the 24-byte header
        with pytest.raises(PduParseError) as exc_info:
            PersistentKeyListPdu.parse(b"\x00" * 10)
        assert exc_info.value.pdu_type == "PersistentKeyListPdu"

    def test_truncated_entries(self) -> None:
        """Header says 1 entry in cache0 but no entry data follows."""
        # Build a valid 24-byte header with num_entries_cache0=1
        header = struct.pack(
            "<HHHHHHHHHH BBH",
            1, 0, 0, 0, 0,  # num_entries
            10, 0, 0, 0, 0,  # total_entries
            0x03, 0, 0,  # b_bit_mask, pad2, pad3
        )
        assert len(header) == 24
        with pytest.raises(PduParseError) as exc_info:
            PersistentKeyListPdu.parse(header)
        assert exc_info.value.pdu_type == "PersistentKeyListPdu"
        assert exc_info.value.offset == 24


# ---------------------------------------------------------------------------
# FontListPdu tests
# ---------------------------------------------------------------------------


class TestFontListPduRoundTrip:
    """Round-trip: construct → serialize → parse → compare equality (Req 8, AC 1)."""

    def test_standard_font_list(self) -> None:
        """Standard Font List PDU with typical values."""
        original = FontListPdu(
            number_fonts=0,
            total_num_fonts=0,
            list_flags=0x0003,
            entry_size=0x0032,
        )
        serialized = original.serialize()
        parsed = FontListPdu.parse(serialized)
        assert parsed == original

    def test_custom_values(self) -> None:
        original = FontListPdu(
            number_fonts=5,
            total_num_fonts=10,
            list_flags=0x0001,
            entry_size=0x0050,
        )
        serialized = original.serialize()
        parsed = FontListPdu.parse(serialized)
        assert parsed == original

    def test_wire_format(self) -> None:
        """Verify exact wire bytes for standard Font List PDU."""
        pdu = FontListPdu(
            number_fonts=0,
            total_num_fonts=0,
            list_flags=0x0003,
            entry_size=0x0032,
        )
        serialized = pdu.serialize()
        # 00 00 00 00 03 00 32 00
        assert serialized == b"\x00\x00\x00\x00\x03\x00\x32\x00"
        assert len(serialized) == 8

    def test_parse_known_bytes(self) -> None:
        """Parse known wire bytes and verify field values."""
        data = struct.pack("<HHHH", 0, 0, 0x0003, 0x0032)
        parsed = FontListPdu.parse(data)
        assert parsed.number_fonts == 0
        assert parsed.total_num_fonts == 0
        assert parsed.list_flags == 0x0003
        assert parsed.entry_size == 0x0032


class TestFontListPduMalformed:
    """Truncated data raises PduParseError (Req 3, AC 6)."""

    def test_empty_data(self) -> None:
        with pytest.raises(PduParseError) as exc_info:
            FontListPdu.parse(b"")
        assert exc_info.value.pdu_type == "FontListPdu"
        assert exc_info.value.offset == 0

    def test_truncated_at_4_bytes(self) -> None:
        with pytest.raises(PduParseError) as exc_info:
            FontListPdu.parse(b"\x00\x00\x00\x00")
        assert exc_info.value.pdu_type == "FontListPdu"
        assert exc_info.value.offset == 4

    def test_truncated_at_6_bytes(self) -> None:
        with pytest.raises(PduParseError) as exc_info:
            FontListPdu.parse(b"\x00\x00\x00\x00\x03\x00")
        assert exc_info.value.pdu_type == "FontListPdu"
        assert exc_info.value.offset == 6


# ---------------------------------------------------------------------------
# FontMapPdu tests
# ---------------------------------------------------------------------------


class TestFontMapPduRoundTrip:
    """Round-trip: construct → serialize → parse → compare equality (Req 8, AC 3)."""

    def test_standard_font_map(self) -> None:
        """Standard Font Map PDU with typical values."""
        original = FontMapPdu(
            number_entries=0,
            total_num_entries=0,
            map_flags=0x0003,
            entry_size=0x0004,
        )
        serialized = original.serialize()
        parsed = FontMapPdu.parse(serialized)
        assert parsed == original

    def test_custom_values(self) -> None:
        original = FontMapPdu(
            number_entries=3,
            total_num_entries=7,
            map_flags=0x0001,
            entry_size=0x0008,
        )
        serialized = original.serialize()
        parsed = FontMapPdu.parse(serialized)
        assert parsed == original

    def test_wire_format(self) -> None:
        """Verify exact wire bytes for standard Font Map PDU."""
        pdu = FontMapPdu(
            number_entries=0,
            total_num_entries=0,
            map_flags=0x0003,
            entry_size=0x0004,
        )
        serialized = pdu.serialize()
        # 00 00 00 00 03 00 04 00
        assert serialized == b"\x00\x00\x00\x00\x03\x00\x04\x00"
        assert len(serialized) == 8

    def test_parse_known_bytes(self) -> None:
        """Parse known wire bytes and verify field values."""
        data = struct.pack("<HHHH", 0, 0, 0x0003, 0x0004)
        parsed = FontMapPdu.parse(data)
        assert parsed.number_entries == 0
        assert parsed.total_num_entries == 0
        assert parsed.map_flags == 0x0003
        assert parsed.entry_size == 0x0004


class TestFontMapPduMalformed:
    """Truncated data raises PduParseError (Req 3, AC 6)."""

    def test_empty_data(self) -> None:
        with pytest.raises(PduParseError) as exc_info:
            FontMapPdu.parse(b"")
        assert exc_info.value.pdu_type == "FontMapPdu"
        assert exc_info.value.offset == 0

    def test_truncated_at_4_bytes(self) -> None:
        with pytest.raises(PduParseError) as exc_info:
            FontMapPdu.parse(b"\x00\x00\x00\x00")
        assert exc_info.value.pdu_type == "FontMapPdu"
        assert exc_info.value.offset == 4

    def test_truncated_at_6_bytes(self) -> None:
        with pytest.raises(PduParseError) as exc_info:
            FontMapPdu.parse(b"\x00\x00\x00\x00\x03\x00")
        assert exc_info.value.pdu_type == "FontMapPdu"
        assert exc_info.value.offset == 6
