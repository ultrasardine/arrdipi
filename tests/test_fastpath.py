"""Tests for arrdipi/pdu/fastpath.py: fast-path input/output PDU framing."""

from __future__ import annotations

import struct

import pytest

from arrdipi.errors import PduParseError
from arrdipi.pdu.fastpath import (
    FastPathInputEventCode,
    FastPathInputPdu,
    FastPathKeyboardEvent,
    FastPathKeyboardFlags,
    FastPathMouseEvent,
    FastPathOutputPdu,
    FastPathOutputUpdate,
    FastPathOutputUpdateCode,
    FastPathUnicodeEvent,
    is_fast_path,
)


# ---------------------------------------------------------------------------
# Fast-path vs slow-path detection
# ---------------------------------------------------------------------------


class TestIsFastPath:
    """Test fast-path vs slow-path detection based on first byte."""

    def test_tpkt_byte_is_slow_path(self) -> None:
        """0x03 is the TPKT version byte, indicating slow-path."""
        assert is_fast_path(0x03) is False

    def test_zero_byte_is_fast_path(self) -> None:
        """0x00 indicates fast-path (action = FASTPATH_INPUT_ACTION_FASTPATH)."""
        assert is_fast_path(0x00) is True

    def test_nonzero_non_tpkt_is_fast_path(self) -> None:
        """Any byte other than 0x03 is fast-path."""
        assert is_fast_path(0x01) is True
        assert is_fast_path(0x04) is True
        assert is_fast_path(0x80) is True
        assert is_fast_path(0xFF) is True

    def test_fast_path_header_with_events(self) -> None:
        """Header byte with numEvents encoded in bits 2-5."""
        # 2 events in header: action=0, numEvents=2, flags=0 → 0b00001000 = 0x08
        header = 0x08
        assert is_fast_path(header) is True


# ---------------------------------------------------------------------------
# FastPathKeyboardEvent
# ---------------------------------------------------------------------------


class TestFastPathKeyboardEvent:
    """Test fast-path keyboard event serialize/parse."""

    def test_serialize_key_press(self) -> None:
        event = FastPathKeyboardEvent(flags=0, key_code=0x1E)  # 'A' scancode
        data = event.serialize()
        # eventHeader: flags=0, eventCode=0 → 0x00; keyCode: 0x1E
        assert data == b"\x00\x1E"

    def test_serialize_key_release(self) -> None:
        event = FastPathKeyboardEvent(
            flags=FastPathKeyboardFlags.FASTPATH_INPUT_KBDFLAGS_RELEASE,
            key_code=0x1E,
        )
        data = event.serialize()
        # eventHeader: flags=0x01, eventCode=0 → 0x01; keyCode: 0x1E
        assert data == b"\x01\x1E"

    def test_serialize_extended_key(self) -> None:
        event = FastPathKeyboardEvent(
            flags=FastPathKeyboardFlags.FASTPATH_INPUT_KBDFLAGS_EXTENDED,
            key_code=0x4B,  # Left arrow
        )
        data = event.serialize()
        # eventHeader: flags=0x02, eventCode=0 → 0x02; keyCode: 0x4B
        assert data == b"\x02\x4B"

    def test_round_trip(self) -> None:
        from arrdipi.pdu.base import ByteReader

        original = FastPathKeyboardEvent(flags=0x01, key_code=0x39)
        serialized = original.serialize()
        reader = ByteReader(serialized, pdu_type="Test")
        event_header = reader.read_u8()
        parsed = FastPathKeyboardEvent.parse(event_header, reader)
        assert parsed.flags == original.flags
        assert parsed.key_code == original.key_code


# ---------------------------------------------------------------------------
# FastPathMouseEvent
# ---------------------------------------------------------------------------


class TestFastPathMouseEvent:
    """Test fast-path mouse event serialize/parse."""

    def test_serialize_mouse_move(self) -> None:
        event = FastPathMouseEvent(pointer_flags=0x0800, x_pos=100, y_pos=200)
        data = event.serialize()
        # eventHeader: eventCode=1 → (1 << 5) = 0x20
        # pointerFlags: 0x0800 LE, xPos: 100 LE, yPos: 200 LE
        expected = bytes([0x20]) + struct.pack("<HHH", 0x0800, 100, 200)
        assert data == expected

    def test_serialize_mouse_click(self) -> None:
        # Left button down: PTRFLAGS_DOWN | PTRFLAGS_BUTTON1 = 0x8000 | 0x1000
        event = FastPathMouseEvent(pointer_flags=0x9000, x_pos=50, y_pos=75)
        data = event.serialize()
        expected = bytes([0x20]) + struct.pack("<HHH", 0x9000, 50, 75)
        assert data == expected

    def test_round_trip(self) -> None:
        from arrdipi.pdu.base import ByteReader

        original = FastPathMouseEvent(pointer_flags=0x0800, x_pos=1920, y_pos=1080)
        serialized = original.serialize()
        reader = ByteReader(serialized, pdu_type="Test")
        event_header = reader.read_u8()
        parsed = FastPathMouseEvent.parse(event_header, reader)
        assert parsed.pointer_flags == original.pointer_flags
        assert parsed.x_pos == original.x_pos
        assert parsed.y_pos == original.y_pos


# ---------------------------------------------------------------------------
# FastPathUnicodeEvent
# ---------------------------------------------------------------------------


class TestFastPathUnicodeEvent:
    """Test fast-path unicode event serialize/parse."""

    def test_serialize_unicode_char(self) -> None:
        event = FastPathUnicodeEvent(flags=0, unicode_code=0x0041)  # 'A'
        data = event.serialize()
        # eventHeader: flags=0, eventCode=4 → (4 << 5) = 0x80
        # unicodeCode: 0x0041 LE
        expected = bytes([0x80]) + struct.pack("<H", 0x0041)
        assert data == expected

    def test_serialize_unicode_release(self) -> None:
        event = FastPathUnicodeEvent(flags=0x01, unicode_code=0x0041)
        data = event.serialize()
        # eventHeader: flags=0x01, eventCode=4 → 0x01 | (4 << 5) = 0x81
        expected = bytes([0x81]) + struct.pack("<H", 0x0041)
        assert data == expected

    def test_round_trip(self) -> None:
        from arrdipi.pdu.base import ByteReader

        original = FastPathUnicodeEvent(flags=0x01, unicode_code=0x4E16)  # '世'
        serialized = original.serialize()
        reader = ByteReader(serialized, pdu_type="Test")
        event_header = reader.read_u8()
        parsed = FastPathUnicodeEvent.parse(event_header, reader)
        assert parsed.flags == original.flags
        assert parsed.unicode_code == original.unicode_code


# ---------------------------------------------------------------------------
# FastPathInputPdu
# ---------------------------------------------------------------------------


class TestFastPathInputPdu:
    """Test fast-path input PDU container serialize/parse."""

    def test_serialize_single_keyboard_event(self) -> None:
        pdu = FastPathInputPdu(
            events=[FastPathKeyboardEvent(flags=0, key_code=0x1E)],
            flags=0,
        )
        data = pdu.serialize()
        # Header: action=0, numEvents=1, flags=0 → (1 << 2) = 0x04
        # Length: header(1) + length(1) + events(2) = 4
        # Events: 0x00 0x1E
        assert data[0] == 0x04  # header with 1 event
        assert data[1] == 4  # total length
        assert data[2:] == b"\x00\x1E"  # keyboard event

    def test_serialize_multiple_events(self) -> None:
        pdu = FastPathInputPdu(
            events=[
                FastPathKeyboardEvent(flags=0, key_code=0x1E),
                FastPathMouseEvent(pointer_flags=0x0800, x_pos=100, y_pos=200),
            ],
            flags=0,
        )
        data = pdu.serialize()
        # Header: action=0, numEvents=2, flags=0 → (2 << 2) = 0x08
        assert data[0] == 0x08

    def test_round_trip_single_event(self) -> None:
        original = FastPathInputPdu(
            events=[FastPathKeyboardEvent(flags=0x01, key_code=0x39)],
            flags=0,
        )
        serialized = original.serialize()
        parsed = FastPathInputPdu.parse(serialized)
        assert len(parsed.events) == 1
        assert isinstance(parsed.events[0], FastPathKeyboardEvent)
        assert parsed.events[0].flags == 0x01
        assert parsed.events[0].key_code == 0x39

    def test_round_trip_multiple_events(self) -> None:
        original = FastPathInputPdu(
            events=[
                FastPathKeyboardEvent(flags=0, key_code=0x1E),
                FastPathMouseEvent(pointer_flags=0x0800, x_pos=100, y_pos=200),
                FastPathUnicodeEvent(flags=0, unicode_code=0x0041),
            ],
            flags=0,
        )
        serialized = original.serialize()
        parsed = FastPathInputPdu.parse(serialized)
        assert len(parsed.events) == 3

        assert isinstance(parsed.events[0], FastPathKeyboardEvent)
        assert parsed.events[0].key_code == 0x1E

        assert isinstance(parsed.events[1], FastPathMouseEvent)
        assert parsed.events[1].pointer_flags == 0x0800
        assert parsed.events[1].x_pos == 100
        assert parsed.events[1].y_pos == 200

        assert isinstance(parsed.events[2], FastPathUnicodeEvent)
        assert parsed.events[2].unicode_code == 0x0041

    def test_round_trip_with_flags(self) -> None:
        original = FastPathInputPdu(
            events=[FastPathKeyboardEvent(flags=0, key_code=0x01)],
            flags=0x02,  # encrypted
        )
        serialized = original.serialize()
        parsed = FastPathInputPdu.parse(serialized)
        assert parsed.flags == 0x02
        assert len(parsed.events) == 1

    def test_parse_with_separate_num_events_byte(self) -> None:
        """When numEvents > 15, it's stored in a separate byte."""
        # Build a PDU with 16 keyboard events manually
        events = [FastPathKeyboardEvent(flags=0, key_code=i) for i in range(16)]
        original = FastPathInputPdu(events=events, flags=0)
        serialized = original.serialize()

        # Verify header has numEvents=0 (since 16 > 15)
        assert (serialized[0] >> 2) & 0x0F == 0

        parsed = FastPathInputPdu.parse(serialized)
        assert len(parsed.events) == 16
        for i, event in enumerate(parsed.events):
            assert isinstance(event, FastPathKeyboardEvent)
            assert event.key_code == i

    def test_parse_truncated_raises_error(self) -> None:
        """Truncated data should raise PduParseError."""
        # Just a header byte with no length
        with pytest.raises(PduParseError):
            FastPathInputPdu.parse(b"\x04")

    def test_serialize_empty_events(self) -> None:
        pdu = FastPathInputPdu(events=[], flags=0)
        data = pdu.serialize()
        parsed = FastPathInputPdu.parse(data)
        assert len(parsed.events) == 0


# ---------------------------------------------------------------------------
# FastPathOutputPdu
# ---------------------------------------------------------------------------


class TestFastPathOutputPdu:
    """Test fast-path output PDU container parse/serialize."""

    def test_parse_single_update(self) -> None:
        """Parse a fast-path output PDU with a single bitmap update."""
        update_data = b"\xDE\xAD\xBE\xEF"
        # Build raw PDU:
        # fpOutputHeader: action=0, flags=0 → 0x00
        # updateHeader: updateCode=1 (bitmap), frag=0, compression=0 → 0x01
        # size: 4 (LE)
        # data: 4 bytes
        update_bytes = bytes([0x01]) + struct.pack("<H", 4) + update_data
        # Total length: header(1) + length(1) + update_bytes
        total_length = 1 + 1 + len(update_bytes)
        raw = bytes([0x00, total_length]) + update_bytes

        pdu = FastPathOutputPdu.parse(raw)
        assert len(pdu.updates) == 1
        assert pdu.updates[0].update_code == FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_BITMAP
        assert pdu.updates[0].data == update_data

    def test_parse_multiple_updates(self) -> None:
        """Parse a fast-path output PDU with multiple updates."""
        update1_data = b"\x01\x02"
        update2_data = b"\x03\x04\x05"

        # Update 1: orders (code=0)
        update1_bytes = bytes([0x00]) + struct.pack("<H", 2) + update1_data
        # Update 2: bitmap (code=1)
        update2_bytes = bytes([0x01]) + struct.pack("<H", 3) + update2_data

        all_updates = update1_bytes + update2_bytes
        total_length = 1 + 1 + len(all_updates)
        raw = bytes([0x00, total_length]) + all_updates

        pdu = FastPathOutputPdu.parse(raw)
        assert len(pdu.updates) == 2
        assert pdu.updates[0].update_code == FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_ORDERS
        assert pdu.updates[0].data == update1_data
        assert pdu.updates[1].update_code == FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_BITMAP
        assert pdu.updates[1].data == update2_data

    def test_round_trip(self) -> None:
        """Serialize then parse should produce equivalent PDU."""
        original = FastPathOutputPdu(
            updates=[
                FastPathOutputUpdate(
                    update_code=FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_BITMAP,
                    data=b"\x01\x02\x03\x04",
                ),
                FastPathOutputUpdate(
                    update_code=FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_ORDERS,
                    data=b"\xAA\xBB",
                ),
            ],
            flags=0,
        )
        serialized = original.serialize()
        parsed = FastPathOutputPdu.parse(serialized)
        assert len(parsed.updates) == 2
        assert parsed.updates[0].update_code == original.updates[0].update_code
        assert parsed.updates[0].data == original.updates[0].data
        assert parsed.updates[1].update_code == original.updates[1].update_code
        assert parsed.updates[1].data == original.updates[1].data

    def test_parse_with_flags(self) -> None:
        """Parse output PDU with security flags set."""
        # fpOutputHeader: action=0, flags=2 (encrypted) → (2 << 4) = 0x20
        update_data = b"\xFF"
        update_bytes = bytes([0x01]) + struct.pack("<H", 1) + update_data
        total_length = 1 + 1 + len(update_bytes)
        raw = bytes([0x20, total_length]) + update_bytes

        pdu = FastPathOutputPdu.parse(raw)
        assert pdu.flags == 0x02
        assert len(pdu.updates) == 1

    def test_parse_empty_updates(self) -> None:
        """Parse output PDU with no updates."""
        # Just header + length (length = 2: header + length byte itself)
        raw = bytes([0x00, 0x02])
        pdu = FastPathOutputPdu.parse(raw)
        assert len(pdu.updates) == 0

    def test_parse_truncated_raises_error(self) -> None:
        """Truncated update data should raise PduParseError."""
        # Header says there's data but it's truncated
        # updateHeader present but size field is missing
        raw = bytes([0x00, 0x03, 0x01])  # length=3, one byte of update
        with pytest.raises(PduParseError):
            FastPathOutputPdu.parse(raw)


# ---------------------------------------------------------------------------
# FastPathOutputUpdate
# ---------------------------------------------------------------------------


class TestFastPathOutputUpdate:
    """Test individual fast-path output update serialize/parse."""

    def test_serialize_uncompressed(self) -> None:
        update = FastPathOutputUpdate(
            update_code=FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_BITMAP,
            data=b"\x01\x02\x03",
        )
        data = update.serialize()
        # updateHeader: code=1, frag=0, compression=0 → 0x01
        # size: 3 (LE)
        # data: 3 bytes
        assert data == bytes([0x01]) + struct.pack("<H", 3) + b"\x01\x02\x03"

    def test_round_trip(self) -> None:
        from arrdipi.pdu.base import ByteReader

        original = FastPathOutputUpdate(
            update_code=FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_ORDERS,
            fragmentation=0,
            compression=0,
            data=b"\xDE\xAD\xBE\xEF",
        )
        serialized = original.serialize()
        reader = ByteReader(serialized, pdu_type="Test")
        parsed = FastPathOutputUpdate.parse_from_reader(reader)
        assert parsed.update_code == original.update_code
        assert parsed.data == original.data
        assert parsed.fragmentation == original.fragmentation
        assert parsed.compression == original.compression


# ---------------------------------------------------------------------------
# Two-byte length encoding
# ---------------------------------------------------------------------------


class TestTwoByteLength:
    """Test PDUs with two-byte length encoding (length > 127)."""

    def test_input_pdu_large_length(self) -> None:
        """Input PDU with enough events to require two-byte length."""
        # Create enough events to exceed 127 bytes total
        # Each keyboard event is 2 bytes, so 64 events = 128 bytes of events
        events = [FastPathKeyboardEvent(flags=0, key_code=i % 256) for i in range(64)]
        original = FastPathInputPdu(events=events, flags=0)
        serialized = original.serialize()

        # Verify two-byte length encoding (high bit set on first length byte)
        assert serialized[1] & 0x80 != 0

        # Round-trip
        parsed = FastPathInputPdu.parse(serialized)
        assert len(parsed.events) == 64
        for i, event in enumerate(parsed.events):
            assert isinstance(event, FastPathKeyboardEvent)
            assert event.key_code == i % 256

    def test_output_pdu_large_length(self) -> None:
        """Output PDU with large update data requiring two-byte length."""
        large_data = bytes(range(256)) * 2  # 512 bytes
        original = FastPathOutputPdu(
            updates=[
                FastPathOutputUpdate(
                    update_code=FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_BITMAP,
                    data=large_data,
                )
            ],
            flags=0,
        )
        serialized = original.serialize()

        # Verify two-byte length encoding
        assert serialized[1] & 0x80 != 0

        # Round-trip
        parsed = FastPathOutputPdu.parse(serialized)
        assert len(parsed.updates) == 1
        assert parsed.updates[0].data == large_data
