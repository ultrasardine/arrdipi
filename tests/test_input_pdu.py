"""Tests for arrdipi/pdu/input_pdu.py: slow-path input event PDUs.

Tests round-trip correctness for each input event type and the InputPdu
container, plus fast-path vs slow-path encoding comparison.
"""

from __future__ import annotations

import struct

import pytest

from arrdipi.errors import PduParseError
from arrdipi.pdu.input_pdu import (
    ExtendedMouseEvent,
    ExtendedPointerFlags,
    InputMessageType,
    InputPdu,
    KeyboardEvent,
    KeyboardEventFlags,
    MouseEvent,
    PointerFlags,
    UnicodeKeyboardEvent,
)
from arrdipi.pdu.fastpath import (
    FastPathInputPdu,
    FastPathKeyboardEvent,
    FastPathKeyboardFlags,
    FastPathMouseEvent,
    FastPathUnicodeEvent,
)


# ---------------------------------------------------------------------------
# KeyboardEvent
# ---------------------------------------------------------------------------


class TestKeyboardEvent:
    """Test slow-path keyboard event serialize/parse."""

    def test_serialize_key_press(self) -> None:
        event = KeyboardEvent(event_time=1000, event_flags=0, key_code=0x1E)
        data = event.serialize()
        # event_time(4) + event_flags(2) + key_code(2) = 8 bytes
        assert len(data) == 8
        assert struct.unpack_from("<I", data, 0)[0] == 1000
        assert struct.unpack_from("<H", data, 4)[0] == 0
        assert struct.unpack_from("<H", data, 6)[0] == 0x1E

    def test_serialize_key_release(self) -> None:
        event = KeyboardEvent(
            event_time=2000,
            event_flags=KeyboardEventFlags.KBDFLAGS_RELEASE,
            key_code=0x1E,
        )
        data = event.serialize()
        assert struct.unpack_from("<H", data, 4)[0] == KeyboardEventFlags.KBDFLAGS_RELEASE

    def test_serialize_extended_key(self) -> None:
        event = KeyboardEvent(
            event_time=500,
            event_flags=KeyboardEventFlags.KBDFLAGS_EXTENDED | KeyboardEventFlags.KBDFLAGS_DOWN,
            key_code=0x4B,
        )
        data = event.serialize()
        flags = struct.unpack_from("<H", data, 4)[0]
        assert flags & KeyboardEventFlags.KBDFLAGS_EXTENDED
        assert flags & KeyboardEventFlags.KBDFLAGS_DOWN

    def test_round_trip(self) -> None:
        original = KeyboardEvent(event_time=12345, event_flags=0x8100, key_code=0x39)
        serialized = original.serialize()
        parsed = KeyboardEvent.parse(serialized)
        assert parsed.event_time == original.event_time
        assert parsed.event_flags == original.event_flags
        assert parsed.key_code == original.key_code

    def test_message_type(self) -> None:
        event = KeyboardEvent()
        assert event.message_type == InputMessageType.INPUT_EVENT_SCANCODE

    def test_parse_truncated_raises_error(self) -> None:
        with pytest.raises(PduParseError):
            KeyboardEvent.parse(b"\x00\x01\x02")  # Only 3 bytes, need 8


# ---------------------------------------------------------------------------
# UnicodeKeyboardEvent
# ---------------------------------------------------------------------------


class TestUnicodeKeyboardEvent:
    """Test slow-path unicode keyboard event serialize/parse."""

    def test_serialize_unicode_char(self) -> None:
        event = UnicodeKeyboardEvent(event_time=3000, event_flags=0, unicode_code=0x0041)
        data = event.serialize()
        assert len(data) == 8
        assert struct.unpack_from("<I", data, 0)[0] == 3000
        assert struct.unpack_from("<H", data, 4)[0] == 0
        assert struct.unpack_from("<H", data, 6)[0] == 0x0041

    def test_serialize_unicode_release(self) -> None:
        event = UnicodeKeyboardEvent(
            event_time=4000,
            event_flags=KeyboardEventFlags.KBDFLAGS_RELEASE,
            unicode_code=0x0041,
        )
        data = event.serialize()
        assert struct.unpack_from("<H", data, 4)[0] == KeyboardEventFlags.KBDFLAGS_RELEASE

    def test_serialize_cjk_character(self) -> None:
        # Chinese character '世' = U+4E16
        event = UnicodeKeyboardEvent(event_time=100, event_flags=0, unicode_code=0x4E16)
        data = event.serialize()
        assert struct.unpack_from("<H", data, 6)[0] == 0x4E16

    def test_round_trip(self) -> None:
        original = UnicodeKeyboardEvent(event_time=9999, event_flags=0x8000, unicode_code=0x00E9)
        serialized = original.serialize()
        parsed = UnicodeKeyboardEvent.parse(serialized)
        assert parsed.event_time == original.event_time
        assert parsed.event_flags == original.event_flags
        assert parsed.unicode_code == original.unicode_code

    def test_message_type(self) -> None:
        event = UnicodeKeyboardEvent()
        assert event.message_type == InputMessageType.INPUT_EVENT_UNICODE

    def test_parse_truncated_raises_error(self) -> None:
        with pytest.raises(PduParseError):
            UnicodeKeyboardEvent.parse(b"\x00\x01\x02\x03\x04")  # Only 5 bytes, need 8


# ---------------------------------------------------------------------------
# MouseEvent
# ---------------------------------------------------------------------------


class TestMouseEvent:
    """Test slow-path mouse event serialize/parse."""

    def test_serialize_mouse_move(self) -> None:
        event = MouseEvent(
            event_time=5000,
            event_flags=PointerFlags.PTRFLAGS_MOVE,
            x=100,
            y=200,
        )
        data = event.serialize()
        assert len(data) == 10
        assert struct.unpack_from("<I", data, 0)[0] == 5000
        assert struct.unpack_from("<H", data, 4)[0] == PointerFlags.PTRFLAGS_MOVE
        assert struct.unpack_from("<H", data, 6)[0] == 100
        assert struct.unpack_from("<H", data, 8)[0] == 200

    def test_serialize_left_button_down(self) -> None:
        event = MouseEvent(
            event_time=6000,
            event_flags=PointerFlags.PTRFLAGS_DOWN | PointerFlags.PTRFLAGS_BUTTON1,
            x=50,
            y=75,
        )
        data = event.serialize()
        flags = struct.unpack_from("<H", data, 4)[0]
        assert flags & PointerFlags.PTRFLAGS_DOWN
        assert flags & PointerFlags.PTRFLAGS_BUTTON1

    def test_serialize_wheel_scroll(self) -> None:
        event = MouseEvent(
            event_time=7000,
            event_flags=PointerFlags.PTRFLAGS_WHEEL | 0x0078,  # wheel rotation = 120
            x=300,
            y=400,
        )
        data = event.serialize()
        flags = struct.unpack_from("<H", data, 4)[0]
        assert flags & PointerFlags.PTRFLAGS_WHEEL

    def test_round_trip(self) -> None:
        original = MouseEvent(event_time=11111, event_flags=0x9800, x=1920, y=1080)
        serialized = original.serialize()
        parsed = MouseEvent.parse(serialized)
        assert parsed.event_time == original.event_time
        assert parsed.event_flags == original.event_flags
        assert parsed.x == original.x
        assert parsed.y == original.y

    def test_message_type(self) -> None:
        event = MouseEvent()
        assert event.message_type == InputMessageType.INPUT_EVENT_MOUSE

    def test_parse_truncated_raises_error(self) -> None:
        with pytest.raises(PduParseError):
            MouseEvent.parse(b"\x00\x01\x02\x03\x04\x05\x06")  # Only 7 bytes, need 10


# ---------------------------------------------------------------------------
# ExtendedMouseEvent
# ---------------------------------------------------------------------------


class TestExtendedMouseEvent:
    """Test slow-path extended mouse event serialize/parse."""

    def test_serialize_xbutton1_down(self) -> None:
        event = ExtendedMouseEvent(
            event_time=8000,
            event_flags=ExtendedPointerFlags.PTRXFLAGS_DOWN | ExtendedPointerFlags.PTRXFLAGS_BUTTON1,
            x=640,
            y=480,
        )
        data = event.serialize()
        assert len(data) == 10
        flags = struct.unpack_from("<H", data, 4)[0]
        assert flags & ExtendedPointerFlags.PTRXFLAGS_DOWN
        assert flags & ExtendedPointerFlags.PTRXFLAGS_BUTTON1

    def test_serialize_xbutton2_release(self) -> None:
        event = ExtendedMouseEvent(
            event_time=9000,
            event_flags=ExtendedPointerFlags.PTRXFLAGS_BUTTON2,  # no DOWN = release
            x=800,
            y=600,
        )
        data = event.serialize()
        flags = struct.unpack_from("<H", data, 4)[0]
        assert flags & ExtendedPointerFlags.PTRXFLAGS_BUTTON2
        assert not (flags & ExtendedPointerFlags.PTRXFLAGS_DOWN)

    def test_round_trip(self) -> None:
        original = ExtendedMouseEvent(event_time=22222, event_flags=0x8001, x=1024, y=768)
        serialized = original.serialize()
        parsed = ExtendedMouseEvent.parse(serialized)
        assert parsed.event_time == original.event_time
        assert parsed.event_flags == original.event_flags
        assert parsed.x == original.x
        assert parsed.y == original.y

    def test_message_type(self) -> None:
        event = ExtendedMouseEvent()
        assert event.message_type == InputMessageType.INPUT_EVENT_MOUSEX

    def test_parse_truncated_raises_error(self) -> None:
        with pytest.raises(PduParseError):
            ExtendedMouseEvent.parse(b"\x00\x01\x02\x03\x04\x05")  # Only 6 bytes, need 10


# ---------------------------------------------------------------------------
# InputPdu container
# ---------------------------------------------------------------------------


class TestInputPdu:
    """Test slow-path InputPdu container serialize/parse."""

    def test_serialize_single_keyboard_event(self) -> None:
        pdu = InputPdu(events=[KeyboardEvent(event_time=100, event_flags=0, key_code=0x1E)])
        data = pdu.serialize()
        # num_events(2) + pad(2) + message_type(2) + event_body(8) = 14 bytes
        assert len(data) == 14
        assert struct.unpack_from("<H", data, 0)[0] == 1  # num_events
        assert struct.unpack_from("<H", data, 2)[0] == 0  # pad
        assert struct.unpack_from("<H", data, 4)[0] == InputMessageType.INPUT_EVENT_SCANCODE

    def test_serialize_multiple_events(self) -> None:
        pdu = InputPdu(
            events=[
                KeyboardEvent(event_time=100, event_flags=0, key_code=0x1E),
                MouseEvent(event_time=200, event_flags=0x0800, x=50, y=60),
                UnicodeKeyboardEvent(event_time=300, event_flags=0, unicode_code=0x0041),
                ExtendedMouseEvent(event_time=400, event_flags=0x8001, x=100, y=200),
            ]
        )
        data = pdu.serialize()
        assert struct.unpack_from("<H", data, 0)[0] == 4  # num_events

    def test_round_trip_single_keyboard(self) -> None:
        original = InputPdu(
            events=[KeyboardEvent(event_time=5000, event_flags=0x8000, key_code=0x39)]
        )
        serialized = original.serialize()
        parsed = InputPdu.parse(serialized)
        assert len(parsed.events) == 1
        assert isinstance(parsed.events[0], KeyboardEvent)
        assert parsed.events[0].event_time == 5000
        assert parsed.events[0].event_flags == 0x8000
        assert parsed.events[0].key_code == 0x39

    def test_round_trip_all_event_types(self) -> None:
        original = InputPdu(
            events=[
                KeyboardEvent(event_time=100, event_flags=0x0100, key_code=0x4B),
                UnicodeKeyboardEvent(event_time=200, event_flags=0x8000, unicode_code=0x4E16),
                MouseEvent(event_time=300, event_flags=0x9000, x=1920, y=1080),
                ExtendedMouseEvent(event_time=400, event_flags=0x8002, x=640, y=480),
            ]
        )
        serialized = original.serialize()
        parsed = InputPdu.parse(serialized)

        assert len(parsed.events) == 4

        kb = parsed.events[0]
        assert isinstance(kb, KeyboardEvent)
        assert kb.event_time == 100
        assert kb.event_flags == 0x0100
        assert kb.key_code == 0x4B

        uni = parsed.events[1]
        assert isinstance(uni, UnicodeKeyboardEvent)
        assert uni.event_time == 200
        assert uni.event_flags == 0x8000
        assert uni.unicode_code == 0x4E16

        mouse = parsed.events[2]
        assert isinstance(mouse, MouseEvent)
        assert mouse.event_time == 300
        assert mouse.event_flags == 0x9000
        assert mouse.x == 1920
        assert mouse.y == 1080

        ext_mouse = parsed.events[3]
        assert isinstance(ext_mouse, ExtendedMouseEvent)
        assert ext_mouse.event_time == 400
        assert ext_mouse.event_flags == 0x8002
        assert ext_mouse.x == 640
        assert ext_mouse.y == 480

    def test_round_trip_empty(self) -> None:
        original = InputPdu(events=[])
        serialized = original.serialize()
        parsed = InputPdu.parse(serialized)
        assert len(parsed.events) == 0

    def test_parse_unknown_message_type_raises_error(self) -> None:
        """Unknown message type should raise PduParseError."""
        # Build a PDU with an invalid message type
        w_data = struct.pack("<H", 1)  # num_events = 1
        w_data += struct.pack("<H", 0)  # pad
        w_data += struct.pack("<H", 0xFFFF)  # invalid message type
        w_data += b"\x00" * 8  # dummy event body
        with pytest.raises(PduParseError) as exc_info:
            InputPdu.parse(w_data)
        assert "0xFFFF" in str(exc_info.value)

    def test_parse_truncated_raises_error(self) -> None:
        """Truncated data should raise PduParseError."""
        # Only 2 bytes (num_events) without pad
        with pytest.raises(PduParseError):
            InputPdu.parse(b"\x01\x00")

    def test_serialize_preserves_byte_correctness(self) -> None:
        """Verify exact byte layout of serialized InputPdu."""
        event = KeyboardEvent(event_time=0, event_flags=0, key_code=0x01)
        pdu = InputPdu(events=[event])
        data = pdu.serialize()

        # Manual construction of expected bytes
        expected = b""
        expected += struct.pack("<H", 1)  # num_events
        expected += struct.pack("<H", 0)  # pad
        expected += struct.pack("<H", InputMessageType.INPUT_EVENT_SCANCODE)  # message_type
        expected += struct.pack("<I", 0)  # event_time
        expected += struct.pack("<H", 0)  # event_flags
        expected += struct.pack("<H", 0x01)  # key_code
        assert data == expected


# ---------------------------------------------------------------------------
# Fast-path vs slow-path encoding comparison
# ---------------------------------------------------------------------------


class TestFastPathVsSlowPath:
    """Compare fast-path and slow-path encoding for the same logical events.

    Fast-path events are more compact (no event_time, flags in header byte).
    Slow-path events include a 4-byte timestamp and 2-byte message type prefix.
    """

    def test_keyboard_event_size_comparison(self) -> None:
        """Fast-path keyboard is smaller than slow-path."""
        # Slow-path: message_type(2) + event_time(4) + flags(2) + key_code(2) = 10 bytes in container
        slow = KeyboardEvent(event_time=0, event_flags=0, key_code=0x1E)
        slow_size = 2 + len(slow.serialize())  # +2 for message_type in container

        # Fast-path: eventHeader(1) + keyCode(1) = 2 bytes
        fast = FastPathKeyboardEvent(flags=0, key_code=0x1E)
        fast_size = len(fast.serialize())

        assert fast_size < slow_size
        assert fast_size == 2
        assert slow_size == 10

    def test_mouse_event_size_comparison(self) -> None:
        """Fast-path mouse is smaller than slow-path."""
        # Slow-path: message_type(2) + event_time(4) + flags(2) + x(2) + y(2) = 12 bytes in container
        slow = MouseEvent(event_time=0, event_flags=0x0800, x=100, y=200)
        slow_size = 2 + len(slow.serialize())

        # Fast-path: eventHeader(1) + pointerFlags(2) + x(2) + y(2) = 7 bytes
        fast = FastPathMouseEvent(pointer_flags=0x0800, x_pos=100, y_pos=200)
        fast_size = len(fast.serialize())

        assert fast_size < slow_size
        assert fast_size == 7
        assert slow_size == 12

    def test_unicode_event_size_comparison(self) -> None:
        """Fast-path unicode is smaller than slow-path."""
        # Slow-path: message_type(2) + event_time(4) + flags(2) + unicode_code(2) = 10 bytes in container
        slow = UnicodeKeyboardEvent(event_time=0, event_flags=0, unicode_code=0x0041)
        slow_size = 2 + len(slow.serialize())

        # Fast-path: eventHeader(1) + unicodeCode(2) = 3 bytes
        fast = FastPathUnicodeEvent(flags=0, unicode_code=0x0041)
        fast_size = len(fast.serialize())

        assert fast_size < slow_size
        assert fast_size == 3
        assert slow_size == 10

    def test_keyboard_semantic_equivalence(self) -> None:
        """Both paths encode the same logical key event."""
        # Key 'A' press (scancode 0x1E)
        slow = KeyboardEvent(event_time=0, event_flags=0, key_code=0x1E)
        fast = FastPathKeyboardEvent(flags=0, key_code=0x1E)

        assert slow.key_code == fast.key_code

        # Key 'A' release
        slow_rel = KeyboardEvent(
            event_time=0,
            event_flags=KeyboardEventFlags.KBDFLAGS_RELEASE,
            key_code=0x1E,
        )
        fast_rel = FastPathKeyboardEvent(
            flags=FastPathKeyboardFlags.FASTPATH_INPUT_KBDFLAGS_RELEASE,
            key_code=0x1E,
        )
        assert slow_rel.key_code == fast_rel.key_code

    def test_mouse_semantic_equivalence(self) -> None:
        """Both paths encode the same logical mouse event."""
        slow = MouseEvent(event_time=0, event_flags=0x0800, x=500, y=300)
        fast = FastPathMouseEvent(pointer_flags=0x0800, x_pos=500, y_pos=300)

        assert slow.event_flags == fast.pointer_flags
        assert slow.x == fast.x_pos
        assert slow.y == fast.y_pos

    def test_fast_path_container_round_trip(self) -> None:
        """Fast-path input PDU container round-trips correctly."""
        pdu = FastPathInputPdu(
            events=[
                FastPathKeyboardEvent(flags=0, key_code=0x1E),
                FastPathMouseEvent(pointer_flags=0x0800, x_pos=100, y_pos=200),
            ],
            flags=0,
        )
        serialized = pdu.serialize()
        parsed = FastPathInputPdu.parse(serialized)
        assert len(parsed.events) == 2

    def test_slow_path_container_round_trip(self) -> None:
        """Slow-path input PDU container round-trips correctly."""
        pdu = InputPdu(
            events=[
                KeyboardEvent(event_time=100, event_flags=0, key_code=0x1E),
                MouseEvent(event_time=200, event_flags=0x0800, x=100, y=200),
            ]
        )
        serialized = pdu.serialize()
        parsed = InputPdu.parse(serialized)
        assert len(parsed.events) == 2
        assert isinstance(parsed.events[0], KeyboardEvent)
        assert isinstance(parsed.events[1], MouseEvent)
