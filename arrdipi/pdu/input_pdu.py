"""Slow-path input event PDUs per [MS-RDPBCGR] 2.2.8.1.1.3.1.1.

Implements the slow-path (TPKT-framed) input event types and the InputPdu
container that wraps a list of input events. These share semantic meaning
with the fast-path input events in fastpath.py but use a different wire format.

Slow-path input events include a 4-byte event_time field and use 16-bit flags,
whereas fast-path events encode flags in the event header byte.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
from typing import Self, Union

from arrdipi.errors import PduParseError
from arrdipi.pdu.base import ByteReader, ByteWriter, Pdu


# ---------------------------------------------------------------------------
# Constants and enums
# ---------------------------------------------------------------------------


class InputMessageType(IntEnum):
    """Slow-path input event message types [MS-RDPBCGR] 2.2.8.1.1.3.1.1."""

    INPUT_EVENT_SCANCODE = 0x0004
    INPUT_EVENT_UNICODE = 0x0005
    INPUT_EVENT_MOUSE = 0x8001
    INPUT_EVENT_MOUSEX = 0x8002


class KeyboardEventFlags(IntFlag):
    """Keyboard event flags [MS-RDPBCGR] 2.2.8.1.1.3.1.1.1."""

    KBDFLAGS_EXTENDED = 0x0100
    KBDFLAGS_EXTENDED1 = 0x0200
    KBDFLAGS_DOWN = 0x4000
    KBDFLAGS_RELEASE = 0x8000


class PointerFlags(IntFlag):
    """Mouse event pointer flags [MS-RDPBCGR] 2.2.8.1.1.3.1.1.3."""

    PTRFLAGS_HWHEEL = 0x0400
    PTRFLAGS_WHEEL = 0x0200
    PTRFLAGS_WHEEL_NEGATIVE = 0x0100
    PTRFLAGS_MOVE = 0x0800
    PTRFLAGS_DOWN = 0x8000
    PTRFLAGS_BUTTON1 = 0x1000
    PTRFLAGS_BUTTON2 = 0x2000
    PTRFLAGS_BUTTON3 = 0x4000


class ExtendedPointerFlags(IntFlag):
    """Extended mouse event flags [MS-RDPBCGR] 2.2.8.1.1.3.1.1.4."""

    PTRXFLAGS_DOWN = 0x8000
    PTRXFLAGS_BUTTON1 = 0x0001
    PTRXFLAGS_BUTTON2 = 0x0002


# ---------------------------------------------------------------------------
# Slow-path input event types
# ---------------------------------------------------------------------------


@dataclass
class KeyboardEvent:
    """Slow-path keyboard (scancode) input event [MS-RDPBCGR] 2.2.8.1.1.3.1.1.1.

    Wire format (8 bytes total within the input event structure):
    - event_time: u32 LE (milliseconds since session start)
    - event_flags: u16 LE (keyboard flags: extended, release, etc.)
    - key_code: u16 LE (scancode)

    Attributes:
        event_time: Timestamp in milliseconds.
        event_flags: Keyboard event flags.
        key_code: Scancode of the key.
    """

    event_time: int = 0
    event_flags: int = 0
    key_code: int = 0

    @property
    def message_type(self) -> int:
        return InputMessageType.INPUT_EVENT_SCANCODE

    def serialize(self) -> bytes:
        """Serialize to slow-path input event bytes (without message type header).

        Returns the 8-byte event body: event_time(4) + event_flags(2) + key_code(2).
        """
        w = ByteWriter()
        w.write_u32_le(self.event_time)
        w.write_u16_le(self.event_flags)
        w.write_u16_le(self.key_code)
        return w.to_bytes()

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse from raw bytes (8 bytes: event_time + event_flags + key_code)."""
        reader = ByteReader(data, pdu_type="KeyboardEvent")
        event_time = reader.read_u32_le()
        event_flags = reader.read_u16_le()
        key_code = reader.read_u16_le()
        return cls(event_time=event_time, event_flags=event_flags, key_code=key_code)

    @classmethod
    def parse_from_reader(cls, reader: ByteReader) -> Self:
        """Parse from a ByteReader positioned at the event body."""
        event_time = reader.read_u32_le()
        event_flags = reader.read_u16_le()
        key_code = reader.read_u16_le()
        return cls(event_time=event_time, event_flags=event_flags, key_code=key_code)


@dataclass
class UnicodeKeyboardEvent:
    """Slow-path unicode keyboard input event [MS-RDPBCGR] 2.2.8.1.1.3.1.1.2.

    Wire format (8 bytes total within the input event structure):
    - event_time: u32 LE (milliseconds since session start)
    - event_flags: u16 LE (keyboard flags: release)
    - unicode_code: u16 LE (Unicode code point)

    Attributes:
        event_time: Timestamp in milliseconds.
        event_flags: Keyboard event flags.
        unicode_code: Unicode character code point.
    """

    event_time: int = 0
    event_flags: int = 0
    unicode_code: int = 0

    @property
    def message_type(self) -> int:
        return InputMessageType.INPUT_EVENT_UNICODE

    def serialize(self) -> bytes:
        """Serialize to slow-path input event bytes (without message type header).

        Returns the 8-byte event body: event_time(4) + event_flags(2) + unicode_code(2).
        """
        w = ByteWriter()
        w.write_u32_le(self.event_time)
        w.write_u16_le(self.event_flags)
        w.write_u16_le(self.unicode_code)
        return w.to_bytes()

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse from raw bytes (8 bytes: event_time + event_flags + unicode_code)."""
        reader = ByteReader(data, pdu_type="UnicodeKeyboardEvent")
        event_time = reader.read_u32_le()
        event_flags = reader.read_u16_le()
        unicode_code = reader.read_u16_le()
        return cls(event_time=event_time, event_flags=event_flags, unicode_code=unicode_code)

    @classmethod
    def parse_from_reader(cls, reader: ByteReader) -> Self:
        """Parse from a ByteReader positioned at the event body."""
        event_time = reader.read_u32_le()
        event_flags = reader.read_u16_le()
        unicode_code = reader.read_u16_le()
        return cls(event_time=event_time, event_flags=event_flags, unicode_code=unicode_code)


@dataclass
class MouseEvent:
    """Slow-path mouse input event [MS-RDPBCGR] 2.2.8.1.1.3.1.1.3.

    Wire format (10 bytes total within the input event structure):
    - event_time: u32 LE (milliseconds since session start)
    - event_flags: u16 LE (pointer flags: move, button, wheel)
    - x: u16 LE (x coordinate)
    - y: u16 LE (y coordinate)

    Attributes:
        event_time: Timestamp in milliseconds.
        event_flags: Pointer flags (movement, buttons, wheel).
        x: X coordinate of the mouse.
        y: Y coordinate of the mouse.
    """

    event_time: int = 0
    event_flags: int = 0
    x: int = 0
    y: int = 0

    @property
    def message_type(self) -> int:
        return InputMessageType.INPUT_EVENT_MOUSE

    def serialize(self) -> bytes:
        """Serialize to slow-path input event bytes (without message type header).

        Returns the 10-byte event body: event_time(4) + event_flags(2) + x(2) + y(2).
        """
        w = ByteWriter()
        w.write_u32_le(self.event_time)
        w.write_u16_le(self.event_flags)
        w.write_u16_le(self.x)
        w.write_u16_le(self.y)
        return w.to_bytes()

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse from raw bytes (10 bytes: event_time + event_flags + x + y)."""
        reader = ByteReader(data, pdu_type="MouseEvent")
        event_time = reader.read_u32_le()
        event_flags = reader.read_u16_le()
        x = reader.read_u16_le()
        y = reader.read_u16_le()
        return cls(event_time=event_time, event_flags=event_flags, x=x, y=y)

    @classmethod
    def parse_from_reader(cls, reader: ByteReader) -> Self:
        """Parse from a ByteReader positioned at the event body."""
        event_time = reader.read_u32_le()
        event_flags = reader.read_u16_le()
        x = reader.read_u16_le()
        y = reader.read_u16_le()
        return cls(event_time=event_time, event_flags=event_flags, x=x, y=y)


@dataclass
class ExtendedMouseEvent:
    """Slow-path extended mouse input event [MS-RDPBCGR] 2.2.8.1.1.3.1.1.4.

    Wire format (10 bytes total within the input event structure):
    - event_time: u32 LE (milliseconds since session start)
    - event_flags: u16 LE (extended pointer flags)
    - x: u16 LE (x coordinate)
    - y: u16 LE (y coordinate)

    Attributes:
        event_time: Timestamp in milliseconds.
        event_flags: Extended pointer flags.
        x: X coordinate of the mouse.
        y: Y coordinate of the mouse.
    """

    event_time: int = 0
    event_flags: int = 0
    x: int = 0
    y: int = 0

    @property
    def message_type(self) -> int:
        return InputMessageType.INPUT_EVENT_MOUSEX

    def serialize(self) -> bytes:
        """Serialize to slow-path input event bytes (without message type header).

        Returns the 10-byte event body: event_time(4) + event_flags(2) + x(2) + y(2).
        """
        w = ByteWriter()
        w.write_u32_le(self.event_time)
        w.write_u16_le(self.event_flags)
        w.write_u16_le(self.x)
        w.write_u16_le(self.y)
        return w.to_bytes()

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse from raw bytes (10 bytes: event_time + event_flags + x + y)."""
        reader = ByteReader(data, pdu_type="ExtendedMouseEvent")
        event_time = reader.read_u32_le()
        event_flags = reader.read_u16_le()
        x = reader.read_u16_le()
        y = reader.read_u16_le()
        return cls(event_time=event_time, event_flags=event_flags, x=x, y=y)

    @classmethod
    def parse_from_reader(cls, reader: ByteReader) -> Self:
        """Parse from a ByteReader positioned at the event body."""
        event_time = reader.read_u32_le()
        event_flags = reader.read_u16_le()
        x = reader.read_u16_le()
        y = reader.read_u16_le()
        return cls(event_time=event_time, event_flags=event_flags, x=x, y=y)


# Type alias for any slow-path input event
SlowPathInputEventType = Union[KeyboardEvent, UnicodeKeyboardEvent, MouseEvent, ExtendedMouseEvent]


# ---------------------------------------------------------------------------
# Slow-path input PDU container
# ---------------------------------------------------------------------------


@dataclass
class InputPdu(Pdu):
    """Slow-path input PDU container [MS-RDPBCGR] 2.2.8.1.1.3.1.

    Wraps a list of slow-path input events. The wire format is:
    - num_events: u16 LE (number of input events)
    - pad: u16 LE (padding, must be 0)
    - events: sequence of (message_type: u16 LE + event body)

    Each event in the list is preceded by a 2-byte message type field that
    identifies the event type, followed by the event-specific body.

    Attributes:
        events: List of slow-path input events.
    """

    events: list[SlowPathInputEventType] = field(default_factory=list)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse a slow-path input PDU from raw bytes.

        Args:
            data: Raw bytes containing the InputPdu.

        Returns:
            Parsed InputPdu instance.

        Raises:
            PduParseError: On malformed or truncated data.
        """
        reader = ByteReader(data, pdu_type="InputPdu")

        num_events = reader.read_u16_le()
        _pad = reader.read_u16_le()  # padding, ignored

        events: list[SlowPathInputEventType] = []
        for _ in range(num_events):
            message_type = reader.read_u16_le()

            if message_type == InputMessageType.INPUT_EVENT_SCANCODE:
                event = KeyboardEvent.parse_from_reader(reader)
            elif message_type == InputMessageType.INPUT_EVENT_UNICODE:
                event = UnicodeKeyboardEvent.parse_from_reader(reader)
            elif message_type == InputMessageType.INPUT_EVENT_MOUSE:
                event = MouseEvent.parse_from_reader(reader)
            elif message_type == InputMessageType.INPUT_EVENT_MOUSEX:
                event = ExtendedMouseEvent.parse_from_reader(reader)
            else:
                raise PduParseError(
                    pdu_type="InputPdu",
                    offset=reader.offset - 2,
                    description=f"unsupported input event message type: 0x{message_type:04X}",
                )
            events.append(event)

        return cls(events=events)

    def serialize(self) -> bytes:
        """Serialize the slow-path input PDU to bytes.

        Returns:
            Bytes containing the complete InputPdu wire format.
        """
        w = ByteWriter()
        w.write_u16_le(len(self.events))
        w.write_u16_le(0)  # pad

        for event in self.events:
            w.write_u16_le(event.message_type)
            w.write_bytes(event.serialize())

        return w.to_bytes()
