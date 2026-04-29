"""Fast-path input and output PDU framing per [MS-RDPBCGR] 2.2.8.1.2 / 2.2.9.1.2.

Fast-path PDUs use a compact header format for high-frequency input events
and graphics output updates, reducing protocol overhead compared to slow-path
(TPKT-framed) PDUs.

Detection: if the first byte of incoming data is 0x03, it is a TPKT (slow-path)
header. Otherwise it is a fast-path PDU.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
from typing import Self

from arrdipi.errors import PduParseError
from arrdipi.pdu.base import ByteReader, ByteWriter, Pdu


# ---------------------------------------------------------------------------
# Constants and enums
# ---------------------------------------------------------------------------


class FastPathInputAction(IntEnum):
    """Fast-path input header action field [MS-RDPBCGR] 2.2.8.1.2."""

    FASTPATH_INPUT_ACTION_FASTPATH = 0x00
    FASTPATH_INPUT_ACTION_X224 = 0x03


class FastPathInputEventCode(IntEnum):
    """Fast-path input event codes [MS-RDPBCGR] 2.2.8.1.2.2."""

    FASTPATH_INPUT_EVENT_SCANCODE = 0x00
    FASTPATH_INPUT_EVENT_MOUSE = 0x01
    FASTPATH_INPUT_EVENT_MOUSEX = 0x02
    FASTPATH_INPUT_EVENT_SYNC = 0x03
    FASTPATH_INPUT_EVENT_UNICODE = 0x04
    FASTPATH_INPUT_EVENT_QOE_TIMESTAMP = 0x06


class FastPathKeyboardFlags(IntFlag):
    """Fast-path keyboard event flags [MS-RDPBCGR] 2.2.8.1.2.2.1."""

    FASTPATH_INPUT_KBDFLAGS_RELEASE = 0x01
    FASTPATH_INPUT_KBDFLAGS_EXTENDED = 0x02
    FASTPATH_INPUT_KBDFLAGS_EXTENDED1 = 0x04


class FastPathOutputAction(IntEnum):
    """Fast-path output header action field [MS-RDPBCGR] 2.2.9.1.2."""

    FASTPATH_OUTPUT_ACTION_FASTPATH = 0x00


class FastPathOutputUpdateCode(IntEnum):
    """Fast-path output update codes [MS-RDPBCGR] 2.2.9.1.2.1."""

    FASTPATH_UPDATETYPE_ORDERS = 0x00
    FASTPATH_UPDATETYPE_BITMAP = 0x01
    FASTPATH_UPDATETYPE_PALETTE = 0x02
    FASTPATH_UPDATETYPE_SYNCHRONIZE = 0x03
    FASTPATH_UPDATETYPE_SURFCMDS = 0x04
    FASTPATH_UPDATETYPE_PTR_NULL = 0x05
    FASTPATH_UPDATETYPE_PTR_DEFAULT = 0x06
    FASTPATH_UPDATETYPE_PTR_POSITION = 0x08
    FASTPATH_UPDATETYPE_COLOR = 0x09
    FASTPATH_UPDATETYPE_CACHED = 0x0A
    FASTPATH_UPDATETYPE_POINTER = 0x0B
    FASTPATH_UPDATETYPE_LARGE_POINTER = 0x0C


class FastPathOutputFragmentation(IntEnum):
    """Fast-path output update fragmentation flags [MS-RDPBCGR] 2.2.9.1.2.1."""

    FASTPATH_FRAGMENT_SINGLE = 0x00
    FASTPATH_FRAGMENT_LAST = 0x01
    FASTPATH_FRAGMENT_FIRST = 0x02
    FASTPATH_FRAGMENT_NEXT = 0x03


class FastPathSecurityFlags(IntFlag):
    """Fast-path header security flags [MS-RDPBCGR] 2.2.8.1.2."""

    FASTPATH_INPUT_SECURE_CHECKSUM = 0x01
    FASTPATH_INPUT_ENCRYPTED = 0x02


# ---------------------------------------------------------------------------
# Detection helper
# ---------------------------------------------------------------------------


def is_fast_path(first_byte: int) -> bool:
    """Determine if the first byte indicates a fast-path PDU.

    Per [MS-RDPBCGR], if the first byte is 0x03 it is a TPKT (slow-path)
    header. Otherwise it is a fast-path PDU (action bits 0-1 == 0x00).

    Args:
        first_byte: The first byte of the incoming data.

    Returns:
        True if the byte indicates fast-path, False for slow-path (TPKT).
    """
    return first_byte != 0x03


# ---------------------------------------------------------------------------
# Fast-path input event types
# ---------------------------------------------------------------------------


@dataclass
class FastPathKeyboardEvent:
    """Fast-path keyboard (scancode) input event [MS-RDPBCGR] 2.2.8.1.2.2.1.

    Attributes:
        flags: Keyboard event flags (release, extended).
        key_code: Scancode of the key.
    """

    flags: int = 0
    key_code: int = 0

    @property
    def event_code(self) -> int:
        return FastPathInputEventCode.FASTPATH_INPUT_EVENT_SCANCODE

    def serialize(self) -> bytes:
        """Serialize to fast-path input event bytes.

        Format: eventHeader (1 byte) + keyCode (1 byte)
        eventHeader: eventFlags (bits 0-4) | eventCode (bits 5-7)
        """
        w = ByteWriter()
        event_header = (self.flags & 0x1F) | ((self.event_code & 0x07) << 5)
        w.write_u8(event_header)
        w.write_u8(self.key_code & 0xFF)
        return w.to_bytes()

    @classmethod
    def parse(cls, event_header: int, reader: ByteReader) -> Self:
        """Parse from event header byte and reader positioned after header.

        Args:
            event_header: The event header byte (already read).
            reader: ByteReader positioned at the event data.
        """
        flags = event_header & 0x1F
        key_code = reader.read_u8()
        return cls(flags=flags, key_code=key_code)


@dataclass
class FastPathMouseEvent:
    """Fast-path mouse input event [MS-RDPBCGR] 2.2.8.1.2.2.3.

    Attributes:
        pointer_flags: Mouse button and movement flags.
        x_pos: X coordinate.
        y_pos: Y coordinate.
    """

    pointer_flags: int = 0
    x_pos: int = 0
    y_pos: int = 0

    @property
    def event_code(self) -> int:
        return FastPathInputEventCode.FASTPATH_INPUT_EVENT_MOUSE

    def serialize(self) -> bytes:
        """Serialize to fast-path input event bytes.

        Format: eventHeader (1 byte) + pointerFlags (2 bytes LE) + xPos (2 bytes LE) + yPos (2 bytes LE)
        """
        w = ByteWriter()
        event_header = (self.event_code & 0x07) << 5  # eventFlags = 0 for mouse
        w.write_u8(event_header)
        w.write_u16_le(self.pointer_flags & 0xFFFF)
        w.write_u16_le(self.x_pos & 0xFFFF)
        w.write_u16_le(self.y_pos & 0xFFFF)
        return w.to_bytes()

    @classmethod
    def parse(cls, event_header: int, reader: ByteReader) -> Self:
        """Parse from event header byte and reader positioned after header."""
        pointer_flags = reader.read_u16_le()
        x_pos = reader.read_u16_le()
        y_pos = reader.read_u16_le()
        return cls(pointer_flags=pointer_flags, x_pos=x_pos, y_pos=y_pos)


@dataclass
class FastPathUnicodeEvent:
    """Fast-path unicode keyboard input event [MS-RDPBCGR] 2.2.8.1.2.2.5.

    Attributes:
        flags: Event flags (e.g., release).
        unicode_code: Unicode character code.
    """

    flags: int = 0
    unicode_code: int = 0

    @property
    def event_code(self) -> int:
        return FastPathInputEventCode.FASTPATH_INPUT_EVENT_UNICODE

    def serialize(self) -> bytes:
        """Serialize to fast-path input event bytes.

        Format: eventHeader (1 byte) + unicodeCode (2 bytes LE)
        """
        w = ByteWriter()
        event_header = (self.flags & 0x1F) | ((self.event_code & 0x07) << 5)
        w.write_u8(event_header)
        w.write_u16_le(self.unicode_code & 0xFFFF)
        return w.to_bytes()

    @classmethod
    def parse(cls, event_header: int, reader: ByteReader) -> Self:
        """Parse from event header byte and reader positioned after header."""
        flags = event_header & 0x1F
        unicode_code = reader.read_u16_le()
        return cls(flags=flags, unicode_code=unicode_code)


# Type alias for any fast-path input event
FastPathInputEventType = FastPathKeyboardEvent | FastPathMouseEvent | FastPathUnicodeEvent


# ---------------------------------------------------------------------------
# Fast-path output update
# ---------------------------------------------------------------------------


@dataclass
class FastPathOutputUpdate:
    """Individual fast-path output update [MS-RDPBCGR] 2.2.9.1.2.1.

    Attributes:
        update_code: The type of update (bitmap, orders, pointer, etc.).
        fragmentation: Fragmentation state of this update.
        compression: Whether the update data is compressed.
        data: The raw update data payload.
    """

    update_code: int = 0
    fragmentation: int = FastPathOutputFragmentation.FASTPATH_FRAGMENT_SINGLE
    compression: int = 0
    data: bytes = b""

    def serialize(self) -> bytes:
        """Serialize to fast-path output update bytes.

        Format: updateHeader (1 byte) + [compressionFlags (1 byte)] + size (2 bytes LE) + data
        """
        w = ByteWriter()
        update_header = (
            (self.update_code & 0x0F)
            | ((self.fragmentation & 0x03) << 4)
            | ((self.compression & 0x01) << 6)
        )
        w.write_u8(update_header)
        if self.compression:
            w.write_u8(0)  # compressionFlags placeholder
        w.write_u16_le(len(self.data))
        w.write_bytes(self.data)
        return w.to_bytes()

    @classmethod
    def parse_from_reader(cls, reader: ByteReader) -> Self:
        """Parse a single output update from the reader."""
        update_header = reader.read_u8()
        update_code = update_header & 0x0F
        fragmentation = (update_header >> 4) & 0x03
        compression = (update_header >> 6) & 0x01

        if compression:
            _compression_flags = reader.read_u8()

        size = reader.read_u16_le()
        data = reader.read_bytes(size)

        return cls(
            update_code=update_code,
            fragmentation=fragmentation,
            compression=compression,
            data=data,
        )


# ---------------------------------------------------------------------------
# Fast-path length encoding helpers
# ---------------------------------------------------------------------------


def _encode_length(length: int) -> bytes:
    """Encode a fast-path PDU length using the variable-length encoding.

    If length <= 0x7F, encode as single byte.
    Otherwise encode as two bytes: (high_byte | 0x80), low_byte.
    """
    if length <= 0x7F:
        return bytes([length])
    else:
        high = ((length >> 8) & 0x7F) | 0x80
        low = length & 0xFF
        return bytes([high, low])


def _decode_length(reader: ByteReader) -> int:
    """Decode a fast-path PDU length from the variable-length encoding.

    If high bit of first byte is clear, length is that byte.
    Otherwise length is ((first & 0x7F) << 8) | second_byte.
    """
    first = reader.read_u8()
    if (first & 0x80) == 0:
        return first
    else:
        second = reader.read_u8()
        return ((first & 0x7F) << 8) | second


# ---------------------------------------------------------------------------
# Fast-path input PDU container
# ---------------------------------------------------------------------------


def _parse_input_event(reader: ByteReader) -> FastPathInputEventType:
    """Parse a single fast-path input event from the reader.

    The event header byte encodes: eventFlags (bits 0-4) | eventCode (bits 5-7).
    """
    event_header = reader.read_u8()
    event_code = (event_header >> 5) & 0x07

    if event_code == FastPathInputEventCode.FASTPATH_INPUT_EVENT_SCANCODE:
        return FastPathKeyboardEvent.parse(event_header, reader)
    elif event_code == FastPathInputEventCode.FASTPATH_INPUT_EVENT_MOUSE:
        return FastPathMouseEvent.parse(event_header, reader)
    elif event_code == FastPathInputEventCode.FASTPATH_INPUT_EVENT_UNICODE:
        return FastPathUnicodeEvent.parse(event_header, reader)
    else:
        raise PduParseError(
            pdu_type="FastPathInputEvent",
            offset=reader.offset - 1,
            description=f"unsupported fast-path input event code: 0x{event_code:02X}",
        )


@dataclass
class FastPathInputPdu(Pdu):
    """Fast-path input PDU container [MS-RDPBCGR] 2.2.8.1.2.

    Contains a list of fast-path input events serialized with the compact
    fast-path header format.

    Attributes:
        events: List of fast-path input events.
        flags: Security flags (encryption, secure checksum).
    """

    events: list[FastPathInputEventType] = field(default_factory=list)
    flags: int = 0

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse a fast-path input PDU from raw bytes.

        Format:
        - fpInputHeader: u8 (action bits 0-1, numEvents bits 2-5, flags bits 6-7)
        - length: variable (1 or 2 bytes)
        - numEvents: u8 (optional, only if header numEvents == 0)
        - fpInputEvents: sequence of input events
        """
        reader = ByteReader(data, pdu_type="FastPathInputPdu")

        fp_input_header = reader.read_u8()
        num_events_in_header = (fp_input_header >> 2) & 0x0F
        flags = (fp_input_header >> 6) & 0x03

        _length = _decode_length(reader)

        # If numEvents in header is 0, read the separate numEvents byte
        if num_events_in_header == 0:
            num_events = reader.read_u8()
        else:
            num_events = num_events_in_header

        events: list[FastPathInputEventType] = []
        for _ in range(num_events):
            event = _parse_input_event(reader)
            events.append(event)

        return cls(events=events, flags=flags)

    def serialize(self) -> bytes:
        """Serialize the fast-path input PDU to bytes.

        Builds the complete PDU with header, length, and serialized events.
        """
        # Serialize all events first to compute total length
        events_data = bytearray()
        for event in self.events:
            events_data.extend(event.serialize())

        num_events = len(self.events)

        # Determine if numEvents fits in header (4 bits, max 15; 0 is reserved
        # to indicate the count is in a separate byte)
        if 1 <= num_events <= 15:
            num_events_in_header = num_events
            extra_num_events_byte = b""
        else:
            # 0 events or > 15 events: use separate byte
            num_events_in_header = 0
            extra_num_events_byte = bytes([num_events & 0xFF])

        # Build header byte: action (bits 0-1) | numEvents (bits 2-5) | flags (bits 6-7)
        fp_input_header = (
            (FastPathInputAction.FASTPATH_INPUT_ACTION_FASTPATH & 0x03)
            | ((num_events_in_header & 0x0F) << 2)
            | ((self.flags & 0x03) << 6)
        )

        # Compute total length: header(1) + length_field + extra_num_events + events_data
        # We need to figure out the length field size first
        # Length includes everything from the header byte onwards
        payload_size = 1 + len(extra_num_events_byte) + len(events_data)
        # Try single-byte length first
        total_with_1byte_len = payload_size + 1
        if total_with_1byte_len <= 0x7F:
            length_bytes = _encode_length(total_with_1byte_len)
        else:
            total_with_2byte_len = payload_size + 2
            length_bytes = _encode_length(total_with_2byte_len)

        w = ByteWriter()
        w.write_u8(fp_input_header)
        w.write_bytes(length_bytes)
        w.write_bytes(extra_num_events_byte)
        w.write_bytes(bytes(events_data))
        return w.to_bytes()


# ---------------------------------------------------------------------------
# Fast-path output PDU container
# ---------------------------------------------------------------------------


@dataclass
class FastPathOutputPdu(Pdu):
    """Fast-path output PDU container [MS-RDPBCGR] 2.2.9.1.2.

    Contains a list of fast-path output updates parsed from the server.

    Attributes:
        updates: List of fast-path output updates.
        flags: Security flags from the header.
    """

    updates: list[FastPathOutputUpdate] = field(default_factory=list)
    flags: int = 0

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse a fast-path output PDU from raw bytes.

        Format:
        - fpOutputHeader: u8 (action bits 0-1, reserved bits 2-3, flags bits 4-5, reserved2 bits 6-7)
        - length: variable (1 or 2 bytes)
        - fpOutputUpdates: sequence of output updates
        """
        reader = ByteReader(data, pdu_type="FastPathOutputPdu")

        fp_output_header = reader.read_u8()
        flags = (fp_output_header >> 4) & 0x03

        _length = _decode_length(reader)

        updates: list[FastPathOutputUpdate] = []
        while reader.remaining() > 0:
            update = FastPathOutputUpdate.parse_from_reader(reader)
            updates.append(update)

        return cls(updates=updates, flags=flags)

    def serialize(self) -> bytes:
        """Serialize the fast-path output PDU to bytes."""
        # Serialize all updates first
        updates_data = bytearray()
        for update in self.updates:
            updates_data.extend(update.serialize())

        # Build header byte: action (bits 0-1) | reserved (bits 2-3) | flags (bits 4-5) | reserved2 (bits 6-7)
        fp_output_header = (
            (FastPathOutputAction.FASTPATH_OUTPUT_ACTION_FASTPATH & 0x03)
            | ((self.flags & 0x03) << 4)
        )

        # Compute total length
        payload_size = 1 + len(updates_data)
        total_with_1byte_len = payload_size + 1
        if total_with_1byte_len <= 0x7F:
            length_bytes = _encode_length(total_with_1byte_len)
        else:
            total_with_2byte_len = payload_size + 2
            length_bytes = _encode_length(total_with_2byte_len)

        w = ByteWriter()
        w.write_u8(fp_output_header)
        w.write_bytes(length_bytes)
        w.write_bytes(bytes(updates_data))
        return w.to_bytes()
