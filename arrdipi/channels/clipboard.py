"""Clipboard redirection channel (CLIPRDR).

Implements [MS-RDPECLIP] — Remote Desktop Protocol Clipboard Virtual Channel Extension.
Operates over the "cliprdr" static virtual channel.

The clipboard channel handles:
- Monitor Ready handshake (server → client)
- Capabilities exchange
- Format List exchange (bidirectional)
- Format Data Request/Response (bidirectional)

Requirements addressed: Req 22 (AC 1–6)
"""

from __future__ import annotations

import asyncio
import struct
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
from typing import Self

from arrdipi.pdu.base import ByteReader, ByteWriter

# CLIPRDR message types
CLIPRDR_MONITOR_READY = 0x0001
CLIPRDR_FORMAT_LIST = 0x0002
CLIPRDR_FORMAT_LIST_RESPONSE = 0x0003
CLIPRDR_FORMAT_DATA_REQUEST = 0x0004
CLIPRDR_FORMAT_DATA_RESPONSE = 0x0005
CLIPRDR_CAPABILITIES = 0x0007
CLIPRDR_TEMP_DIRECTORY = 0x0008

# Clipboard format IDs
CF_UNICODETEXT = 13

# Message flags
CB_RESPONSE_OK = 0x0001
CB_RESPONSE_FAIL = 0x0002
CB_ASCII_NAMES = 0x0004

# General capability set
CB_CAPSTYPE_GENERAL = 0x0001
CB_CAPS_VERSION_2 = 0x0002

# General capability flags
CB_USE_LONG_FORMAT_NAMES = 0x00000002
CB_STREAM_FILECLIP_ENABLED = 0x00000004
CB_FILECLIP_NO_FILE_PATHS = 0x00000008
CB_CAN_LOCK_CLIPDATA = 0x00000010


@dataclass
class ClipboardFormat:
    """A clipboard format entry in a Format List."""

    format_id: int
    format_name: str = ""


# --- PDU Dataclasses ---


@dataclass
class MonitorReadyPdu:
    """CLIPRDR Monitor Ready PDU [MS-RDPECLIP] 2.2.2.1.

    Sent by the server to indicate the clipboard channel is ready.
    """

    msg_flags: int = 0

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse from raw CLIPRDR message body (after header)."""
        # Monitor Ready has no body beyond the header
        return cls()

    def serialize(self) -> bytes:
        """Serialize to wire format (header + empty body)."""
        # msgType(u16) + msgFlags(u16) + dataLen(u32)
        return struct.pack("<HHI", CLIPRDR_MONITOR_READY, self.msg_flags, 0)


@dataclass
class ClipboardCapabilitiesPdu:
    """CLIPRDR Capabilities PDU [MS-RDPECLIP] 2.2.2.2.

    Exchanges clipboard capabilities between client and server.
    """

    general_flags: int = CB_USE_LONG_FORMAT_NAMES

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse from raw CLIPRDR message body."""
        if len(data) < 4:
            return cls()
        # cCapabilitiesSets(u16) + pad1(u16)
        # Then capability sets follow
        offset = 4  # skip cCapabilitiesSets + pad
        general_flags = 0
        if len(data) >= offset + 8:
            # capabilitySetType(u16) + lengthCapability(u16) + version(u32) + generalFlags(u32)
            cap_type = struct.unpack_from("<H", data, offset)[0]
            if cap_type == CB_CAPSTYPE_GENERAL and len(data) >= offset + 12:
                general_flags = struct.unpack_from("<I", data, offset + 8)[0]
        return cls(general_flags=general_flags)

    def serialize(self) -> bytes:
        """Serialize to wire format."""
        # Build general capability set
        # capabilitySetType(u16) + lengthCapability(u16) + version(u32) + generalFlags(u32)
        cap_set = struct.pack(
            "<HHII",
            CB_CAPSTYPE_GENERAL,
            12,  # length of this capability set
            CB_CAPS_VERSION_2,
            self.general_flags,
        )
        # cCapabilitiesSets(u16) + pad1(u16) + capability sets
        body = struct.pack("<HH", 1, 0) + cap_set
        # Header: msgType(u16) + msgFlags(u16) + dataLen(u32)
        header = struct.pack("<HHI", CLIPRDR_CAPABILITIES, 0, len(body))
        return header + body


@dataclass
class TemporaryDirectoryPdu:
    """CLIPRDR Temporary Directory PDU [MS-RDPECLIP] 2.2.2.3.

    Sent by the client to inform the server of a temporary directory path.
    """

    temp_dir: str = ""

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse from raw CLIPRDR message body."""
        # 520 bytes of null-terminated Unicode path
        if len(data) >= 520:
            path_bytes = data[:520]
            temp_dir = path_bytes.decode("utf-16-le", errors="replace").rstrip("\x00")
            return cls(temp_dir=temp_dir)
        return cls()

    def serialize(self) -> bytes:
        """Serialize to wire format."""
        # Encode path as UTF-16LE, padded to 520 bytes
        path_encoded = self.temp_dir.encode("utf-16-le")
        path_padded = path_encoded[:518] + b"\x00\x00"  # null terminate
        path_padded = path_padded.ljust(520, b"\x00")
        # Header: msgType(u16) + msgFlags(u16) + dataLen(u32)
        header = struct.pack("<HHI", CLIPRDR_TEMP_DIRECTORY, 0, len(path_padded))
        return header + path_padded


@dataclass
class FormatListPdu:
    """CLIPRDR Format List PDU [MS-RDPECLIP] 2.2.3.1.

    Announces available clipboard formats.
    """

    formats: list[ClipboardFormat] = field(default_factory=list)
    use_long_names: bool = True

    @classmethod
    def parse(cls, data: bytes, use_long_names: bool = True) -> Self:
        """Parse from raw CLIPRDR message body."""
        formats: list[ClipboardFormat] = []
        offset = 0

        if use_long_names:
            # Long format: formatId(u32) + null-terminated Unicode name
            while offset + 4 <= len(data):
                format_id = struct.unpack_from("<I", data, offset)[0]
                offset += 4
                # Read null-terminated UTF-16LE name
                name_start = offset
                while offset + 2 <= len(data):
                    char = struct.unpack_from("<H", data, offset)[0]
                    offset += 2
                    if char == 0:
                        break
                name_bytes = data[name_start : offset - 2] if offset > name_start + 2 else b""
                name = name_bytes.decode("utf-16-le", errors="replace") if name_bytes else ""
                formats.append(ClipboardFormat(format_id=format_id, format_name=name))
        else:
            # Short format: formatId(u32) + 32 bytes ASCII name
            while offset + 36 <= len(data):
                format_id = struct.unpack_from("<I", data, offset)[0]
                offset += 4
                name_bytes = data[offset : offset + 32]
                offset += 32
                name = name_bytes.split(b"\x00")[0].decode("ascii", errors="replace")
                formats.append(ClipboardFormat(format_id=format_id, format_name=name))

        return cls(formats=formats, use_long_names=use_long_names)

    def serialize(self) -> bytes:
        """Serialize to wire format."""
        body = bytearray()

        if self.use_long_names:
            for fmt in self.formats:
                body.extend(struct.pack("<I", fmt.format_id))
                name_encoded = fmt.format_name.encode("utf-16-le") + b"\x00\x00"
                body.extend(name_encoded)
        else:
            for fmt in self.formats:
                body.extend(struct.pack("<I", fmt.format_id))
                name_encoded = fmt.format_name.encode("ascii", errors="replace")[:31]
                name_padded = name_encoded + b"\x00" * (32 - len(name_encoded))
                body.extend(name_padded)

        header = struct.pack("<HHI", CLIPRDR_FORMAT_LIST, 0, len(body))
        return header + bytes(body)


@dataclass
class FormatDataRequestPdu:
    """CLIPRDR Format Data Request PDU [MS-RDPECLIP] 2.2.5.1.

    Requests clipboard data in a specific format.
    """

    requested_format_id: int

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse from raw CLIPRDR message body."""
        if len(data) < 4:
            return cls(requested_format_id=0)
        format_id = struct.unpack_from("<I", data, 0)[0]
        return cls(requested_format_id=format_id)

    def serialize(self) -> bytes:
        """Serialize to wire format."""
        body = struct.pack("<I", self.requested_format_id)
        header = struct.pack("<HHI", CLIPRDR_FORMAT_DATA_REQUEST, 0, len(body))
        return header + body


@dataclass
class FormatDataResponsePdu:
    """CLIPRDR Format Data Response PDU [MS-RDPECLIP] 2.2.5.2.

    Contains the requested clipboard data.
    """

    data: bytes = b""
    is_success: bool = True

    @classmethod
    def parse(cls, data: bytes, msg_flags: int = CB_RESPONSE_OK) -> Self:
        """Parse from raw CLIPRDR message body."""
        is_success = bool(msg_flags & CB_RESPONSE_OK)
        return cls(data=data, is_success=is_success)

    def serialize(self) -> bytes:
        """Serialize to wire format."""
        flags = CB_RESPONSE_OK if self.is_success else CB_RESPONSE_FAIL
        header = struct.pack("<HHI", CLIPRDR_FORMAT_DATA_RESPONSE, flags, len(self.data))
        return header + self.data


# --- Clipboard Channel ---


class ClipboardChannel:
    """Clipboard redirection channel operating over the "cliprdr" static VC.

    Handles the CLIPRDR protocol exchange including Monitor Ready handshake,
    format list exchange, and data transfer.

    (Req 22, AC 1–6)
    """

    def __init__(self, send_fn: Callable[[bytes], Awaitable[None]]) -> None:
        """Initialize the clipboard channel.

        Args:
            send_fn: Async callable to send data on the underlying static channel.
        """
        self._send_fn = send_fn
        self._use_long_format_names = True
        self._local_clipboard_text: str = ""
        self._server_formats: list[ClipboardFormat] = []
        self._server_clipboard_data: bytes | None = None
        self._data_response_event = asyncio.Event()
        self._ready = False

    @property
    def ready(self) -> bool:
        """Whether the clipboard channel has completed the Monitor Ready handshake."""
        return self._ready

    @property
    def server_formats(self) -> list[ClipboardFormat]:
        """Available clipboard formats from the server."""
        return self._server_formats

    async def handle_message(self, data: bytes) -> None:
        """Dispatch an inbound CLIPRDR PDU.

        Parses the CLIPRDR header and routes to the appropriate handler.

        Args:
            data: The complete CLIPRDR PDU bytes.
        """
        if len(data) < 8:
            return

        msg_type = struct.unpack_from("<H", data, 0)[0]
        msg_flags = struct.unpack_from("<H", data, 2)[0]
        data_len = struct.unpack_from("<I", data, 4)[0]
        body = data[8 : 8 + data_len] if data_len > 0 else b""

        if msg_type == CLIPRDR_MONITOR_READY:
            await self._handle_monitor_ready()
        elif msg_type == CLIPRDR_FORMAT_LIST:
            await self._handle_server_format_list(body, msg_flags)
        elif msg_type == CLIPRDR_FORMAT_DATA_REQUEST:
            await self._handle_format_data_request(body)
        elif msg_type == CLIPRDR_FORMAT_DATA_RESPONSE:
            self._handle_format_data_response(body, msg_flags)
        elif msg_type == CLIPRDR_CAPABILITIES:
            self._handle_capabilities(body)

    async def _handle_monitor_ready(self) -> None:
        """Handle Monitor Ready → send Capabilities + Temporary Directory.

        (Req 22, AC 2)
        """
        self._ready = True

        # Send Capabilities PDU
        caps = ClipboardCapabilitiesPdu(general_flags=CB_USE_LONG_FORMAT_NAMES)
        await self._send_fn(caps.serialize())

        # Send Temporary Directory PDU
        temp_dir = TemporaryDirectoryPdu(temp_dir="C:\\Windows\\Temp")
        await self._send_fn(temp_dir.serialize())

    def _handle_capabilities(self, body: bytes) -> None:
        """Handle server Capabilities PDU — parse general flags."""
        caps = ClipboardCapabilitiesPdu.parse(body)
        self._use_long_format_names = bool(caps.general_flags & CB_USE_LONG_FORMAT_NAMES)

    async def _handle_server_format_list(self, body: bytes, msg_flags: int) -> None:
        """Handle server Format List → parse and store available formats.

        (Req 22, AC 5)
        """
        format_list = FormatListPdu.parse(body, use_long_names=self._use_long_format_names)
        self._server_formats = format_list.formats

        # Send Format List Response (OK)
        response = struct.pack("<HHI", CLIPRDR_FORMAT_LIST_RESPONSE, CB_RESPONSE_OK, 0)
        await self._send_fn(response)

    async def _handle_format_data_request(self, body: bytes) -> None:
        """Handle Format Data Request → respond with clipboard data.

        (Req 22, AC 4)
        """
        request = FormatDataRequestPdu.parse(body)

        if request.requested_format_id == CF_UNICODETEXT and self._local_clipboard_text:
            # Encode text as UTF-16LE with null terminator
            text_data = self._local_clipboard_text.encode("utf-16-le") + b"\x00\x00"
            response = FormatDataResponsePdu(data=text_data, is_success=True)
        else:
            # No data available for the requested format
            response = FormatDataResponsePdu(data=b"", is_success=False)

        await self._send_fn(response.serialize())

    def _handle_format_data_response(self, body: bytes, msg_flags: int) -> None:
        """Handle Format Data Response — store received data."""
        if msg_flags & CB_RESPONSE_OK:
            self._server_clipboard_data = body
        else:
            self._server_clipboard_data = None
        self._data_response_event.set()

    async def set_clipboard_text(self, text: str) -> None:
        """Set local clipboard text and announce to server.

        Sends a Format List with CF_UNICODETEXT to inform the server
        that clipboard text is available.

        (Req 22, AC 3, 6)

        Args:
            text: The text to place on the clipboard.
        """
        self._local_clipboard_text = text

        # Send Format List with CF_UNICODETEXT
        format_list = FormatListPdu(
            formats=[ClipboardFormat(format_id=CF_UNICODETEXT, format_name="")],
            use_long_names=self._use_long_format_names,
        )
        await self._send_fn(format_list.serialize())

    async def get_server_clipboard_text(self, timeout: float = 5.0) -> str:
        """Request and return text from the server clipboard.

        Sends a Format Data Request for CF_UNICODETEXT and waits for the response.

        Args:
            timeout: Maximum time to wait for the response in seconds.

        Returns:
            The server clipboard text, or empty string if unavailable.
        """
        # Check if server has CF_UNICODETEXT available
        has_text = any(f.format_id == CF_UNICODETEXT for f in self._server_formats)
        if not has_text:
            return ""

        # Reset event and send request
        self._data_response_event.clear()
        self._server_clipboard_data = None

        request = FormatDataRequestPdu(requested_format_id=CF_UNICODETEXT)
        await self._send_fn(request.serialize())

        # Wait for response
        try:
            await asyncio.wait_for(self._data_response_event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            return ""

        if self._server_clipboard_data is None:
            return ""

        # Decode UTF-16LE, strip null terminator
        text = self._server_clipboard_data.decode("utf-16-le", errors="replace")
        return text.rstrip("\x00")
