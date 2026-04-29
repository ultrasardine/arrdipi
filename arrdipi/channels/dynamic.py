"""Dynamic virtual channel (DRDYNVC) multiplexer.

Implements [MS-RDPEDYC] — Dynamic Virtual Channel Extension.
DRDYNVC operates over the "drdynvc" static virtual channel and multiplexes
multiple dynamic virtual channels over a single static channel.

PDU types per [MS-RDPEDYC]:
- Create Request/Response (cmd 0x01)
- Data First (cmd 0x02)
- Data (cmd 0x03)
- Close (cmd 0x04)

The DRDYNVC header has a cbId field (2 bits) that determines the size of
the channel ID field (1, 2, or 4 bytes).
"""

from __future__ import annotations

import struct
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Self

from arrdipi.errors import PduParseError
from arrdipi.pdu.base import ByteReader, ByteWriter

# DRDYNVC command IDs
DYNVC_CMD_CREATE = 0x01
DYNVC_CMD_DATA_FIRST = 0x02
DYNVC_CMD_DATA = 0x03
DYNVC_CMD_CLOSE = 0x04

# cbId field values → channel ID sizes in bytes
_CBID_SIZES = {0: 1, 1: 2, 2: 4}

# Length field sizes for Data First total_length
_LEN_SIZES = {0: 1, 1: 2, 2: 4}


def _read_channel_id(reader: ByteReader, cb_id: int) -> int:
    """Read a channel ID of the size indicated by cbId."""
    if cb_id == 0:
        return reader.read_u8()
    elif cb_id == 1:
        return reader.read_u16_le()
    elif cb_id == 2:
        return reader.read_u32_le()
    else:
        raise PduParseError(
            pdu_type="DRDYNVC",
            offset=reader.offset,
            description=f"invalid cbId value: {cb_id}",
        )


def _write_channel_id(writer: ByteWriter, channel_id: int, cb_id: int) -> None:
    """Write a channel ID with the size indicated by cbId."""
    if cb_id == 0:
        writer.write_u8(channel_id)
    elif cb_id == 1:
        writer.write_u16_le(channel_id)
    elif cb_id == 2:
        writer.write_u32_le(channel_id)


def _read_length(reader: ByteReader, len_id: int) -> int:
    """Read a length field of the size indicated by Len."""
    if len_id == 0:
        return reader.read_u8()
    elif len_id == 1:
        return reader.read_u16_le()
    elif len_id == 2:
        return reader.read_u32_le()
    else:
        raise PduParseError(
            pdu_type="DRDYNVC",
            offset=reader.offset,
            description=f"invalid Len value: {len_id}",
        )


def _write_length(writer: ByteWriter, length: int, len_id: int) -> None:
    """Write a length field with the size indicated by Len."""
    if len_id == 0:
        writer.write_u8(length)
    elif len_id == 1:
        writer.write_u16_le(length)
    elif len_id == 2:
        writer.write_u32_le(length)


def _cbid_for_channel_id(channel_id: int) -> int:
    """Determine the smallest cbId that can hold the given channel ID."""
    if channel_id <= 0xFF:
        return 0
    elif channel_id <= 0xFFFF:
        return 1
    else:
        return 2


def _len_id_for_length(length: int) -> int:
    """Determine the smallest Len field size for the given length."""
    if length <= 0xFF:
        return 0
    elif length <= 0xFFFF:
        return 1
    else:
        return 2


# --- PDU Dataclasses ---


@dataclass
class DynvcCreateRequest:
    """DRDYNVC Create Request PDU [MS-RDPEDYC] 2.2.2.1.

    Sent by the server to request creation of a dynamic virtual channel.
    """

    channel_id: int
    channel_name: str

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse a Create Request PDU from raw bytes (after the header byte)."""
        reader = ByteReader(data, "DynvcCreateRequest")
        header = reader.read_u8()
        cmd = (header >> 4) & 0x0F
        cb_id = header & 0x03

        if cmd != DYNVC_CMD_CREATE:
            raise PduParseError(
                pdu_type="DynvcCreateRequest",
                offset=0,
                description=f"expected cmd 0x01, got 0x{cmd:02X}",
            )

        channel_id = _read_channel_id(reader, cb_id)

        # Channel name is null-terminated ASCII
        name_bytes = reader.read_bytes(reader.remaining())
        if name_bytes and name_bytes[-1:] == b"\x00":
            name_bytes = name_bytes[:-1]
        channel_name = name_bytes.decode("ascii", errors="replace")

        return cls(channel_id=channel_id, channel_name=channel_name)

    def serialize(self) -> bytes:
        """Serialize the Create Request PDU to wire format."""
        writer = ByteWriter()
        cb_id = _cbid_for_channel_id(self.channel_id)
        header = (DYNVC_CMD_CREATE << 4) | cb_id
        writer.write_u8(header)
        _write_channel_id(writer, self.channel_id, cb_id)
        writer.write_bytes(self.channel_name.encode("ascii") + b"\x00")
        return writer.to_bytes()


@dataclass
class DynvcCreateResponse:
    """DRDYNVC Create Response PDU [MS-RDPEDYC] 2.2.2.2.

    Sent by the client to acknowledge or reject channel creation.
    creation_status == 0 means success; non-zero means failure.
    """

    channel_id: int
    creation_status: int

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse a Create Response PDU from raw bytes."""
        reader = ByteReader(data, "DynvcCreateResponse")
        header = reader.read_u8()
        cmd = (header >> 4) & 0x0F
        cb_id = header & 0x03

        if cmd != DYNVC_CMD_CREATE:
            raise PduParseError(
                pdu_type="DynvcCreateResponse",
                offset=0,
                description=f"expected cmd 0x01, got 0x{cmd:02X}",
            )

        channel_id = _read_channel_id(reader, cb_id)
        creation_status = reader.read_u32_le()

        return cls(channel_id=channel_id, creation_status=creation_status)

    def serialize(self) -> bytes:
        """Serialize the Create Response PDU to wire format."""
        writer = ByteWriter()
        cb_id = _cbid_for_channel_id(self.channel_id)
        header = (DYNVC_CMD_CREATE << 4) | cb_id
        writer.write_u8(header)
        _write_channel_id(writer, self.channel_id, cb_id)
        writer.write_u32_le(self.creation_status)
        return writer.to_bytes()


@dataclass
class DynvcDataFirst:
    """DRDYNVC Data First PDU [MS-RDPEDYC] 2.2.3.1.

    Sent when a large message is fragmented. Contains the total data length
    and the first fragment.
    """

    channel_id: int
    total_length: int
    data: bytes

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse a Data First PDU from raw bytes."""
        reader = ByteReader(data, "DynvcDataFirst")
        header = reader.read_u8()
        cmd = (header >> 4) & 0x0F
        cb_id = header & 0x03
        len_id = (header >> 2) & 0x03

        if cmd != DYNVC_CMD_DATA_FIRST:
            raise PduParseError(
                pdu_type="DynvcDataFirst",
                offset=0,
                description=f"expected cmd 0x02, got 0x{cmd:02X}",
            )

        channel_id = _read_channel_id(reader, cb_id)
        total_length = _read_length(reader, len_id)
        payload = reader.read_bytes(reader.remaining())

        return cls(channel_id=channel_id, total_length=total_length, data=payload)

    def serialize(self) -> bytes:
        """Serialize the Data First PDU to wire format."""
        writer = ByteWriter()
        cb_id = _cbid_for_channel_id(self.channel_id)
        len_id = _len_id_for_length(self.total_length)
        header = (DYNVC_CMD_DATA_FIRST << 4) | (len_id << 2) | cb_id
        writer.write_u8(header)
        _write_channel_id(writer, self.channel_id, cb_id)
        _write_length(writer, self.total_length, len_id)
        writer.write_bytes(self.data)
        return writer.to_bytes()


@dataclass
class DynvcData:
    """DRDYNVC Data PDU [MS-RDPEDYC] 2.2.3.2.

    Contains a data fragment (or complete message if no fragmentation).
    """

    channel_id: int
    data: bytes

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse a Data PDU from raw bytes."""
        reader = ByteReader(data, "DynvcData")
        header = reader.read_u8()
        cmd = (header >> 4) & 0x0F
        cb_id = header & 0x03

        if cmd != DYNVC_CMD_DATA:
            raise PduParseError(
                pdu_type="DynvcData",
                offset=0,
                description=f"expected cmd 0x03, got 0x{cmd:02X}",
            )

        channel_id = _read_channel_id(reader, cb_id)
        payload = reader.read_bytes(reader.remaining())

        return cls(channel_id=channel_id, data=payload)

    def serialize(self) -> bytes:
        """Serialize the Data PDU to wire format."""
        writer = ByteWriter()
        cb_id = _cbid_for_channel_id(self.channel_id)
        header = (DYNVC_CMD_DATA << 4) | cb_id
        writer.write_u8(header)
        _write_channel_id(writer, self.channel_id, cb_id)
        writer.write_bytes(self.data)
        return writer.to_bytes()


@dataclass
class DynvcClose:
    """DRDYNVC Close PDU [MS-RDPEDYC] 2.2.2.4.

    Sent to close a dynamic virtual channel.
    """

    channel_id: int

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse a Close PDU from raw bytes."""
        reader = ByteReader(data, "DynvcClose")
        header = reader.read_u8()
        cmd = (header >> 4) & 0x0F
        cb_id = header & 0x03

        if cmd != DYNVC_CMD_CLOSE:
            raise PduParseError(
                pdu_type="DynvcClose",
                offset=0,
                description=f"expected cmd 0x04, got 0x{cmd:02X}",
            )

        channel_id = _read_channel_id(reader, cb_id)

        return cls(channel_id=channel_id)

    def serialize(self) -> bytes:
        """Serialize the Close PDU to wire format."""
        writer = ByteWriter()
        cb_id = _cbid_for_channel_id(self.channel_id)
        header = (DYNVC_CMD_CLOSE << 4) | cb_id
        writer.write_u8(header)
        _write_channel_id(writer, self.channel_id, cb_id)
        return writer.to_bytes()


# --- Dynamic Channel State ---


@dataclass
class DynamicChannel:
    """State for a single dynamic virtual channel."""

    channel_id: int
    channel_name: str
    handler: Callable[[bytes], Awaitable[None]]
    reassembly_buffer: bytearray = field(default_factory=bytearray)
    total_length: int = 0


# --- DRDYNVC Handler ---


class DrdynvcHandler:
    """DRDYNVC multiplexer for dynamic virtual channels.

    Operates over the 'drdynvc' static virtual channel.
    Parses inbound DRDYNVC PDUs and dispatches to the appropriate
    dynamic channel handler.

    (Req 21, AC 1–5)
    """

    def __init__(self, send_fn: Callable[[bytes], Awaitable[None]]) -> None:
        """Initialize the DRDYNVC handler.

        Args:
            send_fn: Async callable to send data on the underlying static channel.
                     This is typically bound to the static channel's send method.
        """
        self._send_fn = send_fn
        self._channels: dict[int, DynamicChannel] = {}
        self._channel_factories: dict[str, Callable[[], Callable[[bytes], Awaitable[None]]]] = {}

    @property
    def channels(self) -> dict[int, DynamicChannel]:
        """Active dynamic channels keyed by channel ID."""
        return self._channels

    def register_channel_factory(
        self, name: str, factory: Callable[[], Callable[[bytes], Awaitable[None]]]
    ) -> None:
        """Register a factory for creating dynamic channel handlers by name.

        When a Create Request arrives for a channel with the given name,
        the factory is called to create a handler for that channel.

        Args:
            name: The dynamic channel name (e.g. "AUDIO_INPUT", "Microsoft::Windows::RDS::Graphics").
            factory: A callable that returns an async handler function for the channel.
        """
        self._channel_factories[name] = factory

    async def handle_message(self, data: bytes) -> None:
        """Dispatch an inbound DRDYNVC PDU.

        Parses the PDU header to determine the command type and routes
        to the appropriate handler method.

        (Req 21, AC 2–5)

        Args:
            data: The complete DRDYNVC PDU bytes received from the static channel.
        """
        if not data:
            return

        header = data[0]
        cmd = (header >> 4) & 0x0F

        if cmd == DYNVC_CMD_CREATE:
            pdu = DynvcCreateRequest.parse(data)
            await self._handle_create_request(pdu.channel_id, pdu.channel_name)
        elif cmd == DYNVC_CMD_DATA_FIRST:
            pdu_df = DynvcDataFirst.parse(data)
            await self._handle_data_first(pdu_df.channel_id, pdu_df.total_length, pdu_df.data)
        elif cmd == DYNVC_CMD_DATA:
            pdu_d = DynvcData.parse(data)
            await self._handle_data(pdu_d.channel_id, pdu_d.data)
        elif cmd == DYNVC_CMD_CLOSE:
            pdu_c = DynvcClose.parse(data)
            await self._handle_close(pdu_c.channel_id)
        # Unknown commands are silently ignored per protocol robustness

    async def _handle_create_request(self, channel_id: int, channel_name: str) -> None:
        """Create a dynamic channel and send a Create Response.

        If a factory is registered for the channel name, the channel is created
        with the factory-produced handler and a success response (status 0) is sent.
        Otherwise, a failure response (status 0xC0000001) is sent.

        (Req 21, AC 2)

        Args:
            channel_id: The server-assigned channel ID.
            channel_name: The name of the dynamic channel to create.
        """
        if channel_name in self._channel_factories:
            handler = self._channel_factories[channel_name]()
            self._channels[channel_id] = DynamicChannel(
                channel_id=channel_id,
                channel_name=channel_name,
                handler=handler,
            )
            response = DynvcCreateResponse(channel_id=channel_id, creation_status=0)
        else:
            # No factory registered — reject the channel
            response = DynvcCreateResponse(
                channel_id=channel_id, creation_status=0xC0000001
            )

        await self._send_fn(response.serialize())

    async def _handle_data_first(
        self, channel_id: int, total_length: int, data: bytes
    ) -> None:
        """Handle a Data First PDU — start fragmentation reassembly.

        (Req 21, AC 5)

        Args:
            channel_id: The dynamic channel ID.
            total_length: The total length of the complete message.
            data: The first fragment of the message.
        """
        channel = self._channels.get(channel_id)
        if channel is None:
            return

        channel.reassembly_buffer = bytearray(data)
        channel.total_length = total_length

        # If the first fragment completes the message, dispatch immediately
        if len(channel.reassembly_buffer) >= total_length:
            complete = bytes(channel.reassembly_buffer[:total_length])
            channel.reassembly_buffer = bytearray()
            channel.total_length = 0
            await channel.handler(complete)

    async def _handle_data(self, channel_id: int, data: bytes) -> None:
        """Handle a Data PDU — either a complete message or a continuation fragment.

        If the channel has an active reassembly (total_length > 0), the data is
        appended to the reassembly buffer. Once the total length is reached, the
        complete message is dispatched to the handler.

        If no reassembly is active, the data is treated as a complete message.

        (Req 21, AC 3, 5)

        Args:
            channel_id: The dynamic channel ID.
            data: The data payload.
        """
        channel = self._channels.get(channel_id)
        if channel is None:
            return

        if channel.total_length > 0:
            # Continuation of a fragmented message
            channel.reassembly_buffer.extend(data)
            if len(channel.reassembly_buffer) >= channel.total_length:
                complete = bytes(channel.reassembly_buffer[: channel.total_length])
                channel.reassembly_buffer = bytearray()
                channel.total_length = 0
                await channel.handler(complete)
        else:
            # Complete (non-fragmented) message
            await channel.handler(data)

    async def _handle_close(self, channel_id: int) -> None:
        """Close a dynamic channel and release resources.

        (Req 21, AC 4)

        Args:
            channel_id: The dynamic channel ID to close.
        """
        if channel_id in self._channels:
            del self._channels[channel_id]
