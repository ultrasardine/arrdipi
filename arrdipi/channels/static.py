"""Static virtual channel chunking and reassembly.

Implements [MS-RDPBCGR] Section 2.2.6.1 — Virtual Channel PDU.
Static virtual channels segment large messages into chunks with
CHANNEL_FLAG_FIRST/CHANNEL_FLAG_LAST flags and reassemble inbound
chunks into complete messages before dispatching to handlers.
"""

from __future__ import annotations

import struct
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

from arrdipi.pdu.types import ChannelChunkFlags

if TYPE_CHECKING:
    from arrdipi.mcs.layer import McsLayer

# Default max chunk size per [MS-RDPBCGR] — typically negotiated via
# VirtualChannelCapabilitySet, but 1600 bytes is the standard default.
DEFAULT_MAX_CHUNK_SIZE = 1600


class StaticVirtualChannel:
    """Handles chunking/reassembly for a single static virtual channel.

    Outbound messages are segmented into chunks respecting max_chunk_size,
    with appropriate CHANNEL_FLAG_FIRST and CHANNEL_FLAG_LAST flags.

    Inbound chunks are reassembled into complete messages before being
    dispatched to the registered handler.

    (Req 20, AC 2–4)
    """

    def __init__(
        self,
        channel_name: str,
        channel_id: int,
        max_chunk_size: int = DEFAULT_MAX_CHUNK_SIZE,
    ) -> None:
        """Initialize a static virtual channel.

        Args:
            channel_name: The name of the virtual channel (e.g. "cliprdr").
            channel_id: The MCS channel ID assigned during connection.
            max_chunk_size: Maximum size of a single chunk payload in bytes.
        """
        self._name = channel_name
        self._channel_id = channel_id
        self._max_chunk_size = max_chunk_size
        self._reassembly_buffer: bytearray = bytearray()
        self._expected_length: int = 0
        self._handler: Callable[[bytes], Awaitable[None]] | None = None

    @property
    def name(self) -> str:
        """The channel name."""
        return self._name

    @property
    def channel_id(self) -> int:
        """The MCS channel ID."""
        return self._channel_id

    def register_handler(self, handler: Callable[[bytes], Awaitable[None]]) -> None:
        """Register a handler for complete reassembled messages.

        The handler is an async callable that receives the full message bytes
        once all chunks have been reassembled.

        (Req 20, AC 4)

        Args:
            handler: Async callable that processes complete channel messages.
        """
        self._handler = handler

    async def send(self, mcs: McsLayer, data: bytes) -> None:
        """Segment outbound data into chunks and send via MCS.

        Messages larger than max_chunk_size are split into multiple chunks.
        Each chunk is prefixed with a channel PDU header containing:
        - total_length (4 bytes LE): the total uncompressed length of the message
        - flags (4 bytes LE): CHANNEL_FLAG_FIRST on the first chunk,
          CHANNEL_FLAG_LAST on the last chunk, both on single-chunk messages.

        (Req 20, AC 2)

        Args:
            mcs: The MCS layer used to send data on the channel.
            data: The complete message to send.
        """
        total_length = len(data)
        offset = 0

        while offset < total_length:
            chunk_end = min(offset + self._max_chunk_size, total_length)
            chunk = data[offset:chunk_end]

            flags = ChannelChunkFlags(0)
            if offset == 0:
                flags |= ChannelChunkFlags.FLAG_FIRST
            if chunk_end == total_length:
                flags |= ChannelChunkFlags.FLAG_LAST

            # Channel PDU header: totalLength (u32 LE) + flags (u32 LE)
            header = struct.pack("<II", total_length, int(flags))
            await mcs.send_to_channel(self._channel_id, header + chunk)

            offset = chunk_end

    async def on_data_received(self, chunk: bytes, flags: int) -> None:
        """Reassemble inbound chunks into complete messages.

        Buffers chunks until CHANNEL_FLAG_LAST is received, then dispatches
        the complete reassembled message to the registered handler.

        (Req 20, AC 3)

        Args:
            chunk: The chunk payload (without the channel PDU header).
            flags: The channel chunk flags from the PDU header.
        """
        chunk_flags = ChannelChunkFlags(flags)

        if chunk_flags & ChannelChunkFlags.FLAG_FIRST:
            # Start of a new message — reset the buffer
            self._reassembly_buffer = bytearray()

        self._reassembly_buffer.extend(chunk)

        if chunk_flags & ChannelChunkFlags.FLAG_LAST:
            # Message is complete — dispatch to handler
            complete_message = bytes(self._reassembly_buffer)
            self._reassembly_buffer = bytearray()

            if self._handler is not None:
                await self._handler(complete_message)
