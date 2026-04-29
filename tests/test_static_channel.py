"""Tests for static virtual channel chunking and reassembly."""

import struct

import pytest

from arrdipi.channels.static import DEFAULT_MAX_CHUNK_SIZE, StaticVirtualChannel
from arrdipi.pdu.types import ChannelChunkFlags


class FakeMcsLayer:
    """Fake MCS layer that records sent data for assertions."""

    def __init__(self) -> None:
        self.sent: list[tuple[int, bytes]] = []

    async def send_to_channel(self, channel_id: int, data: bytes) -> None:
        self.sent.append((channel_id, data))


def parse_chunk_header(data: bytes) -> tuple[int, int, bytes]:
    """Parse a channel PDU chunk: (total_length, flags, payload)."""
    total_length, flags = struct.unpack_from("<II", data, 0)
    payload = data[8:]
    return total_length, flags, payload


class TestSendChunking:
    """Test outbound message chunking (Req 20, AC 2)."""

    @pytest.mark.asyncio
    async def test_single_chunk_small_message(self) -> None:
        """A message smaller than max_chunk_size is sent as a single chunk
        with both FLAG_FIRST and FLAG_LAST set."""
        channel = StaticVirtualChannel("cliprdr", 1004, max_chunk_size=1600)
        mcs = FakeMcsLayer()

        data = b"Hello, RDP!"
        await channel.send(mcs, data)

        assert len(mcs.sent) == 1
        channel_id, raw = mcs.sent[0]
        assert channel_id == 1004

        total_length, flags, payload = parse_chunk_header(raw)
        assert total_length == len(data)
        assert flags & int(ChannelChunkFlags.FLAG_FIRST)
        assert flags & int(ChannelChunkFlags.FLAG_LAST)
        assert payload == data

    @pytest.mark.asyncio
    async def test_exact_chunk_size_message(self) -> None:
        """A message exactly equal to max_chunk_size is sent as a single chunk."""
        max_size = 100
        channel = StaticVirtualChannel("rdpsnd", 1005, max_chunk_size=max_size)
        mcs = FakeMcsLayer()

        data = b"X" * max_size
        await channel.send(mcs, data)

        assert len(mcs.sent) == 1
        total_length, flags, payload = parse_chunk_header(mcs.sent[0][1])
        assert total_length == max_size
        assert flags & int(ChannelChunkFlags.FLAG_FIRST)
        assert flags & int(ChannelChunkFlags.FLAG_LAST)
        assert payload == data

    @pytest.mark.asyncio
    async def test_large_message_chunked(self) -> None:
        """A message larger than max_chunk_size is split into multiple chunks."""
        max_size = 100
        channel = StaticVirtualChannel("cliprdr", 1004, max_chunk_size=max_size)
        mcs = FakeMcsLayer()

        # 250 bytes → 3 chunks: 100 + 100 + 50
        data = bytes(range(256))[:250]
        await channel.send(mcs, data)

        assert len(mcs.sent) == 3

        # First chunk
        total_length, flags, payload = parse_chunk_header(mcs.sent[0][1])
        assert total_length == 250
        assert flags & int(ChannelChunkFlags.FLAG_FIRST)
        assert not (flags & int(ChannelChunkFlags.FLAG_LAST))
        assert payload == data[:100]

        # Middle chunk
        total_length, flags, payload = parse_chunk_header(mcs.sent[1][1])
        assert total_length == 250
        assert not (flags & int(ChannelChunkFlags.FLAG_FIRST))
        assert not (flags & int(ChannelChunkFlags.FLAG_LAST))
        assert payload == data[100:200]

        # Last chunk
        total_length, flags, payload = parse_chunk_header(mcs.sent[2][1])
        assert total_length == 250
        assert not (flags & int(ChannelChunkFlags.FLAG_FIRST))
        assert flags & int(ChannelChunkFlags.FLAG_LAST)
        assert payload == data[200:250]

    @pytest.mark.asyncio
    async def test_two_chunk_message(self) -> None:
        """A message that is slightly larger than max_chunk_size produces 2 chunks."""
        max_size = 100
        channel = StaticVirtualChannel("rdpdr", 1006, max_chunk_size=max_size)
        mcs = FakeMcsLayer()

        data = b"A" * 150
        await channel.send(mcs, data)

        assert len(mcs.sent) == 2

        # First chunk has FLAG_FIRST only
        _, flags1, payload1 = parse_chunk_header(mcs.sent[0][1])
        assert flags1 & int(ChannelChunkFlags.FLAG_FIRST)
        assert not (flags1 & int(ChannelChunkFlags.FLAG_LAST))
        assert payload1 == b"A" * 100

        # Last chunk has FLAG_LAST only
        _, flags2, payload2 = parse_chunk_header(mcs.sent[1][1])
        assert not (flags2 & int(ChannelChunkFlags.FLAG_FIRST))
        assert flags2 & int(ChannelChunkFlags.FLAG_LAST)
        assert payload2 == b"A" * 50

    @pytest.mark.asyncio
    async def test_all_chunks_carry_total_length(self) -> None:
        """Every chunk header carries the total message length."""
        max_size = 50
        channel = StaticVirtualChannel("test", 1007, max_chunk_size=max_size)
        mcs = FakeMcsLayer()

        data = b"B" * 200  # 4 chunks
        await channel.send(mcs, data)

        assert len(mcs.sent) == 4
        for _, raw in mcs.sent:
            total_length, _, _ = parse_chunk_header(raw)
            assert total_length == 200


class TestReassembly:
    """Test inbound chunk reassembly (Req 20, AC 3)."""

    @pytest.mark.asyncio
    async def test_single_chunk_passthrough(self) -> None:
        """A single-chunk message (FIRST|LAST) is dispatched immediately."""
        channel = StaticVirtualChannel("cliprdr", 1004)
        received: list[bytes] = []

        async def handler(data: bytes) -> None:
            received.append(data)

        channel.register_handler(handler)

        flags = int(ChannelChunkFlags.FLAG_FIRST | ChannelChunkFlags.FLAG_LAST)
        await channel.on_data_received(b"complete message", flags)

        assert len(received) == 1
        assert received[0] == b"complete message"

    @pytest.mark.asyncio
    async def test_multi_chunk_reassembly(self) -> None:
        """Multiple chunks are reassembled into a single complete message."""
        channel = StaticVirtualChannel("rdpsnd", 1005)
        received: list[bytes] = []

        async def handler(data: bytes) -> None:
            received.append(data)

        channel.register_handler(handler)

        # First chunk
        await channel.on_data_received(
            b"chunk1_", int(ChannelChunkFlags.FLAG_FIRST)
        )
        assert len(received) == 0  # Not dispatched yet

        # Middle chunk
        await channel.on_data_received(b"chunk2_", 0)
        assert len(received) == 0

        # Last chunk
        await channel.on_data_received(b"chunk3", int(ChannelChunkFlags.FLAG_LAST))
        assert len(received) == 1
        assert received[0] == b"chunk1_chunk2_chunk3"

    @pytest.mark.asyncio
    async def test_reassembly_resets_on_new_first(self) -> None:
        """Receiving FLAG_FIRST resets the buffer, discarding any partial data."""
        channel = StaticVirtualChannel("test", 1006)
        received: list[bytes] = []

        async def handler(data: bytes) -> None:
            received.append(data)

        channel.register_handler(handler)

        # Start a message but don't finish it
        await channel.on_data_received(
            b"abandoned_", int(ChannelChunkFlags.FLAG_FIRST)
        )

        # Start a new message (resets buffer)
        await channel.on_data_received(
            b"new_message", int(ChannelChunkFlags.FLAG_FIRST | ChannelChunkFlags.FLAG_LAST)
        )

        assert len(received) == 1
        assert received[0] == b"new_message"

    @pytest.mark.asyncio
    async def test_no_handler_no_error(self) -> None:
        """If no handler is registered, reassembled data is silently discarded."""
        channel = StaticVirtualChannel("unused", 1007)

        # Should not raise
        flags = int(ChannelChunkFlags.FLAG_FIRST | ChannelChunkFlags.FLAG_LAST)
        await channel.on_data_received(b"data", flags)

    @pytest.mark.asyncio
    async def test_multiple_messages_sequential(self) -> None:
        """Multiple complete messages are dispatched independently."""
        channel = StaticVirtualChannel("cliprdr", 1004)
        received: list[bytes] = []

        async def handler(data: bytes) -> None:
            received.append(data)

        channel.register_handler(handler)

        # First message (single chunk)
        flags_both = int(ChannelChunkFlags.FLAG_FIRST | ChannelChunkFlags.FLAG_LAST)
        await channel.on_data_received(b"msg1", flags_both)

        # Second message (two chunks)
        await channel.on_data_received(b"msg2_part1_", int(ChannelChunkFlags.FLAG_FIRST))
        await channel.on_data_received(b"msg2_part2", int(ChannelChunkFlags.FLAG_LAST))

        assert len(received) == 2
        assert received[0] == b"msg1"
        assert received[1] == b"msg2_part1_msg2_part2"


class TestRegisterHandler:
    """Test handler registration (Req 20, AC 4)."""

    def test_register_handler_stores_callable(self) -> None:
        """register_handler stores the handler for later dispatch."""
        channel = StaticVirtualChannel("test", 1004)

        async def my_handler(data: bytes) -> None:
            pass

        channel.register_handler(my_handler)
        assert channel._handler is my_handler

    @pytest.mark.asyncio
    async def test_handler_receives_complete_message(self) -> None:
        """The registered handler receives the fully reassembled message."""
        channel = StaticVirtualChannel("cliprdr", 1004, max_chunk_size=50)
        received: list[bytes] = []

        async def handler(data: bytes) -> None:
            received.append(data)

        channel.register_handler(handler)

        # Simulate receiving a chunked message
        original = b"X" * 120
        await channel.on_data_received(original[:50], int(ChannelChunkFlags.FLAG_FIRST))
        await channel.on_data_received(original[50:100], 0)
        await channel.on_data_received(original[100:], int(ChannelChunkFlags.FLAG_LAST))

        assert len(received) == 1
        assert received[0] == original


class TestChannelProperties:
    """Test channel property accessors."""

    def test_name_property(self) -> None:
        channel = StaticVirtualChannel("cliprdr", 1004)
        assert channel.name == "cliprdr"

    def test_channel_id_property(self) -> None:
        channel = StaticVirtualChannel("rdpsnd", 1005)
        assert channel.channel_id == 1005

    def test_default_max_chunk_size(self) -> None:
        channel = StaticVirtualChannel("test", 1004)
        assert channel._max_chunk_size == DEFAULT_MAX_CHUNK_SIZE
