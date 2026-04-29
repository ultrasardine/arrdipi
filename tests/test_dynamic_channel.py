"""Tests for dynamic virtual channel (DRDYNVC) handler.

Tests cover:
- PDU parse/serialize round-trip for all DRDYNVC PDU types
- Create/data/close lifecycle
- Fragmentation reassembly (Data First + Data)
- Unknown channel handling
- Channel factory registration
"""

import pytest

from arrdipi.channels.dynamic import (
    DYNVC_CMD_CLOSE,
    DYNVC_CMD_CREATE,
    DYNVC_CMD_DATA,
    DYNVC_CMD_DATA_FIRST,
    DrdynvcHandler,
    DynamicChannel,
    DynvcClose,
    DynvcCreateRequest,
    DynvcCreateResponse,
    DynvcData,
    DynvcDataFirst,
)
from arrdipi.errors import PduParseError


# --- PDU Round-Trip Tests ---


class TestDynvcCreateRequest:
    """Test DynvcCreateRequest parse/serialize."""

    def test_round_trip_small_channel_id(self) -> None:
        """Round-trip with a 1-byte channel ID."""
        pdu = DynvcCreateRequest(channel_id=5, channel_name="AUDIO_INPUT")
        data = pdu.serialize()
        parsed = DynvcCreateRequest.parse(data)
        assert parsed.channel_id == 5
        assert parsed.channel_name == "AUDIO_INPUT"

    def test_round_trip_medium_channel_id(self) -> None:
        """Round-trip with a 2-byte channel ID."""
        pdu = DynvcCreateRequest(channel_id=300, channel_name="TestChannel")
        data = pdu.serialize()
        parsed = DynvcCreateRequest.parse(data)
        assert parsed.channel_id == 300
        assert parsed.channel_name == "TestChannel"

    def test_round_trip_large_channel_id(self) -> None:
        """Round-trip with a 4-byte channel ID."""
        pdu = DynvcCreateRequest(channel_id=70000, channel_name="GFX")
        data = pdu.serialize()
        parsed = DynvcCreateRequest.parse(data)
        assert parsed.channel_id == 70000
        assert parsed.channel_name == "GFX"

    def test_serialize_format(self) -> None:
        """Verify the wire format of a Create Request."""
        pdu = DynvcCreateRequest(channel_id=3, channel_name="test")
        data = pdu.serialize()
        # Header: cmd=0x01 << 4 | cbId=0 = 0x10
        assert data[0] == 0x10
        # Channel ID: 1 byte = 3
        assert data[1] == 3
        # Name: "test\x00"
        assert data[2:] == b"test\x00"

    def test_parse_invalid_cmd(self) -> None:
        """Parsing with wrong command raises PduParseError."""
        # Build a Data PDU header (cmd=0x03) but try to parse as Create
        bad_data = bytes([0x30, 0x01])
        with pytest.raises(PduParseError, match="expected cmd 0x01"):
            DynvcCreateRequest.parse(bad_data)


class TestDynvcCreateResponse:
    """Test DynvcCreateResponse parse/serialize."""

    def test_round_trip_success(self) -> None:
        """Round-trip with success status."""
        pdu = DynvcCreateResponse(channel_id=10, creation_status=0)
        data = pdu.serialize()
        parsed = DynvcCreateResponse.parse(data)
        assert parsed.channel_id == 10
        assert parsed.creation_status == 0

    def test_round_trip_failure(self) -> None:
        """Round-trip with failure status."""
        pdu = DynvcCreateResponse(channel_id=42, creation_status=0xC0000001)
        data = pdu.serialize()
        parsed = DynvcCreateResponse.parse(data)
        assert parsed.channel_id == 42
        assert parsed.creation_status == 0xC0000001

    def test_round_trip_large_channel_id(self) -> None:
        """Round-trip with a 4-byte channel ID."""
        pdu = DynvcCreateResponse(channel_id=100000, creation_status=0)
        data = pdu.serialize()
        parsed = DynvcCreateResponse.parse(data)
        assert parsed.channel_id == 100000
        assert parsed.creation_status == 0


class TestDynvcDataFirst:
    """Test DynvcDataFirst parse/serialize."""

    def test_round_trip_small(self) -> None:
        """Round-trip with small total length and channel ID."""
        pdu = DynvcDataFirst(channel_id=1, total_length=100, data=b"hello")
        data = pdu.serialize()
        parsed = DynvcDataFirst.parse(data)
        assert parsed.channel_id == 1
        assert parsed.total_length == 100
        assert parsed.data == b"hello"

    def test_round_trip_medium_length(self) -> None:
        """Round-trip with 2-byte total length."""
        pdu = DynvcDataFirst(channel_id=5, total_length=5000, data=b"X" * 50)
        data = pdu.serialize()
        parsed = DynvcDataFirst.parse(data)
        assert parsed.channel_id == 5
        assert parsed.total_length == 5000
        assert parsed.data == b"X" * 50

    def test_round_trip_large_length(self) -> None:
        """Round-trip with 4-byte total length."""
        pdu = DynvcDataFirst(channel_id=256, total_length=100000, data=b"A" * 10)
        data = pdu.serialize()
        parsed = DynvcDataFirst.parse(data)
        assert parsed.channel_id == 256
        assert parsed.total_length == 100000
        assert parsed.data == b"A" * 10

    def test_parse_invalid_cmd(self) -> None:
        """Parsing with wrong command raises PduParseError."""
        bad_data = bytes([0x30, 0x01])  # cmd=0x03 (Data), not Data First
        with pytest.raises(PduParseError, match="expected cmd 0x02"):
            DynvcDataFirst.parse(bad_data)


class TestDynvcData:
    """Test DynvcData parse/serialize."""

    def test_round_trip(self) -> None:
        """Round-trip with data payload."""
        pdu = DynvcData(channel_id=7, data=b"payload data here")
        data = pdu.serialize()
        parsed = DynvcData.parse(data)
        assert parsed.channel_id == 7
        assert parsed.data == b"payload data here"

    def test_round_trip_empty_data(self) -> None:
        """Round-trip with empty data payload."""
        pdu = DynvcData(channel_id=1, data=b"")
        data = pdu.serialize()
        parsed = DynvcData.parse(data)
        assert parsed.channel_id == 1
        assert parsed.data == b""

    def test_round_trip_large_channel_id(self) -> None:
        """Round-trip with 4-byte channel ID."""
        pdu = DynvcData(channel_id=80000, data=b"\x01\x02\x03")
        data = pdu.serialize()
        parsed = DynvcData.parse(data)
        assert parsed.channel_id == 80000
        assert parsed.data == b"\x01\x02\x03"

    def test_parse_invalid_cmd(self) -> None:
        """Parsing with wrong command raises PduParseError."""
        bad_data = bytes([0x10, 0x01])  # cmd=0x01 (Create), not Data
        with pytest.raises(PduParseError, match="expected cmd 0x03"):
            DynvcData.parse(bad_data)


class TestDynvcClose:
    """Test DynvcClose parse/serialize."""

    def test_round_trip(self) -> None:
        """Round-trip with channel ID."""
        pdu = DynvcClose(channel_id=15)
        data = pdu.serialize()
        parsed = DynvcClose.parse(data)
        assert parsed.channel_id == 15

    def test_round_trip_large_channel_id(self) -> None:
        """Round-trip with 4-byte channel ID."""
        pdu = DynvcClose(channel_id=65536)
        data = pdu.serialize()
        parsed = DynvcClose.parse(data)
        assert parsed.channel_id == 65536

    def test_serialize_format(self) -> None:
        """Verify the wire format of a Close PDU."""
        pdu = DynvcClose(channel_id=2)
        data = pdu.serialize()
        # Header: cmd=0x04 << 4 | cbId=0 = 0x40
        assert data[0] == 0x40
        # Channel ID: 1 byte = 2
        assert data[1] == 2
        assert len(data) == 2

    def test_parse_invalid_cmd(self) -> None:
        """Parsing with wrong command raises PduParseError."""
        bad_data = bytes([0x10, 0x01])  # cmd=0x01 (Create), not Close
        with pytest.raises(PduParseError, match="expected cmd 0x04"):
            DynvcClose.parse(bad_data)


# --- DrdynvcHandler Lifecycle Tests ---


class TestDrdynvcHandlerCreate:
    """Test channel creation lifecycle (Req 21, AC 2)."""

    @pytest.mark.asyncio
    async def test_create_known_channel(self) -> None:
        """Create Request for a registered channel name succeeds."""
        sent: list[bytes] = []

        async def send_fn(data: bytes) -> None:
            sent.append(data)

        handler = DrdynvcHandler(send_fn)
        received: list[bytes] = []

        async def channel_handler(data: bytes) -> None:
            received.append(data)

        handler.register_channel_factory("AUDIO_INPUT", lambda: channel_handler)

        # Simulate server sending Create Request
        create_req = DynvcCreateRequest(channel_id=1, channel_name="AUDIO_INPUT")
        await handler.handle_message(create_req.serialize())

        # Verify Create Response was sent with success
        assert len(sent) == 1
        response = DynvcCreateResponse.parse(sent[0])
        assert response.channel_id == 1
        assert response.creation_status == 0

        # Verify channel was registered
        assert 1 in handler.channels
        assert handler.channels[1].channel_name == "AUDIO_INPUT"

    @pytest.mark.asyncio
    async def test_create_unknown_channel(self) -> None:
        """Create Request for an unregistered channel name is rejected."""
        sent: list[bytes] = []

        async def send_fn(data: bytes) -> None:
            sent.append(data)

        handler = DrdynvcHandler(send_fn)

        # No factory registered for "UNKNOWN"
        create_req = DynvcCreateRequest(channel_id=5, channel_name="UNKNOWN")
        await handler.handle_message(create_req.serialize())

        # Verify Create Response was sent with failure
        assert len(sent) == 1
        response = DynvcCreateResponse.parse(sent[0])
        assert response.channel_id == 5
        assert response.creation_status == 0xC0000001

        # Verify channel was NOT registered
        assert 5 not in handler.channels


class TestDrdynvcHandlerData:
    """Test data routing (Req 21, AC 3)."""

    @pytest.mark.asyncio
    async def test_data_routed_to_handler(self) -> None:
        """Data PDU is routed to the correct channel handler."""
        sent: list[bytes] = []

        async def send_fn(data: bytes) -> None:
            sent.append(data)

        handler = DrdynvcHandler(send_fn)
        received: list[bytes] = []

        async def channel_handler(data: bytes) -> None:
            received.append(data)

        handler.register_channel_factory("TestCh", lambda: channel_handler)

        # Create the channel
        create_req = DynvcCreateRequest(channel_id=10, channel_name="TestCh")
        await handler.handle_message(create_req.serialize())

        # Send data
        data_pdu = DynvcData(channel_id=10, data=b"hello world")
        await handler.handle_message(data_pdu.serialize())

        assert len(received) == 1
        assert received[0] == b"hello world"

    @pytest.mark.asyncio
    async def test_data_to_unknown_channel_ignored(self) -> None:
        """Data PDU for an unknown channel ID is silently ignored."""
        sent: list[bytes] = []

        async def send_fn(data: bytes) -> None:
            sent.append(data)

        handler = DrdynvcHandler(send_fn)

        # Send data to non-existent channel — should not raise
        data_pdu = DynvcData(channel_id=99, data=b"orphan data")
        await handler.handle_message(data_pdu.serialize())

    @pytest.mark.asyncio
    async def test_multiple_channels_routed_correctly(self) -> None:
        """Data is routed to the correct handler when multiple channels exist."""
        sent: list[bytes] = []

        async def send_fn(data: bytes) -> None:
            sent.append(data)

        handler = DrdynvcHandler(send_fn)
        received_a: list[bytes] = []
        received_b: list[bytes] = []

        async def handler_a(data: bytes) -> None:
            received_a.append(data)

        async def handler_b(data: bytes) -> None:
            received_b.append(data)

        handler.register_channel_factory("ChannelA", lambda: handler_a)
        handler.register_channel_factory("ChannelB", lambda: handler_b)

        # Create both channels
        await handler.handle_message(
            DynvcCreateRequest(channel_id=1, channel_name="ChannelA").serialize()
        )
        await handler.handle_message(
            DynvcCreateRequest(channel_id=2, channel_name="ChannelB").serialize()
        )

        # Send data to each
        await handler.handle_message(DynvcData(channel_id=1, data=b"for A").serialize())
        await handler.handle_message(DynvcData(channel_id=2, data=b"for B").serialize())

        assert received_a == [b"for A"]
        assert received_b == [b"for B"]


class TestDrdynvcHandlerClose:
    """Test channel close (Req 21, AC 4)."""

    @pytest.mark.asyncio
    async def test_close_removes_channel(self) -> None:
        """Close PDU removes the channel from the handler."""
        sent: list[bytes] = []

        async def send_fn(data: bytes) -> None:
            sent.append(data)

        handler = DrdynvcHandler(send_fn)

        async def channel_handler(data: bytes) -> None:
            pass

        handler.register_channel_factory("TestCh", lambda: channel_handler)

        # Create then close
        await handler.handle_message(
            DynvcCreateRequest(channel_id=7, channel_name="TestCh").serialize()
        )
        assert 7 in handler.channels

        await handler.handle_message(DynvcClose(channel_id=7).serialize())
        assert 7 not in handler.channels

    @pytest.mark.asyncio
    async def test_close_unknown_channel_no_error(self) -> None:
        """Closing a non-existent channel does not raise."""
        sent: list[bytes] = []

        async def send_fn(data: bytes) -> None:
            sent.append(data)

        handler = DrdynvcHandler(send_fn)

        # Should not raise
        await handler.handle_message(DynvcClose(channel_id=999).serialize())

    @pytest.mark.asyncio
    async def test_data_after_close_ignored(self) -> None:
        """Data sent to a closed channel is silently ignored."""
        sent: list[bytes] = []

        async def send_fn(data: bytes) -> None:
            sent.append(data)

        handler = DrdynvcHandler(send_fn)
        received: list[bytes] = []

        async def channel_handler(data: bytes) -> None:
            received.append(data)

        handler.register_channel_factory("TestCh", lambda: channel_handler)

        # Create, close, then send data
        await handler.handle_message(
            DynvcCreateRequest(channel_id=3, channel_name="TestCh").serialize()
        )
        await handler.handle_message(DynvcClose(channel_id=3).serialize())
        await handler.handle_message(DynvcData(channel_id=3, data=b"late").serialize())

        assert received == []


class TestDrdynvcFragmentation:
    """Test Data First + Data fragmentation reassembly (Req 21, AC 5)."""

    @pytest.mark.asyncio
    async def test_two_fragment_reassembly(self) -> None:
        """Data First + Data reassembles into a complete message."""
        sent: list[bytes] = []

        async def send_fn(data: bytes) -> None:
            sent.append(data)

        handler = DrdynvcHandler(send_fn)
        received: list[bytes] = []

        async def channel_handler(data: bytes) -> None:
            received.append(data)

        handler.register_channel_factory("Frag", lambda: channel_handler)

        await handler.handle_message(
            DynvcCreateRequest(channel_id=1, channel_name="Frag").serialize()
        )

        # Total message is 10 bytes, sent in 2 fragments
        full_message = b"0123456789"
        data_first = DynvcDataFirst(
            channel_id=1, total_length=10, data=full_message[:5]
        )
        data_cont = DynvcData(channel_id=1, data=full_message[5:])

        await handler.handle_message(data_first.serialize())
        assert len(received) == 0  # Not yet complete

        await handler.handle_message(data_cont.serialize())
        assert len(received) == 1
        assert received[0] == full_message

    @pytest.mark.asyncio
    async def test_three_fragment_reassembly(self) -> None:
        """Data First + 2 Data PDUs reassemble correctly."""
        sent: list[bytes] = []

        async def send_fn(data: bytes) -> None:
            sent.append(data)

        handler = DrdynvcHandler(send_fn)
        received: list[bytes] = []

        async def channel_handler(data: bytes) -> None:
            received.append(data)

        handler.register_channel_factory("Frag", lambda: channel_handler)

        await handler.handle_message(
            DynvcCreateRequest(channel_id=2, channel_name="Frag").serialize()
        )

        full_message = b"ABCDEFGHIJKLMNOP"  # 16 bytes
        await handler.handle_message(
            DynvcDataFirst(channel_id=2, total_length=16, data=full_message[:5]).serialize()
        )
        assert len(received) == 0

        await handler.handle_message(
            DynvcData(channel_id=2, data=full_message[5:10]).serialize()
        )
        assert len(received) == 0

        await handler.handle_message(
            DynvcData(channel_id=2, data=full_message[10:]).serialize()
        )
        assert len(received) == 1
        assert received[0] == full_message

    @pytest.mark.asyncio
    async def test_data_first_complete_in_one(self) -> None:
        """Data First with all data in the first fragment dispatches immediately."""
        sent: list[bytes] = []

        async def send_fn(data: bytes) -> None:
            sent.append(data)

        handler = DrdynvcHandler(send_fn)
        received: list[bytes] = []

        async def channel_handler(data: bytes) -> None:
            received.append(data)

        handler.register_channel_factory("Frag", lambda: channel_handler)

        await handler.handle_message(
            DynvcCreateRequest(channel_id=1, channel_name="Frag").serialize()
        )

        # Total length equals the data in Data First
        full_message = b"complete"
        await handler.handle_message(
            DynvcDataFirst(
                channel_id=1, total_length=len(full_message), data=full_message
            ).serialize()
        )

        assert len(received) == 1
        assert received[0] == full_message

    @pytest.mark.asyncio
    async def test_fragmentation_to_unknown_channel_ignored(self) -> None:
        """Data First to an unknown channel is silently ignored."""
        sent: list[bytes] = []

        async def send_fn(data: bytes) -> None:
            sent.append(data)

        handler = DrdynvcHandler(send_fn)

        # Should not raise
        await handler.handle_message(
            DynvcDataFirst(channel_id=99, total_length=100, data=b"frag").serialize()
        )

    @pytest.mark.asyncio
    async def test_non_fragmented_data_dispatches_immediately(self) -> None:
        """A Data PDU without prior Data First dispatches as a complete message."""
        sent: list[bytes] = []

        async def send_fn(data: bytes) -> None:
            sent.append(data)

        handler = DrdynvcHandler(send_fn)
        received: list[bytes] = []

        async def channel_handler(data: bytes) -> None:
            received.append(data)

        handler.register_channel_factory("Direct", lambda: channel_handler)

        await handler.handle_message(
            DynvcCreateRequest(channel_id=1, channel_name="Direct").serialize()
        )

        await handler.handle_message(
            DynvcData(channel_id=1, data=b"immediate").serialize()
        )

        assert len(received) == 1
        assert received[0] == b"immediate"


class TestDrdynvcHandlerEdgeCases:
    """Test edge cases and robustness."""

    @pytest.mark.asyncio
    async def test_empty_message_ignored(self) -> None:
        """An empty message does not raise."""
        sent: list[bytes] = []

        async def send_fn(data: bytes) -> None:
            sent.append(data)

        handler = DrdynvcHandler(send_fn)
        await handler.handle_message(b"")

    @pytest.mark.asyncio
    async def test_full_lifecycle(self) -> None:
        """Full lifecycle: create → data → close."""
        sent: list[bytes] = []

        async def send_fn(data: bytes) -> None:
            sent.append(data)

        handler = DrdynvcHandler(send_fn)
        received: list[bytes] = []

        async def channel_handler(data: bytes) -> None:
            received.append(data)

        handler.register_channel_factory("lifecycle", lambda: channel_handler)

        # Create
        await handler.handle_message(
            DynvcCreateRequest(channel_id=42, channel_name="lifecycle").serialize()
        )
        assert 42 in handler.channels

        # Send multiple data messages
        await handler.handle_message(
            DynvcData(channel_id=42, data=b"msg1").serialize()
        )
        await handler.handle_message(
            DynvcData(channel_id=42, data=b"msg2").serialize()
        )
        assert received == [b"msg1", b"msg2"]

        # Close
        await handler.handle_message(DynvcClose(channel_id=42).serialize())
        assert 42 not in handler.channels

    @pytest.mark.asyncio
    async def test_register_multiple_factories(self) -> None:
        """Multiple factories can be registered for different channel names."""
        sent: list[bytes] = []

        async def send_fn(data: bytes) -> None:
            sent.append(data)

        handler = DrdynvcHandler(send_fn)

        async def handler_a(data: bytes) -> None:
            pass

        async def handler_b(data: bytes) -> None:
            pass

        handler.register_channel_factory("A", lambda: handler_a)
        handler.register_channel_factory("B", lambda: handler_b)

        await handler.handle_message(
            DynvcCreateRequest(channel_id=1, channel_name="A").serialize()
        )
        await handler.handle_message(
            DynvcCreateRequest(channel_id=2, channel_name="B").serialize()
        )

        assert handler.channels[1].channel_name == "A"
        assert handler.channels[2].channel_name == "B"
