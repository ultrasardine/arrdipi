"""Tests for the MCS layer — T.125 domain management and channel multiplexing.

Tests BER/PER encoding helpers, Connect Initial/Response, Erect Domain,
Attach User, Channel Join success/failure, and Send Data mux/demux routing.
"""

from __future__ import annotations

import struct
from unittest.mock import AsyncMock, MagicMock

import pytest

from arrdipi.errors import ChannelJoinError
from arrdipi.mcs.gcc import (
    ClientCoreData,
    ClientSecurityData,
    ServerCoreData,
    ServerNetworkData,
    ServerSecurityData,
    encode_gcc_conference_create_request,
    ClientNetworkData,
    decode_gcc_conference_create_response,
)
from arrdipi.mcs.layer import (
    MCS_USER_CHANNEL_BASE,
    McsLayer,
    _build_attach_user_request,
    _build_channel_join_request,
    _build_connect_initial,
    _build_erect_domain_request,
    _build_send_data_request,
    _parse_attach_user_confirm,
    _parse_channel_join_confirm,
    _parse_connect_response,
    _parse_send_data_indication,
    ber_decode_length,
    ber_encode_application_tag,
    ber_encode_boolean,
    ber_encode_integer,
    ber_encode_length,
    ber_encode_octet_string,
)


# ---------------------------------------------------------------------------
# BER encoding tests
# ---------------------------------------------------------------------------


class TestBerEncodeLength:
    """Test BER length encoding/decoding."""

    def test_short_form(self):
        """Length < 0x80 uses single byte."""
        assert ber_encode_length(0) == b"\x00"
        assert ber_encode_length(5) == b"\x05"
        assert ber_encode_length(127) == b"\x7f"

    def test_medium_form(self):
        """Length 0x80–0xFF uses 0x81 + 1 byte."""
        assert ber_encode_length(128) == b"\x81\x80"
        assert ber_encode_length(255) == b"\x81\xff"

    def test_long_form(self):
        """Length >= 0x100 uses 0x82 + 2 bytes."""
        assert ber_encode_length(256) == b"\x82\x01\x00"
        assert ber_encode_length(1000) == b"\x82\x03\xe8"

    def test_decode_short_form(self):
        """Decode single-byte length."""
        length, offset = ber_decode_length(b"\x05\x00", 0)
        assert length == 5
        assert offset == 1

    def test_decode_medium_form(self):
        """Decode 0x81 + 1 byte length."""
        length, offset = ber_decode_length(b"\x81\x80", 0)
        assert length == 128
        assert offset == 2

    def test_decode_long_form(self):
        """Decode 0x82 + 2 byte length."""
        length, offset = ber_decode_length(b"\x82\x01\x00", 0)
        assert length == 256
        assert offset == 3

    def test_roundtrip(self):
        """Encode then decode produces the original value."""
        for value in [0, 1, 50, 127, 128, 200, 255, 256, 1000, 65535]:
            encoded = ber_encode_length(value)
            decoded, _ = ber_decode_length(encoded, 0)
            assert decoded == value, f"Roundtrip failed for {value}"


class TestBerEncodeInteger:
    """Test BER integer encoding."""

    def test_small_value(self):
        """Values < 0x80 use 1 byte."""
        result = ber_encode_integer(0)
        assert result == b"\x02\x01\x00"

    def test_one_byte(self):
        """Values < 0x80 use 1 byte."""
        result = ber_encode_integer(1)
        assert result == b"\x02\x01\x01"

    def test_two_bytes(self):
        """Values 0x80–0x7FFF use 2 bytes."""
        result = ber_encode_integer(256)
        assert result == b"\x02\x02\x01\x00"

    def test_four_bytes(self):
        """Large values use 4 bytes."""
        result = ber_encode_integer(65535)
        assert result == b"\x02\x03\x00\xff\xff"


class TestBerEncodeOctetString:
    """Test BER octet string encoding."""

    def test_empty(self):
        """Empty octet string."""
        result = ber_encode_octet_string(b"")
        assert result == b"\x04\x00"

    def test_short(self):
        """Short octet string."""
        result = ber_encode_octet_string(b"\x01")
        assert result == b"\x04\x01\x01"

    def test_longer(self):
        """Longer octet string with correct length."""
        data = b"\x01\x02\x03\x04\x05"
        result = ber_encode_octet_string(data)
        assert result == b"\x04\x05\x01\x02\x03\x04\x05"


class TestBerEncodeApplicationTag:
    """Test BER application tag encoding."""

    def test_small_tag(self):
        """Tag < 31 uses single byte."""
        content = b"\x01\x02\x03"
        result = ber_encode_application_tag(5, content)
        # 0x60 | 5 = 0x65, length=3
        assert result[0] == 0x65
        assert result[1] == 3
        assert result[2:] == content

    def test_large_tag(self):
        """Tag >= 31 uses two-byte form (0x7F + tag)."""
        content = b"\x01\x02"
        result = ber_encode_application_tag(101, content)
        # 0x7F, 101, length=2
        assert result[0] == 0x7F
        assert result[1] == 101
        # Then BER length
        length, offset = ber_decode_length(result, 2)
        assert length == 2
        assert result[offset:] == content


# ---------------------------------------------------------------------------
# MCS PDU construction/parsing tests
# ---------------------------------------------------------------------------


class TestConnectInitial:
    """Test MCS Connect Initial PDU construction."""

    def test_structure(self):
        """Connect Initial has correct application tag 101."""
        gcc_data = b"\x00" * 10
        pdu = _build_connect_initial(gcc_data)
        # Should start with application tag 101: 0x7F, 0x65
        assert pdu[0] == 0x7F
        assert pdu[1] == 101  # 0x65

    def test_contains_gcc_data(self):
        """Connect Initial contains the GCC user data."""
        gcc_data = b"\xDE\xAD\xBE\xEF"
        pdu = _build_connect_initial(gcc_data)
        # The GCC data should appear as an octet string within the PDU
        assert b"\xDE\xAD\xBE\xEF" in pdu


class TestConnectResponse:
    """Test MCS Connect Response PDU parsing."""

    def _build_mock_connect_response(self, gcc_response: bytes) -> bytes:
        """Build a minimal valid Connect Response for testing."""
        from arrdipi.mcs.layer import (
            _ber_encode_domain_parameters,
            ber_encode_enumerated,
            ber_encode_integer,
            ber_encode_octet_string,
        )

        content = bytearray()
        # result: ENUMERATED 0 (rt-successful)
        content.extend(ber_encode_enumerated(0))
        # calledConnectId: INTEGER 0
        content.extend(ber_encode_integer(0))
        # domainParameters: SEQUENCE
        content.extend(_ber_encode_domain_parameters())
        # userData: OCTET STRING
        content.extend(ber_encode_octet_string(gcc_response))

        # Wrap in application tag 102
        return ber_encode_application_tag(102, bytes(content))

    def test_parse_success(self):
        """Parse a valid Connect Response extracts user data."""
        gcc_data = b"\x01\x02\x03\x04\x05"
        response = self._build_mock_connect_response(gcc_data)
        result = _parse_connect_response(response)
        assert result == gcc_data

    def test_parse_failure_result(self):
        """Parse a Connect Response with non-zero result raises ValueError."""
        from arrdipi.mcs.layer import (
            _ber_encode_domain_parameters,
            ber_encode_enumerated,
            ber_encode_integer,
            ber_encode_octet_string,
        )

        content = bytearray()
        content.extend(ber_encode_enumerated(1))  # failure
        content.extend(ber_encode_integer(0))
        content.extend(_ber_encode_domain_parameters())
        content.extend(ber_encode_octet_string(b""))
        response = ber_encode_application_tag(102, bytes(content))

        with pytest.raises(ValueError, match="result=1"):
            _parse_connect_response(response)


class TestErectDomainRequest:
    """Test Erect Domain Request PDU construction."""

    def test_structure(self):
        """Erect Domain Request has type byte 0x04 and two u16 zeros."""
        pdu = _build_erect_domain_request()
        assert pdu == b"\x04\x00\x00\x00\x00"


class TestAttachUserRequest:
    """Test Attach User Request PDU construction."""

    def test_structure(self):
        """Attach User Request is just type byte 0x28."""
        pdu = _build_attach_user_request()
        assert pdu == b"\x28"


class TestAttachUserConfirm:
    """Test Attach User Confirm PDU parsing."""

    def test_parse_success(self):
        """Parse a successful Attach User Confirm returns user channel ID."""
        # Type byte: 0x2E (base 0x2C | result 0x00 in bits 1:0 = success)
        # Actually: 0x2E = 0x2C | 0x02? Let's check the encoding.
        # The PER encoding: type_byte = 0x2C | (result << 0)
        # For result=0: type_byte & 0x03 == 0, and type_byte & 0xFC == 0x2C
        # So type_byte = 0x2C for success
        # User channel ID: 5 (encoded as 5, actual = 5 + 1001 = 1006)
        data = b"\x2c" + struct.pack(">H", 5)  # user_id = 5 -> channel 1006
        result = _parse_attach_user_confirm(data)
        assert result == 1006

    def test_parse_failure(self):
        """Parse a failed Attach User Confirm raises ValueError."""
        # result = 1 (failure): type_byte = 0x2C | 0x01 = 0x2D
        data = b"\x2d" + struct.pack(">H", 5)
        with pytest.raises(ValueError, match="result=1"):
            _parse_attach_user_confirm(data)


class TestChannelJoinRequest:
    """Test Channel Join Request PDU construction."""

    def test_structure(self):
        """Channel Join Request has correct type byte and encoded IDs."""
        pdu = _build_channel_join_request(1007, 1003)
        assert pdu[0] == 0x38
        # user channel ID: 1007 - 1001 = 6
        assert struct.unpack_from(">H", pdu, 1)[0] == 6
        # channel ID: 1003
        assert struct.unpack_from(">H", pdu, 3)[0] == 1003


class TestChannelJoinConfirm:
    """Test Channel Join Confirm PDU parsing."""

    def test_parse_success(self):
        """Parse a successful Channel Join Confirm returns channel ID."""
        # type_byte = 0x3E with result=0: 0x3C | 0x00 = 0x3C? 
        # Actually: base is 0x3C, result in bits 1:0
        # For result=0: type_byte & 0x03 == 0
        # So type_byte = 0x3E & 0xFC = 0x3C... let's use 0x3C for result=0
        # Wait, the spec says type byte is 0x3E. Let me re-check.
        # The PER type byte for Channel Join Confirm is 0x3E
        # But result is encoded in the low 2 bits.
        # So for success: type_byte = 0x3E & 0xFC | 0 = 0x3C
        data = (
            b"\x3c"  # type with result=0
            + struct.pack(">H", 6)  # user channel ID (1007 - 1001 = 6)
            + struct.pack(">H", 1003)  # requested channel ID
            + struct.pack(">H", 1003)  # actual channel ID
        )
        result, channel_id = _parse_channel_join_confirm(data)
        assert result == 0
        assert channel_id == 1003

    def test_parse_failure(self):
        """Parse a failed Channel Join Confirm returns non-zero result."""
        # result = 2 (failure): type_byte = 0x3C | 0x02 = 0x3E
        data = (
            b"\x3e"  # type with result=2
            + struct.pack(">H", 6)  # user channel ID
            + struct.pack(">H", 1003)  # requested channel ID
            + struct.pack(">H", 1003)  # channel ID
        )
        result, channel_id = _parse_channel_join_confirm(data)
        assert result == 2


class TestSendDataRequest:
    """Test Send Data Request PDU construction."""

    def test_structure(self):
        """Send Data Request has correct type byte and contains payload."""
        payload = b"\xAA\xBB\xCC"
        pdu = _build_send_data_request(1007, 1003, payload)
        assert pdu[0] == 0x64
        # user channel ID: 1007 - 1001 = 6
        assert struct.unpack_from(">H", pdu, 1)[0] == 6
        # channel ID: 1003
        assert struct.unpack_from(">H", pdu, 3)[0] == 1003
        # payload should be at the end
        assert pdu.endswith(payload)


class TestSendDataIndication:
    """Test Send Data Indication PDU parsing."""

    def test_parse(self):
        """Parse a Send Data Indication extracts channel ID and payload."""
        payload = b"\x01\x02\x03\x04"
        # Build: type=0x68, user_id=6 (1007-1001), channel_id=1003,
        # priority=0x70, length=4, payload
        from arrdipi.mcs.layer import _per_encode_length, _per_encode_u16

        data = (
            b"\x68"
            + _per_encode_u16(6)  # user channel ID
            + _per_encode_u16(1003)  # channel ID
            + b"\x70"  # priority + segmentation
            + _per_encode_length(len(payload))
            + payload
        )
        channel_id, result_payload = _parse_send_data_indication(data)
        assert channel_id == 1003
        assert result_payload == payload

    def test_wrong_type_byte(self):
        """Parse with wrong type byte raises ValueError."""
        data = b"\x64\x00\x06\x03\xEB\x70\x04\x01\x02\x03\x04"
        with pytest.raises(ValueError, match="unexpected type byte"):
            _parse_send_data_indication(data)


# ---------------------------------------------------------------------------
# McsLayer integration tests (with mock X224Layer)
# ---------------------------------------------------------------------------


def _make_mock_x224() -> MagicMock:
    """Create a mock X224Layer with async send_pdu and recv_pdu."""
    mock = MagicMock()
    mock.send_pdu = AsyncMock()
    mock.recv_pdu = AsyncMock()
    return mock


def _build_gcc_response_bytes() -> bytes:
    """Build a minimal valid GCC Conference Create Response for testing."""
    from arrdipi.mcs.gcc import (
        SC_CORE,
        SC_NET,
        SC_SECURITY,
        ServerCoreData,
        ServerNetworkData,
        ServerSecurityData,
    )
    from arrdipi.pdu.base import ByteWriter

    # Build server data blocks
    core_data = ServerCoreData(version=0x00080004).serialize()
    security_data = ServerSecurityData(encryption_method=0, encryption_level=0).serialize()
    network_data = ServerNetworkData(mcs_channel_id=1003, channel_ids=[1004, 1005]).serialize()

    # Write data blocks with headers
    w = ByteWriter()
    # SC_CORE
    w.write_u16_le(SC_CORE)
    w.write_u16_le(len(core_data) + 4)
    w.write_bytes(core_data)
    # SC_SECURITY
    w.write_u16_le(SC_SECURITY)
    w.write_u16_le(len(security_data) + 4)
    w.write_bytes(security_data)
    # SC_NET
    w.write_u16_le(SC_NET)
    w.write_u16_le(len(network_data) + 4)
    w.write_bytes(network_data)

    user_data = w.to_bytes()

    # Wrap in GCC Conference Create Response structure
    # OID + ConnectPDU length + fixed fields + "McDn" + user data length + user data
    gcc_response = bytearray()
    # T.124 OID
    gcc_response.extend(b"\x00\x05\x00\x14\x7c\x00\x01")
    # ConnectPDU length (PER) — we'll compute it
    inner = bytearray()
    # Fixed response fields (Conference Create Response PER encoding)
    inner.extend(b"\x14\x76\x0a\x01\x01\x00\x01\xc0\x00")
    # H.221 key "McDn"
    inner.extend(b"\x4d\x63\x44\x6e")
    # User data length (PER)
    if len(user_data) > 0x7F:
        inner.append(0x80 | ((len(user_data) >> 8) & 0x7F))
        inner.append(len(user_data) & 0xFF)
    else:
        inner.append(len(user_data))
    inner.extend(user_data)

    # ConnectPDU length
    connect_pdu_len = len(inner)
    if connect_pdu_len > 0x7F:
        gcc_response.append(0x80 | ((connect_pdu_len >> 8) & 0x7F))
        gcc_response.append(connect_pdu_len & 0xFF)
    else:
        gcc_response.append(connect_pdu_len)
    gcc_response.extend(inner)

    return bytes(gcc_response)


def _build_mock_connect_response_pdu() -> bytes:
    """Build a complete MCS Connect Response PDU wrapping GCC response."""
    from arrdipi.mcs.layer import (
        _ber_encode_domain_parameters,
        ber_encode_enumerated,
        ber_encode_integer,
        ber_encode_octet_string,
    )

    gcc_response = _build_gcc_response_bytes()

    content = bytearray()
    content.extend(ber_encode_enumerated(0))  # result: rt-successful
    content.extend(ber_encode_integer(0))  # calledConnectId
    content.extend(_ber_encode_domain_parameters())  # domainParameters
    content.extend(ber_encode_octet_string(gcc_response))  # userData

    return ber_encode_application_tag(102, bytes(content))


@pytest.mark.asyncio
async def test_connect_initial_sends_pdu():
    """connect_initial sends an MCS Connect Initial PDU via X.224."""
    mock_x224 = _make_mock_x224()

    # Set up recv_pdu to return a valid Connect Response
    mock_x224.recv_pdu.return_value = _build_mock_connect_response_pdu()

    mcs = McsLayer(mock_x224)
    core = ClientCoreData(client_name="test")
    security = ClientSecurityData()

    server_core, server_security, server_network = await mcs.connect_initial(
        core, security, ["cliprdr", "rdpsnd"]
    )

    # Verify send_pdu was called with data starting with application tag 101
    mock_x224.send_pdu.assert_called_once()
    sent_data = mock_x224.send_pdu.call_args[0][0]
    assert sent_data[0] == 0x7F
    assert sent_data[1] == 101

    # Verify server data was parsed
    assert server_core.version == 0x00080004
    assert server_network.mcs_channel_id == 1003
    assert server_network.channel_ids == [1004, 1005]

    # Verify channel map was populated
    assert mcs.io_channel_id == 1003
    assert mcs.channel_map[1004] == "cliprdr"
    assert mcs.channel_map[1005] == "rdpsnd"


@pytest.mark.asyncio
async def test_erect_domain_and_attach_user():
    """erect_domain_and_attach_user sends correct PDUs and returns user channel ID."""
    mock_x224 = _make_mock_x224()

    # Attach User Confirm: result=0, user_id=6 (channel 1007)
    mock_x224.recv_pdu.return_value = b"\x2c" + struct.pack(">H", 6)

    mcs = McsLayer(mock_x224)
    user_channel_id = await mcs.erect_domain_and_attach_user()

    assert user_channel_id == 1007
    assert mcs.user_channel_id == 1007

    # Verify two PDUs were sent: Erect Domain + Attach User
    assert mock_x224.send_pdu.call_count == 2
    first_call = mock_x224.send_pdu.call_args_list[0][0][0]
    second_call = mock_x224.send_pdu.call_args_list[1][0][0]
    assert first_call[0] == 0x04  # Erect Domain Request
    assert second_call == b"\x28"  # Attach User Request


@pytest.mark.asyncio
async def test_join_channels_success():
    """join_channels succeeds when all confirms have result=0."""
    mock_x224 = _make_mock_x224()

    # All Channel Join Confirms succeed (result=0)
    def make_confirm(channel_id: int) -> bytes:
        return (
            b"\x3c"  # type with result=0
            + struct.pack(">H", 6)  # user channel ID
            + struct.pack(">H", channel_id)  # requested
            + struct.pack(">H", channel_id)  # actual
        )

    mock_x224.recv_pdu.side_effect = [
        make_confirm(1007),  # user channel
        make_confirm(1003),  # I/O channel
        make_confirm(1004),  # cliprdr
    ]

    mcs = McsLayer(mock_x224)
    mcs._user_channel_id = 1007
    mcs._io_channel_id = 1003
    mcs._channel_map = {1004: "cliprdr"}

    await mcs.join_channels([1007, 1003, 1004])

    # Verify 3 join requests were sent
    assert mock_x224.send_pdu.call_count == 3


@pytest.mark.asyncio
async def test_join_channels_failure():
    """join_channels raises ChannelJoinError when a confirm has non-zero result."""
    mock_x224 = _make_mock_x224()

    # First join succeeds, second fails
    mock_x224.recv_pdu.side_effect = [
        # Success for user channel
        b"\x3c" + struct.pack(">H", 6) + struct.pack(">H", 1007) + struct.pack(">H", 1007),
        # Failure for I/O channel (result=2)
        b"\x3e" + struct.pack(">H", 6) + struct.pack(">H", 1003) + struct.pack(">H", 1003),
    ]

    mcs = McsLayer(mock_x224)
    mcs._user_channel_id = 1007
    mcs._io_channel_id = 1003

    with pytest.raises(ChannelJoinError) as exc_info:
        await mcs.join_channels([1007, 1003])

    assert exc_info.value.channel_id == 1003
    assert "I/O" in exc_info.value.channel_name


@pytest.mark.asyncio
async def test_send_to_channel():
    """send_to_channel sends a Send Data Request PDU."""
    mock_x224 = _make_mock_x224()

    mcs = McsLayer(mock_x224)
    mcs._user_channel_id = 1007

    payload = b"\x01\x02\x03\x04"
    await mcs.send_to_channel(1003, payload)

    mock_x224.send_pdu.assert_called_once()
    sent_data = mock_x224.send_pdu.call_args[0][0]
    assert sent_data[0] == 0x64  # Send Data Request type byte
    assert sent_data.endswith(payload)


@pytest.mark.asyncio
async def test_recv_pdu_demux():
    """recv_pdu demultiplexes and returns (channel_id, payload)."""
    mock_x224 = _make_mock_x224()

    from arrdipi.mcs.layer import _per_encode_length, _per_encode_u16

    payload = b"\xAA\xBB\xCC\xDD"
    indication = (
        b"\x68"
        + _per_encode_u16(6)  # user channel ID (1007 - 1001)
        + _per_encode_u16(1003)  # channel ID
        + b"\x70"  # priority + segmentation
        + _per_encode_length(len(payload))
        + payload
    )
    mock_x224.recv_pdu.return_value = indication

    mcs = McsLayer(mock_x224)
    mcs._user_channel_id = 1007

    channel_id, result_payload = await mcs.recv_pdu()
    assert channel_id == 1003
    assert result_payload == payload


@pytest.mark.asyncio
async def test_recv_pdu_routes_to_handler():
    """recv_pdu invokes registered handler for the channel."""
    mock_x224 = _make_mock_x224()

    from arrdipi.mcs.layer import _per_encode_length, _per_encode_u16

    payload = b"\x01\x02\x03"
    indication = (
        b"\x68"
        + _per_encode_u16(6)
        + _per_encode_u16(1004)
        + b"\x70"
        + _per_encode_length(len(payload))
        + payload
    )
    mock_x224.recv_pdu.return_value = indication

    mcs = McsLayer(mock_x224)
    mcs._user_channel_id = 1007

    received_data: list[bytes] = []
    mcs.register_channel_handler(1004, lambda data: received_data.append(data))

    channel_id, result_payload = await mcs.recv_pdu()
    assert channel_id == 1004
    assert result_payload == payload
    assert received_data == [payload]


@pytest.mark.asyncio
async def test_recv_pdu_no_handler():
    """recv_pdu works without a registered handler."""
    mock_x224 = _make_mock_x224()

    from arrdipi.mcs.layer import _per_encode_length, _per_encode_u16

    payload = b"\xFF"
    indication = (
        b"\x68"
        + _per_encode_u16(6)
        + _per_encode_u16(1005)
        + b"\x70"
        + _per_encode_length(len(payload))
        + payload
    )
    mock_x224.recv_pdu.return_value = indication

    mcs = McsLayer(mock_x224)
    mcs._user_channel_id = 1007

    channel_id, result_payload = await mcs.recv_pdu()
    assert channel_id == 1005
    assert result_payload == payload
