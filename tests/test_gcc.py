"""Tests for arrdipi/mcs/gcc.py: GCC Conference encoding and data blocks."""

from __future__ import annotations

import struct

import pytest

from arrdipi.errors import PduParseError
from arrdipi.mcs.gcc import (
    CS_CORE,
    CS_NET,
    CS_SECURITY,
    SC_CORE,
    SC_NET,
    SC_SECURITY,
    ClientCoreData,
    ClientNetworkData,
    ClientSecurityData,
    ServerCoreData,
    ServerNetworkData,
    ServerSecurityData,
    _write_data_block,
    decode_gcc_conference_create_response,
    encode_gcc_conference_create_request,
)


# ---------------------------------------------------------------------------
# ClientCoreData tests
# ---------------------------------------------------------------------------


class TestClientCoreData:
    """Test ClientCoreData parse/serialize round-trip."""

    def test_round_trip_default(self) -> None:
        """Default ClientCoreData round-trips correctly."""
        original = ClientCoreData()
        serialized = original.serialize()
        parsed = ClientCoreData.parse(serialized)
        assert parsed == original

    def test_round_trip_custom_values(self) -> None:
        """ClientCoreData with custom values round-trips correctly."""
        original = ClientCoreData(
            version=0x00080004,
            desktop_width=1920,
            desktop_height=1080,
            color_depth=0xCA01,
            sas_sequence=0xAA03,
            keyboard_layout=0x00000407,  # German
            client_build=7601,
            client_name="TESTPC",
            keyboard_type=4,
            keyboard_sub_type=0,
            keyboard_function_key=12,
            ime_file_name="",
            post_beta2_color_depth=0xCA03,
            client_product_id=1,
            serial_number=0,
            high_color_depth=32,
            supported_color_depths=0x000F,
            early_capability_flags=0x0003,
            client_dig_product_id="",
            connection_type=6,
            pad1octet=0,
            server_selected_protocol=0x00000001,
        )
        serialized = original.serialize()
        parsed = ClientCoreData.parse(serialized)
        assert parsed == original

    def test_client_name_truncation(self) -> None:
        """Client name longer than 15 chars is truncated to fit 32 bytes UTF-16LE."""
        original = ClientCoreData(client_name="A" * 20)
        serialized = original.serialize()
        parsed = ClientCoreData.parse(serialized)
        # 30 bytes / 2 = 15 UTF-16LE chars max
        assert len(parsed.client_name) <= 15

    def test_parse_truncated_raises(self) -> None:
        """Parsing truncated data raises PduParseError."""
        with pytest.raises(PduParseError) as exc_info:
            ClientCoreData.parse(b"\x00\x01\x02")
        assert exc_info.value.pdu_type == "ClientCoreData"

    def test_serialize_produces_expected_size(self) -> None:
        """Serialized ClientCoreData has the expected minimum size."""
        core = ClientCoreData()
        data = core.serialize()
        # Minimum: 4+2+2+2+2+4+4+32+4+4+4+64 = 128 bytes (mandatory)
        # Plus optional fields: 2+2+4+2+2+2+64+1+1+4 = 84 bytes
        assert len(data) == 212


# ---------------------------------------------------------------------------
# ClientSecurityData tests
# ---------------------------------------------------------------------------


class TestClientSecurityData:
    """Test ClientSecurityData parse/serialize round-trip."""

    def test_round_trip(self) -> None:
        """ClientSecurityData round-trips correctly."""
        original = ClientSecurityData(
            encryption_methods=0x0000003B,
            ext_encryption_methods=0,
        )
        serialized = original.serialize()
        parsed = ClientSecurityData.parse(serialized)
        assert parsed == original

    def test_serialize_size(self) -> None:
        """Serialized ClientSecurityData is exactly 8 bytes."""
        sec = ClientSecurityData()
        assert len(sec.serialize()) == 8

    def test_parse_truncated_raises(self) -> None:
        """Parsing truncated data raises PduParseError."""
        with pytest.raises(PduParseError):
            ClientSecurityData.parse(b"\x00\x01\x02\x03")


# ---------------------------------------------------------------------------
# ClientNetworkData tests
# ---------------------------------------------------------------------------


class TestClientNetworkData:
    """Test ClientNetworkData parse/serialize round-trip."""

    def test_round_trip_empty(self) -> None:
        """Empty channel list round-trips correctly."""
        original = ClientNetworkData(channel_names=[], channel_options=[])
        serialized = original.serialize()
        parsed = ClientNetworkData.parse(serialized)
        assert parsed == original

    def test_round_trip_with_channels(self) -> None:
        """Channel list with multiple entries round-trips correctly (Req 20, AC 1)."""
        original = ClientNetworkData(
            channel_names=["cliprdr", "rdpsnd", "rdpdr", "drdynvc"],
            channel_options=[0x80000000, 0x80000000, 0x80800000, 0xC0000000],
        )
        serialized = original.serialize()
        parsed = ClientNetworkData.parse(serialized)
        assert parsed == original

    def test_channel_name_ascii_encoding(self) -> None:
        """Channel names are encoded as 8-byte null-padded ASCII."""
        net = ClientNetworkData(
            channel_names=["abc"],
            channel_options=[0x80000000],
        )
        data = net.serialize()
        # Skip 4-byte channel_count
        name_bytes = data[4:12]
        assert name_bytes == b"abc\x00\x00\x00\x00\x00"

    def test_parse_truncated_raises(self) -> None:
        """Parsing truncated data raises PduParseError."""
        # channel_count says 1 but no channel data follows
        data = struct.pack("<I", 1)
        with pytest.raises(PduParseError):
            ClientNetworkData.parse(data)


# ---------------------------------------------------------------------------
# ServerCoreData tests
# ---------------------------------------------------------------------------


class TestServerCoreData:
    """Test ServerCoreData parse/serialize round-trip."""

    def test_round_trip(self) -> None:
        """ServerCoreData round-trips correctly."""
        original = ServerCoreData(
            version=0x00080004,
            client_requested_protocols=0x00000003,
            early_capability_flags=0x00000006,
        )
        serialized = original.serialize()
        parsed = ServerCoreData.parse(serialized)
        assert parsed == original

    def test_parse_minimal(self) -> None:
        """ServerCoreData with only version field parses correctly."""
        data = struct.pack("<I", 0x00080004)
        parsed = ServerCoreData.parse(data)
        assert parsed.version == 0x00080004
        assert parsed.client_requested_protocols == 0
        assert parsed.early_capability_flags == 0

    def test_serialize_size(self) -> None:
        """Serialized ServerCoreData is 12 bytes (version + 2 optional u32)."""
        core = ServerCoreData()
        assert len(core.serialize()) == 12


# ---------------------------------------------------------------------------
# ServerSecurityData tests
# ---------------------------------------------------------------------------


class TestServerSecurityData:
    """Test ServerSecurityData parse/serialize round-trip."""

    def test_round_trip_no_crypto(self) -> None:
        """ServerSecurityData with no encryption round-trips correctly."""
        original = ServerSecurityData(
            encryption_method=0,
            encryption_level=0,
            server_random=b"",
            server_certificate=b"",
        )
        serialized = original.serialize()
        parsed = ServerSecurityData.parse(serialized)
        assert parsed == original

    def test_round_trip_with_random_and_cert(self) -> None:
        """ServerSecurityData with server random and certificate round-trips."""
        server_random = bytes(range(32))
        server_cert = b"\x01\x02\x03\x04\x05\x06\x07\x08" * 16
        original = ServerSecurityData(
            encryption_method=0x00000002,  # 128-bit
            encryption_level=2,  # CLIENT_COMPATIBLE
            server_random=server_random,
            server_certificate=server_cert,
        )
        serialized = original.serialize()
        parsed = ServerSecurityData.parse(serialized)
        assert parsed == original

    def test_parse_minimal(self) -> None:
        """ServerSecurityData with only method/level parses correctly."""
        data = struct.pack("<II", 0, 0)
        parsed = ServerSecurityData.parse(data)
        assert parsed.encryption_method == 0
        assert parsed.encryption_level == 0
        assert parsed.server_random == b""
        assert parsed.server_certificate == b""


# ---------------------------------------------------------------------------
# ServerNetworkData tests
# ---------------------------------------------------------------------------


class TestServerNetworkData:
    """Test ServerNetworkData parse/serialize round-trip."""

    def test_round_trip_even_channels(self) -> None:
        """ServerNetworkData with even channel count round-trips correctly."""
        original = ServerNetworkData(
            mcs_channel_id=0x03EB,
            channel_ids=[0x03EC, 0x03ED, 0x03EE, 0x03EF],
        )
        serialized = original.serialize()
        parsed = ServerNetworkData.parse(serialized)
        assert parsed == original

    def test_round_trip_odd_channels(self) -> None:
        """ServerNetworkData with odd channel count includes padding."""
        original = ServerNetworkData(
            mcs_channel_id=0x03EB,
            channel_ids=[0x03EC, 0x03ED, 0x03EE],
        )
        serialized = original.serialize()
        # Odd count: 2+2 + 3*2 + 2(pad) = 12 bytes
        assert len(serialized) == 12
        parsed = ServerNetworkData.parse(serialized)
        assert parsed == original

    def test_round_trip_no_channels(self) -> None:
        """ServerNetworkData with no channels round-trips correctly."""
        original = ServerNetworkData(mcs_channel_id=0x03EB, channel_ids=[])
        serialized = original.serialize()
        parsed = ServerNetworkData.parse(serialized)
        assert parsed == original

    def test_parse_truncated_raises(self) -> None:
        """Parsing truncated data raises PduParseError."""
        with pytest.raises(PduParseError):
            ServerNetworkData.parse(b"\x00")


# ---------------------------------------------------------------------------
# GCC Conference Create Request encoding tests
# ---------------------------------------------------------------------------


class TestGccConferenceCreateRequest:
    """Test GCC Conference Create Request encoding."""

    def test_encode_produces_valid_header(self) -> None:
        """Encoded request starts with T.124 object identifier."""
        core = ClientCoreData()
        security = ClientSecurityData()
        network = ClientNetworkData(channel_names=["cliprdr"], channel_options=[0x80000000])

        result = encode_gcc_conference_create_request(core, security, network)

        # Must start with T.124 OID
        assert result[:7] == b"\x00\x05\x00\x14\x7c\x00\x01"

    def test_encode_contains_duca_key(self) -> None:
        """Encoded request contains the 'Duca' H.221 key."""
        core = ClientCoreData()
        security = ClientSecurityData()
        network = ClientNetworkData()

        result = encode_gcc_conference_create_request(core, security, network)

        assert b"Duca" in result

    def test_encode_contains_client_data_blocks(self) -> None:
        """Encoded request contains CS_CORE and CS_SECURITY block headers."""
        core = ClientCoreData(desktop_width=1920, desktop_height=1080)
        security = ClientSecurityData()
        network = ClientNetworkData()

        result = encode_gcc_conference_create_request(core, security, network)

        # CS_CORE header (0xC001 LE)
        assert b"\x01\xc0" in result
        # CS_SECURITY header (0xC002 LE)
        assert b"\x02\xc0" in result

    def test_encode_includes_network_data_when_channels_present(self) -> None:
        """CS_NET block is included when channels are specified."""
        core = ClientCoreData()
        security = ClientSecurityData()
        network = ClientNetworkData(
            channel_names=["cliprdr", "rdpsnd"],
            channel_options=[0x80000000, 0x80000000],
        )

        result = encode_gcc_conference_create_request(core, security, network)

        # CS_NET header (0xC003 LE)
        assert b"\x03\xc0" in result

    def test_encode_excludes_network_data_when_no_channels(self) -> None:
        """CS_NET block is excluded when no channels are specified."""
        core = ClientCoreData()
        security = ClientSecurityData()
        network = ClientNetworkData(channel_names=[], channel_options=[])

        result = encode_gcc_conference_create_request(core, security, network)

        # CS_NET header (0xC003 LE) should NOT be present
        assert b"\x03\xc0" not in result


# ---------------------------------------------------------------------------
# GCC Conference Create Response decoding tests
# ---------------------------------------------------------------------------


class TestGccConferenceCreateResponse:
    """Test GCC Conference Create Response decoding."""

    def _build_response(
        self,
        core: ServerCoreData | None = None,
        security: ServerSecurityData | None = None,
        network: ServerNetworkData | None = None,
    ) -> bytes:
        """Build a synthetic GCC Conference Create Response for testing."""
        if core is None:
            core = ServerCoreData(version=0x00080004)
        if security is None:
            security = ServerSecurityData(encryption_method=0, encryption_level=0)
        if network is None:
            network = ServerNetworkData(mcs_channel_id=0x03EB, channel_ids=[0x03EC])

        # Build user data blocks
        user_data = bytearray()
        user_data.extend(_write_data_block(SC_CORE, core.serialize()))
        user_data.extend(_write_data_block(SC_SECURITY, security.serialize()))
        user_data.extend(_write_data_block(SC_NET, network.serialize()))
        user_data_bytes = bytes(user_data)

        # Build the GCC Conference Create Response wrapper
        response = bytearray()

        # T.124 OID
        response.extend(b"\x00\x05\x00\x14\x7c\x00\x01")

        # ConnectData::connectPDU length
        # We'll compute the inner length after building it
        inner = bytearray()

        # Conference Create Response fixed fields (PER-encoded)
        # These are the typical response fields before "McDn"
        inner.extend(b"\x14\x76\x0a\x01\x01\x00\x01\xc0\x00")

        # H.221 key "McDn"
        inner.extend(b"\x4d\x63\x44\x6e")

        # User data length (PER)
        ud_len = len(user_data_bytes)
        if ud_len > 0x7F:
            inner.append(0x80 | ((ud_len >> 8) & 0x7F))
            inner.append(ud_len & 0xFF)
        else:
            inner.append(ud_len & 0x7F)

        inner.extend(user_data_bytes)

        # Write ConnectData length
        inner_len = len(inner)
        if inner_len > 0x7F:
            response.append(0x80 | ((inner_len >> 8) & 0x7F))
            response.append(inner_len & 0xFF)
        else:
            response.append(inner_len & 0x7F)

        response.extend(inner)
        return bytes(response)

    def test_decode_basic_response(self) -> None:
        """Decode a basic GCC response with all three server data blocks."""
        core = ServerCoreData(version=0x00080004, client_requested_protocols=3)
        security = ServerSecurityData(encryption_method=0, encryption_level=0)
        network = ServerNetworkData(mcs_channel_id=0x03EB, channel_ids=[0x03EC, 0x03ED])

        response_data = self._build_response(core, security, network)
        parsed_core, parsed_security, parsed_network = decode_gcc_conference_create_response(
            response_data
        )

        assert parsed_core.version == 0x00080004
        assert parsed_core.client_requested_protocols == 3
        assert parsed_security.encryption_method == 0
        assert parsed_security.encryption_level == 0
        assert parsed_network.mcs_channel_id == 0x03EB
        assert parsed_network.channel_ids == [0x03EC, 0x03ED]

    def test_decode_with_server_random(self) -> None:
        """Decode response with server random and certificate."""
        server_random = bytes(range(32))
        server_cert = b"\xAB" * 64
        security = ServerSecurityData(
            encryption_method=2,
            encryption_level=2,
            server_random=server_random,
            server_certificate=server_cert,
        )

        response_data = self._build_response(security=security)
        _, parsed_security, _ = decode_gcc_conference_create_response(response_data)

        assert parsed_security.encryption_method == 2
        assert parsed_security.encryption_level == 2
        assert parsed_security.server_random == server_random
        assert parsed_security.server_certificate == server_cert

    def test_decode_invalid_oid_raises(self) -> None:
        """Decoding with invalid OID raises PduParseError."""
        bad_data = b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF" + b"\x00" * 50
        with pytest.raises(PduParseError) as exc_info:
            decode_gcc_conference_create_response(bad_data)
        assert "invalid T.124 object identifier" in exc_info.value.description

    def test_decode_too_short_raises(self) -> None:
        """Decoding data that's too short raises PduParseError."""
        with pytest.raises(PduParseError):
            decode_gcc_conference_create_response(b"\x00\x01\x02")

    def test_decode_missing_mcdn_raises(self) -> None:
        """Decoding without 'McDn' marker raises PduParseError."""
        # Valid OID but no McDn marker
        data = b"\x00\x05\x00\x14\x7c\x00\x01" + b"\x10" + b"\x00" * 16
        with pytest.raises(PduParseError) as exc_info:
            decode_gcc_conference_create_response(data)
        assert "McDn" in exc_info.value.description


# ---------------------------------------------------------------------------
# Data block header tests
# ---------------------------------------------------------------------------


class TestDataBlockHeader:
    """Test the _write_data_block helper."""

    def test_header_format(self) -> None:
        """Data block header has correct type and length."""
        payload = b"\x01\x02\x03"
        result = _write_data_block(0xC001, payload)
        # type (2) + length (2) + payload (3) = 7 bytes
        assert len(result) == 7
        # Type
        assert struct.unpack_from("<H", result, 0)[0] == 0xC001
        # Length includes header (4 + 3 = 7)
        assert struct.unpack_from("<H", result, 2)[0] == 7
        # Payload
        assert result[4:] == payload
