"""T.125 MCS layer: domain management and channel multiplexing.

Implements the Multipoint Communication Service protocol for RDP,
handling Connect Initial/Response, domain management (Erect Domain,
Attach User), channel joining, and data multiplexing/demultiplexing
per [MS-RDPBCGR] 2.2.1.3–2.2.1.9 and ITU-T T.125.

Requirements addressed: Req 2 (AC 1–6)
"""

from __future__ import annotations

import struct
from collections.abc import Callable

from arrdipi.errors import ChannelJoinError
from arrdipi.mcs.gcc import (
    ClientCoreData,
    ClientNetworkData,
    ClientSecurityData,
    ServerCoreData,
    ServerNetworkData,
    ServerSecurityData,
    decode_gcc_conference_create_response,
    encode_gcc_conference_create_request,
)
from arrdipi.transport.x224 import X224Layer


# ---------------------------------------------------------------------------
# BER (Basic Encoding Rules) encoding/decoding helpers
# ---------------------------------------------------------------------------


def ber_encode_length(length: int) -> bytes:
    """Encode a length value using BER definite-form length encoding.

    - If length < 0x80: single byte
    - If length < 0x100: 0x81 + 1 byte
    - If length < 0x10000: 0x82 + 2 bytes (big-endian)
    """
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    else:
        return bytes([0x82]) + struct.pack(">H", length)


def ber_decode_length(data: bytes, offset: int) -> tuple[int, int]:
    """Decode a BER length value from data at the given offset.

    Returns:
        Tuple of (decoded_length, new_offset).
    """
    if offset >= len(data):
        msg = "BER length: unexpected end of data"
        raise ValueError(msg)

    first = data[offset]
    offset += 1

    if first < 0x80:
        return first, offset
    elif first == 0x81:
        if offset >= len(data):
            msg = "BER length: unexpected end of data"
            raise ValueError(msg)
        return data[offset], offset + 1
    elif first == 0x82:
        if offset + 1 >= len(data):
            msg = "BER length: unexpected end of data"
            raise ValueError(msg)
        length = struct.unpack_from(">H", data, offset)[0]
        return length, offset + 2
    else:
        msg = f"BER length: unsupported long form 0x{first:02X}"
        raise ValueError(msg)


def ber_encode_integer(value: int) -> bytes:
    """Encode an integer using BER (tag 0x02).

    Uses the minimum number of bytes needed to represent the value.
    """
    tag = b"\x02"
    if value < 0x80:
        return tag + b"\x01" + bytes([value])
    elif value < 0x8000:
        return tag + b"\x02" + struct.pack(">H", value)
    elif value < 0x800000:
        return tag + b"\x03" + struct.pack(">I", value)[1:]
    else:
        return tag + b"\x04" + struct.pack(">I", value)


def ber_encode_octet_string(data: bytes) -> bytes:
    """Encode an octet string using BER (tag 0x04)."""
    return b"\x04" + ber_encode_length(len(data)) + data


def ber_encode_boolean(value: bool) -> bytes:
    """Encode a boolean using BER (tag 0x01)."""
    return b"\x01\x01" + (b"\xff" if value else b"\x00")


def ber_encode_enumerated(value: int) -> bytes:
    """Encode an enumerated value using BER (tag 0x0a)."""
    return b"\x0a\x01" + bytes([value])


def ber_encode_application_tag(tag_number: int, content: bytes) -> bytes:
    """Encode content with a BER application-constructed tag.

    For tag numbers >= 31, uses the two-byte form (0x7F + tag_number).
    For tag numbers < 31, uses single-byte form (0x60 | tag_number).
    """
    if tag_number >= 31:
        # Two-byte application tag: class=application(01), constructed(1), 11111
        # followed by the tag number
        tag_bytes = bytes([0x7F, tag_number])
    else:
        # Single-byte: 0x60 | tag_number (application + constructed)
        tag_bytes = bytes([0x60 | tag_number])
    return tag_bytes + ber_encode_length(len(content)) + content


def _ber_encode_domain_parameters(
    max_channel_ids: int = 34,
    max_user_ids: int = 2,
    max_token_ids: int = 0,
    num_priorities: int = 1,
    min_throughput: int = 0,
    max_height: int = 1,
    max_mcs_pdu_size: int = 65535,
    protocol_version: int = 2,
) -> bytes:
    """Encode a DomainParameters SEQUENCE (BER tag 0x30)."""
    content = (
        ber_encode_integer(max_channel_ids)
        + ber_encode_integer(max_user_ids)
        + ber_encode_integer(max_token_ids)
        + ber_encode_integer(num_priorities)
        + ber_encode_integer(min_throughput)
        + ber_encode_integer(max_height)
        + ber_encode_integer(max_mcs_pdu_size)
        + ber_encode_integer(protocol_version)
    )
    return b"\x30" + ber_encode_length(len(content)) + content


# ---------------------------------------------------------------------------
# BER decoding helpers for Connect Response parsing
# ---------------------------------------------------------------------------


def _ber_read_tag(data: bytes, offset: int) -> tuple[int, int]:
    """Read a BER tag and return (tag_value, new_offset).

    Handles both single-byte and two-byte (0x7F + number) application tags.
    """
    if offset >= len(data):
        msg = "BER: unexpected end of data reading tag"
        raise ValueError(msg)

    first = data[offset]
    offset += 1

    if first == 0x7F:
        if offset >= len(data):
            msg = "BER: unexpected end of data reading extended tag"
            raise ValueError(msg)
        return (0x7F << 8) | data[offset], offset + 1

    return first, offset


def _ber_read_integer(data: bytes, offset: int) -> tuple[int, int]:
    """Read a BER INTEGER (tag 0x02) and return (value, new_offset)."""
    if offset >= len(data) or data[offset] != 0x02:
        msg = f"BER: expected INTEGER tag 0x02 at offset {offset}"
        raise ValueError(msg)
    offset += 1
    length, offset = ber_decode_length(data, offset)
    value = int.from_bytes(data[offset : offset + length], "big")
    offset += length
    return value, offset


def _ber_read_enumerated(data: bytes, offset: int) -> tuple[int, int]:
    """Read a BER ENUMERATED (tag 0x0a) and return (value, new_offset)."""
    if offset >= len(data) or data[offset] != 0x0A:
        msg = f"BER: expected ENUMERATED tag 0x0A at offset {offset}"
        raise ValueError(msg)
    offset += 1
    length, offset = ber_decode_length(data, offset)
    value = int.from_bytes(data[offset : offset + length], "big")
    offset += length
    return value, offset


def _ber_read_octet_string(data: bytes, offset: int) -> tuple[bytes, int]:
    """Read a BER OCTET STRING (tag 0x04) and return (value, new_offset)."""
    if offset >= len(data) or data[offset] != 0x04:
        msg = f"BER: expected OCTET STRING tag 0x04 at offset {offset}"
        raise ValueError(msg)
    offset += 1
    length, offset = ber_decode_length(data, offset)
    value = data[offset : offset + length]
    offset += length
    return value, offset


def _ber_skip_domain_parameters(data: bytes, offset: int) -> int:
    """Skip a DomainParameters SEQUENCE (tag 0x30)."""
    if offset >= len(data) or data[offset] != 0x30:
        msg = f"BER: expected SEQUENCE tag 0x30 at offset {offset}"
        raise ValueError(msg)
    offset += 1
    length, offset = ber_decode_length(data, offset)
    return offset + length


# ---------------------------------------------------------------------------
# PER (Packed Encoding Rules) helpers for MCS PDU types
# ---------------------------------------------------------------------------


def _per_encode_u16(value: int) -> bytes:
    """Encode a 16-bit value in PER (big-endian)."""
    return struct.pack(">H", value)


def _per_decode_u16(data: bytes, offset: int) -> tuple[int, int]:
    """Decode a 16-bit PER value from data at offset."""
    if offset + 2 > len(data):
        msg = "PER: not enough data for u16"
        raise ValueError(msg)
    value = struct.unpack_from(">H", data, offset)[0]
    return value, offset + 2


def _per_encode_length(length: int) -> bytes:
    """Encode a PER length determinant.

    - If length < 0x80: single byte
    - Otherwise: two bytes with high bit set on first byte
    """
    if length < 0x80:
        return bytes([length])
    else:
        return bytes([0x80 | ((length >> 8) & 0x7F), length & 0xFF])


def _per_decode_length(data: bytes, offset: int) -> tuple[int, int]:
    """Decode a PER length determinant."""
    if offset >= len(data):
        msg = "PER: unexpected end of data reading length"
        raise ValueError(msg)
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    if offset >= len(data):
        msg = "PER: unexpected end of data reading length"
        raise ValueError(msg)
    second = data[offset]
    offset += 1
    return ((first & 0x7F) << 8) | second, offset


# ---------------------------------------------------------------------------
# MCS PDU construction and parsing
# ---------------------------------------------------------------------------

# MCS channel ID base for user channels
MCS_USER_CHANNEL_BASE = 1001


def _build_connect_initial(gcc_user_data: bytes) -> bytes:
    """Build an MCS Connect Initial PDU (BER application tag 101).

    Structure:
    - callingDomainSelector: OCTET STRING (0x01)
    - calledDomainSelector: OCTET STRING (0x01)
    - upwardFlag: BOOLEAN (TRUE)
    - targetParameters: DomainParameters
    - minimumParameters: DomainParameters
    - maximumParameters: DomainParameters
    - userData: OCTET STRING (GCC Conference Create Request)
    """
    content = bytearray()

    # callingDomainSelector: OCTET STRING with value 0x01
    content.extend(ber_encode_octet_string(b"\x01"))
    # calledDomainSelector: OCTET STRING with value 0x01
    content.extend(ber_encode_octet_string(b"\x01"))
    # upwardFlag: BOOLEAN TRUE
    content.extend(ber_encode_boolean(True))

    # targetParameters
    content.extend(
        _ber_encode_domain_parameters(
            max_channel_ids=34,
            max_user_ids=2,
            max_token_ids=0,
            num_priorities=1,
            min_throughput=0,
            max_height=1,
            max_mcs_pdu_size=65535,
            protocol_version=2,
        )
    )

    # minimumParameters
    content.extend(
        _ber_encode_domain_parameters(
            max_channel_ids=1,
            max_user_ids=1,
            max_token_ids=1,
            num_priorities=1,
            min_throughput=0,
            max_height=1,
            max_mcs_pdu_size=1056,
            protocol_version=2,
        )
    )

    # maximumParameters
    content.extend(
        _ber_encode_domain_parameters(
            max_channel_ids=65535,
            max_user_ids=64535,
            max_token_ids=65535,
            num_priorities=1,
            min_throughput=0,
            max_height=1,
            max_mcs_pdu_size=65535,
            protocol_version=2,
        )
    )

    # userData: OCTET STRING containing GCC Conference Create Request
    content.extend(ber_encode_octet_string(gcc_user_data))

    # Wrap in application tag 101 (Connect Initial)
    return ber_encode_application_tag(101, bytes(content))


def _parse_connect_response(data: bytes) -> bytes:
    """Parse an MCS Connect Response PDU (BER application tag 102).

    Returns the userData (GCC Conference Create Response) bytes.

    Raises:
        ValueError: If the PDU is malformed or the result is not successful.
    """
    offset = 0

    # Read application tag — should be 0x7F66 (application tag 102)
    tag, offset = _ber_read_tag(data, offset)
    expected_tag = (0x7F << 8) | 102
    if tag != expected_tag:
        msg = f"MCS Connect Response: expected application tag 102, got 0x{tag:04X}"
        raise ValueError(msg)

    # Read overall length
    _total_length, offset = ber_decode_length(data, offset)

    # result: ENUMERATED (should be 0 = rt-successful)
    result, offset = _ber_read_enumerated(data, offset)
    if result != 0:
        msg = f"MCS Connect Response: result={result} (expected 0=rt-successful)"
        raise ValueError(msg)

    # calledConnectId: INTEGER
    _called_connect_id, offset = _ber_read_integer(data, offset)

    # domainParameters: SEQUENCE
    offset = _ber_skip_domain_parameters(data, offset)

    # userData: OCTET STRING (GCC Conference Create Response)
    user_data, _offset = _ber_read_octet_string(data, offset)

    return user_data


def _build_erect_domain_request() -> bytes:
    """Build an MCS Erect Domain Request PDU (PER).

    Type byte: 0x04
    subHeight: u16 = 0
    subInterval: u16 = 0
    """
    return b"\x04" + _per_encode_u16(0) + _per_encode_u16(0)


def _build_attach_user_request() -> bytes:
    """Build an MCS Attach User Request PDU (PER).

    Type byte: 0x28
    """
    return b"\x28"


def _parse_attach_user_confirm(data: bytes) -> int:
    """Parse an MCS Attach User Confirm PDU (PER).

    Type byte: 0x2E (base 0x2C with result in low 2 bits)
    user channel ID: u16 (+ 1001 base) — only present if result == 0

    The PER encoding places the result enumeration in the low 2 bits
    of the type byte. For success (result=0), the user channel ID follows.

    Returns:
        The user channel ID.

    Raises:
        ValueError: If the result is not successful or data is malformed.
    """
    if len(data) < 1:
        msg = "MCS Attach User Confirm: data too short"
        raise ValueError(msg)

    offset = 0
    type_byte = data[offset]
    offset += 1

    # The type byte for Attach User Confirm has base 0x2C
    # with result in the low 2 bits
    if (type_byte & 0xFC) != 0x2C:
        msg = f"MCS Attach User Confirm: unexpected type byte 0x{type_byte:02X}"
        raise ValueError(msg)

    # Result is encoded in the 2 LSBs of the type byte for PER
    result = type_byte & 0x03
    if result != 0:
        msg = f"MCS Attach User Confirm: result={result} (expected 0=rt-successful)"
        raise ValueError(msg)

    # User channel ID (u16, value is channel_id - 1001)
    if offset + 2 > len(data):
        msg = "MCS Attach User Confirm: data too short for user channel ID"
        raise ValueError(msg)
    user_id_encoded, offset = _per_decode_u16(data, offset)
    return user_id_encoded + MCS_USER_CHANNEL_BASE


def _build_channel_join_request(user_channel_id: int, channel_id: int) -> bytes:
    """Build an MCS Channel Join Request PDU (PER).

    Type byte: 0x38
    user channel ID: u16 (- 1001 base)
    channel ID: u16
    """
    return (
        b"\x38"
        + _per_encode_u16(user_channel_id - MCS_USER_CHANNEL_BASE)
        + _per_encode_u16(channel_id)
    )


def _parse_channel_join_confirm(data: bytes) -> tuple[int, int]:
    """Parse an MCS Channel Join Confirm PDU (PER).

    Type byte: 0x3E (with result in low bits)
    result: ENUMERATED (in type byte low bits)
    user channel ID: u16 (+ 1001 base)
    requested channel ID: u16
    channel ID: u16

    Returns:
        Tuple of (result, channel_id).

    Raises:
        ValueError: If the data is too short.
    """
    if len(data) < 7:
        msg = "MCS Channel Join Confirm: data too short"
        raise ValueError(msg)

    offset = 0
    type_byte = data[offset]
    offset += 1

    # Result is in the 2 LSBs of the type byte
    # Type byte base for Channel Join Confirm is 0x3E
    # But with result bits: 0x3E | (result << 0) — actually result is in bits 1:0
    # The actual encoding: type_byte & 0xFC should be 0x3C
    result = type_byte & 0x03

    # user channel ID
    _user_id, offset = _per_decode_u16(data, offset)

    # requested channel ID
    _requested_channel_id, offset = _per_decode_u16(data, offset)

    # actual channel ID (only present if result == 0)
    if result == 0 and offset + 2 <= len(data):
        channel_id, offset = _per_decode_u16(data, offset)
    else:
        channel_id = _requested_channel_id

    return result, channel_id


def _build_send_data_request(
    user_channel_id: int, channel_id: int, data: bytes
) -> bytes:
    """Build an MCS Send Data Request PDU (PER).

    Type byte: 0x64
    user channel ID: u16 (- 1001 base)
    channel ID: u16
    priority: u8 (0x70 = high priority with segmentation)
    user data length: PER length
    user data
    """
    header = (
        b"\x64"
        + _per_encode_u16(user_channel_id - MCS_USER_CHANNEL_BASE)
        + _per_encode_u16(channel_id)
        + b"\x70"  # priority (high) + segmentation flags
        + _per_encode_length(len(data))
    )
    return header + data


def _parse_send_data_indication(data: bytes) -> tuple[int, bytes]:
    """Parse an MCS Send Data Indication PDU (PER).

    Type byte: 0x68
    user channel ID: u16 (+ 1001 base)
    channel ID: u16
    priority + segmentation: u8
    user data length: PER length
    user data

    Returns:
        Tuple of (channel_id, payload).
    """
    if len(data) < 6:
        msg = "MCS Send Data Indication: data too short"
        raise ValueError(msg)

    offset = 0
    type_byte = data[offset]
    offset += 1

    if type_byte != 0x68:
        msg = f"MCS Send Data Indication: unexpected type byte 0x{type_byte:02X}"
        raise ValueError(msg)

    # user channel ID (skip)
    _user_id, offset = _per_decode_u16(data, offset)

    # channel ID
    channel_id, offset = _per_decode_u16(data, offset)

    # priority + segmentation (skip)
    offset += 1

    # user data length
    payload_length, offset = _per_decode_length(data, offset)

    # user data
    payload = data[offset : offset + payload_length]

    return channel_id, payload


# ---------------------------------------------------------------------------
# McsLayer class
# ---------------------------------------------------------------------------


class McsLayer:
    """T.125 MCS layer: domain management and channel multiplexing.

    Handles the MCS Connect Initial/Response exchange, domain management
    (Erect Domain, Attach User), channel joining, and data
    multiplexing/demultiplexing.

    (Req 2, AC 1–6)
    """

    def __init__(self, x224: X224Layer) -> None:
        self._x224 = x224
        self._user_channel_id: int = 0
        self._io_channel_id: int = 0
        self._channel_map: dict[int, str] = {}  # channel_id -> channel_name
        self._channel_handlers: dict[int, Callable[[bytes], None]] = {}

    @property
    def user_channel_id(self) -> int:
        """The assigned user channel ID."""
        return self._user_channel_id

    @property
    def io_channel_id(self) -> int:
        """The I/O channel ID from the server."""
        return self._io_channel_id

    @property
    def channel_map(self) -> dict[int, str]:
        """Mapping of channel ID to channel name."""
        return self._channel_map

    async def connect_initial(
        self,
        client_core: ClientCoreData,
        client_security: ClientSecurityData,
        channel_names: list[str],
    ) -> tuple[ServerCoreData, ServerSecurityData, ServerNetworkData]:
        """Send MCS Connect Initial with GCC user data, receive Connect Response.

        Encodes client data blocks into a GCC Conference Create Request,
        wraps them in an MCS Connect Initial PDU, and sends via X.224.
        Receives the Connect Response and parses server data blocks.

        (Req 2, AC 1–2)

        Args:
            client_core: Client core data block.
            client_security: Client security data block.
            channel_names: List of static virtual channel names to request.

        Returns:
            Tuple of (ServerCoreData, ServerSecurityData, ServerNetworkData).
        """
        # Build client network data with channel names
        network = ClientNetworkData(
            channel_names=channel_names,
            channel_options=[0xC0000000] * len(channel_names),
        )

        # Encode GCC Conference Create Request
        gcc_data = encode_gcc_conference_create_request(
            client_core, client_security, network
        )

        # Build and send MCS Connect Initial
        connect_initial_pdu = _build_connect_initial(gcc_data)
        await self._x224.send_pdu(connect_initial_pdu)

        # Receive MCS Connect Response
        response_data = await self._x224.recv_pdu()

        # Parse Connect Response to get GCC user data
        gcc_response_data = _parse_connect_response(response_data)

        # Parse server data blocks from GCC response
        server_core, server_security, server_network = (
            decode_gcc_conference_create_response(gcc_response_data)
        )

        # Store I/O channel ID and build channel map
        self._io_channel_id = server_network.mcs_channel_id

        # Map channel IDs to names
        for i, channel_id in enumerate(server_network.channel_ids):
            if i < len(channel_names):
                self._channel_map[channel_id] = channel_names[i]

        return server_core, server_security, server_network

    async def erect_domain_and_attach_user(self) -> int:
        """Send Erect Domain Request + Attach User Request, receive Attach User Confirm.

        (Req 2, AC 3)

        Returns:
            The assigned user channel ID.
        """
        # Send Erect Domain Request
        await self._x224.send_pdu(_build_erect_domain_request())

        # Send Attach User Request
        await self._x224.send_pdu(_build_attach_user_request())

        # Receive Attach User Confirm
        confirm_data = await self._x224.recv_pdu()
        user_channel_id = _parse_attach_user_confirm(confirm_data)

        self._user_channel_id = user_channel_id
        return user_channel_id

    async def join_channels(self, channel_ids: list[int]) -> None:
        """Join the specified MCS channels.

        Sends Channel Join Request for each channel ID and waits for
        Channel Join Confirm. Raises ChannelJoinError on failure.

        (Req 2, AC 4–5)

        Args:
            channel_ids: List of channel IDs to join (user channel, I/O channel,
                        and all static virtual channels).

        Raises:
            ChannelJoinError: If any channel join is denied by the server.
        """
        for channel_id in channel_ids:
            # Send Channel Join Request
            join_request = _build_channel_join_request(
                self._user_channel_id, channel_id
            )
            await self._x224.send_pdu(join_request)

            # Receive Channel Join Confirm
            confirm_data = await self._x224.recv_pdu()
            result, confirmed_channel_id = _parse_channel_join_confirm(confirm_data)

            if result != 0:
                # Look up channel name
                channel_name = self._channel_map.get(channel_id, "unknown")
                if channel_id == self._user_channel_id:
                    channel_name = "user"
                elif channel_id == self._io_channel_id:
                    channel_name = "I/O"
                raise ChannelJoinError(
                    channel_name=channel_name, channel_id=channel_id
                )

    def register_channel_handler(
        self, channel_id: int, handler: Callable[[bytes], None]
    ) -> None:
        """Register a handler for inbound data on a specific channel.

        Args:
            channel_id: The MCS channel ID to handle.
            handler: Callable that receives the payload bytes.
        """
        self._channel_handlers[channel_id] = handler

    async def send_to_channel(self, channel_id: int, data: bytes) -> None:
        """Send data on a specific MCS channel.

        Wraps the data in an MCS Send Data Request PDU and sends via X.224.

        (Req 2, AC 6)

        Args:
            channel_id: The target channel ID.
            data: The payload to send.
        """
        pdu = _build_send_data_request(self._user_channel_id, channel_id, data)
        await self._x224.send_pdu(pdu)

    async def recv_pdu(self) -> tuple[int, bytes]:
        """Receive an MCS Send Data Indication and demultiplex.

        Reads from X.224, parses the MCS Send Data Indication header,
        and returns the channel ID and payload. If a handler is registered
        for the channel, it is invoked.

        (Req 2, AC 6)

        Returns:
            Tuple of (channel_id, payload).
        """
        data = await self._x224.recv_pdu()
        channel_id, payload = _parse_send_data_indication(data)

        # Route to registered handler if available
        handler = self._channel_handlers.get(channel_id)
        if handler is not None:
            handler(payload)

        return channel_id, payload
