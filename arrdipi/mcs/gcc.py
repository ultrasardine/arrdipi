"""GCC Conference Create Request/Response encoding and client/server data blocks.

Implements the T.124 GCC Conference structure wrapping client and server data
blocks for the MCS Basic Settings Exchange phase per [MS-RDPBCGR] 2.2.1.3–2.2.1.4.

Client data blocks:
- CS_CORE (0xC001): ClientCoreData
- CS_SECURITY (0xC002): ClientSecurityData
- CS_NET (0xC003): ClientNetworkData

Server data blocks:
- SC_CORE (0x0C01): ServerCoreData
- SC_SECURITY (0x0C02): ServerSecurityData
- SC_NET (0x0C03): ServerNetworkData
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Self

from arrdipi.errors import PduParseError
from arrdipi.pdu.base import ByteReader, ByteWriter, Pdu


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Client data block types
CS_CORE = 0xC001
CS_SECURITY = 0xC002
CS_NET = 0xC003

# Server data block types
SC_CORE = 0x0C01
SC_SECURITY = 0x0C02
SC_NET = 0x0C03

# GCC Conference Create Request fixed header prefix.
# This is the well-known PER-encoded T.124 GCC Conference Create Request
# header used by all RDP implementations. The user data length is appended
# after this prefix.
_GCC_CREATE_REQUEST_HEADER = bytes([
    # T.124 GCC ConnectData::connectPDU (ConnectGCCPDU)
    0x00, 0x05,  # object identifier key (T.124 0.0.20.124.0.1)
    0x00, 0x14,
    0x7C, 0x00,
    0x01,
    # ConnectData::connectPDU (PER choice for Conference Create Request)
    0x81, 0x2A,  # length placeholder (will be overwritten)
    # ConferenceCreateRequest::conferenceName
    0x08, 0x00, 0x10, 0x00, 0x01, 0xC0, 0x00,
    # ConferenceCreateRequest::userData key
    0x44, 0x75, 0x63, 0x61,  # "Duca" (T.124 OID for MS user data)
    0x81, 0x34,  # length placeholder (will be overwritten)
])

# GCC Conference Create Response fixed header prefix for parsing.
# Object identifier for T.124 (0.0.20.124.0.1) in the response.
_GCC_RESPONSE_OID = bytes([0x00, 0x05, 0x00, 0x14, 0x7C, 0x00, 0x01])


# ---------------------------------------------------------------------------
# Client Data Blocks
# ---------------------------------------------------------------------------


@dataclass
class ClientCoreData(Pdu):
    """Client Core Data block [MS-RDPBCGR] 2.2.1.3.2.

    Contains client system information sent during the Basic Settings Exchange.
    """

    version: int = 0x00080004  # RDP 5.0+
    desktop_width: int = 1024
    desktop_height: int = 768
    color_depth: int = 0xCA01  # 8bpp (RNS_UD_COLOR_8BPP)
    sas_sequence: int = 0xAA03  # RNS_UD_SAS_DEL
    keyboard_layout: int = 0x00000409  # US English
    client_build: int = 2600
    client_name: str = ""
    keyboard_type: int = 4  # IBM enhanced (101/102-key)
    keyboard_sub_type: int = 0
    keyboard_function_key: int = 12
    ime_file_name: str = ""
    # Optional fields
    post_beta2_color_depth: int = 0xCA01
    client_product_id: int = 1
    serial_number: int = 0
    high_color_depth: int = 24
    supported_color_depths: int = 0x000F  # 15/16/24/32
    early_capability_flags: int = 0x0001  # RNS_UD_CS_SUPPORT_ERRINFO_PDU
    client_dig_product_id: str = ""
    connection_type: int = 0
    pad1octet: int = 0
    server_selected_protocol: int = 0

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse ClientCoreData from binary data (without block header)."""
        reader = ByteReader(data, pdu_type="ClientCoreData")

        version = reader.read_u32_le()
        desktop_width = reader.read_u16_le()
        desktop_height = reader.read_u16_le()
        color_depth = reader.read_u16_le()
        sas_sequence = reader.read_u16_le()
        keyboard_layout = reader.read_u32_le()
        client_build = reader.read_u32_le()
        client_name_raw = reader.read_bytes(32)
        client_name = client_name_raw.decode("utf-16-le").rstrip("\x00")
        keyboard_type = reader.read_u32_le()
        keyboard_sub_type = reader.read_u32_le()
        keyboard_function_key = reader.read_u32_le()
        ime_file_name_raw = reader.read_bytes(64)
        ime_file_name = ime_file_name_raw.decode("utf-16-le").rstrip("\x00")

        # Optional fields - parse if data remains
        post_beta2_color_depth = 0xCA01
        client_product_id = 1
        serial_number = 0
        high_color_depth = 24
        supported_color_depths = 0x000F
        early_capability_flags = 0x0001
        client_dig_product_id = ""
        connection_type = 0
        pad1octet = 0
        server_selected_protocol = 0

        if reader.remaining() >= 2:
            post_beta2_color_depth = reader.read_u16_le()
        if reader.remaining() >= 2:
            client_product_id = reader.read_u16_le()
        if reader.remaining() >= 4:
            serial_number = reader.read_u32_le()
        if reader.remaining() >= 2:
            high_color_depth = reader.read_u16_le()
        if reader.remaining() >= 2:
            supported_color_depths = reader.read_u16_le()
        if reader.remaining() >= 2:
            early_capability_flags = reader.read_u16_le()
        if reader.remaining() >= 64:
            dig_raw = reader.read_bytes(64)
            client_dig_product_id = dig_raw.decode("utf-16-le").rstrip("\x00")
        if reader.remaining() >= 1:
            connection_type = reader.read_u8()
        if reader.remaining() >= 1:
            pad1octet = reader.read_u8()
        if reader.remaining() >= 4:
            server_selected_protocol = reader.read_u32_le()

        return cls(
            version=version,
            desktop_width=desktop_width,
            desktop_height=desktop_height,
            color_depth=color_depth,
            sas_sequence=sas_sequence,
            keyboard_layout=keyboard_layout,
            client_build=client_build,
            client_name=client_name,
            keyboard_type=keyboard_type,
            keyboard_sub_type=keyboard_sub_type,
            keyboard_function_key=keyboard_function_key,
            ime_file_name=ime_file_name,
            post_beta2_color_depth=post_beta2_color_depth,
            client_product_id=client_product_id,
            serial_number=serial_number,
            high_color_depth=high_color_depth,
            supported_color_depths=supported_color_depths,
            early_capability_flags=early_capability_flags,
            client_dig_product_id=client_dig_product_id,
            connection_type=connection_type,
            pad1octet=pad1octet,
            server_selected_protocol=server_selected_protocol,
        )

    def serialize(self) -> bytes:
        """Serialize ClientCoreData to binary (without block header)."""
        w = ByteWriter()
        w.write_u32_le(self.version)
        w.write_u16_le(self.desktop_width)
        w.write_u16_le(self.desktop_height)
        w.write_u16_le(self.color_depth)
        w.write_u16_le(self.sas_sequence)
        w.write_u32_le(self.keyboard_layout)
        w.write_u32_le(self.client_build)
        # client_name: 32 bytes UTF-16LE null-padded
        name_encoded = self.client_name.encode("utf-16-le")[:30]
        w.write_bytes(name_encoded.ljust(32, b"\x00"))
        w.write_u32_le(self.keyboard_type)
        w.write_u32_le(self.keyboard_sub_type)
        w.write_u32_le(self.keyboard_function_key)
        # ime_file_name: 64 bytes UTF-16LE null-padded
        ime_encoded = self.ime_file_name.encode("utf-16-le")[:62]
        w.write_bytes(ime_encoded.ljust(64, b"\x00"))
        # Optional fields
        w.write_u16_le(self.post_beta2_color_depth)
        w.write_u16_le(self.client_product_id)
        w.write_u32_le(self.serial_number)
        w.write_u16_le(self.high_color_depth)
        w.write_u16_le(self.supported_color_depths)
        w.write_u16_le(self.early_capability_flags)
        # client_dig_product_id: 64 bytes UTF-16LE null-padded
        dig_encoded = self.client_dig_product_id.encode("utf-16-le")[:62]
        w.write_bytes(dig_encoded.ljust(64, b"\x00"))
        w.write_u8(self.connection_type)
        w.write_u8(self.pad1octet)
        w.write_u32_le(self.server_selected_protocol)
        return w.to_bytes()


@dataclass
class ClientSecurityData(Pdu):
    """Client Security Data block [MS-RDPBCGR] 2.2.1.3.3.

    Contains client encryption method preferences.
    """

    encryption_methods: int = 0x0000003B  # 40-bit + 128-bit + 56-bit + FIPS
    ext_encryption_methods: int = 0

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse ClientSecurityData from binary data (without block header)."""
        reader = ByteReader(data, pdu_type="ClientSecurityData")
        encryption_methods = reader.read_u32_le()
        ext_encryption_methods = reader.read_u32_le()
        return cls(
            encryption_methods=encryption_methods,
            ext_encryption_methods=ext_encryption_methods,
        )

    def serialize(self) -> bytes:
        """Serialize ClientSecurityData to binary (without block header)."""
        w = ByteWriter()
        w.write_u32_le(self.encryption_methods)
        w.write_u32_le(self.ext_encryption_methods)
        return w.to_bytes()


@dataclass
class ClientNetworkData(Pdu):
    """Client Network Data block [MS-RDPBCGR] 2.2.1.3.4.

    Contains the list of requested static virtual channel names (Req 20, AC 1).
    Each channel has a name (up to 7 ASCII chars) and options flags.
    """

    channel_names: list[str] = field(default_factory=list)
    channel_options: list[int] = field(default_factory=list)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse ClientNetworkData from binary data (without block header)."""
        reader = ByteReader(data, pdu_type="ClientNetworkData")
        channel_count = reader.read_u32_le()
        channel_names: list[str] = []
        channel_options: list[int] = []
        for _ in range(channel_count):
            name_raw = reader.read_bytes(8)
            name = name_raw.split(b"\x00", 1)[0].decode("ascii")
            options = reader.read_u32_le()
            channel_names.append(name)
            channel_options.append(options)
        return cls(channel_names=channel_names, channel_options=channel_options)

    def serialize(self) -> bytes:
        """Serialize ClientNetworkData to binary (without block header)."""
        w = ByteWriter()
        w.write_u32_le(len(self.channel_names))
        for i, name in enumerate(self.channel_names):
            # Channel name: 8 bytes, null-padded ASCII
            name_bytes = name.encode("ascii")[:7]
            w.write_bytes(name_bytes.ljust(8, b"\x00"))
            # Channel options
            options = self.channel_options[i] if i < len(self.channel_options) else 0x80000000
            w.write_u32_le(options)
        return w.to_bytes()


# ---------------------------------------------------------------------------
# Server Data Blocks
# ---------------------------------------------------------------------------


@dataclass
class ServerCoreData(Pdu):
    """Server Core Data block [MS-RDPBCGR] 2.2.1.4.2.

    Contains server version and protocol information.
    """

    version: int = 0x00080004
    client_requested_protocols: int = 0
    early_capability_flags: int = 0

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse ServerCoreData from binary data (without block header)."""
        reader = ByteReader(data, pdu_type="ServerCoreData")
        version = reader.read_u32_le()
        client_requested_protocols = 0
        early_capability_flags = 0
        if reader.remaining() >= 4:
            client_requested_protocols = reader.read_u32_le()
        if reader.remaining() >= 4:
            early_capability_flags = reader.read_u32_le()
        return cls(
            version=version,
            client_requested_protocols=client_requested_protocols,
            early_capability_flags=early_capability_flags,
        )

    def serialize(self) -> bytes:
        """Serialize ServerCoreData to binary (without block header)."""
        w = ByteWriter()
        w.write_u32_le(self.version)
        w.write_u32_le(self.client_requested_protocols)
        w.write_u32_le(self.early_capability_flags)
        return w.to_bytes()


@dataclass
class ServerSecurityData(Pdu):
    """Server Security Data block [MS-RDPBCGR] 2.2.1.4.3.

    Contains encryption method/level and the server random + certificate
    used for Standard RDP Security key exchange.
    """

    encryption_method: int = 0
    encryption_level: int = 0
    server_random: bytes = field(default=b"")
    server_certificate: bytes = field(default=b"")

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse ServerSecurityData from binary data (without block header)."""
        reader = ByteReader(data, pdu_type="ServerSecurityData")
        encryption_method = reader.read_u32_le()
        encryption_level = reader.read_u32_le()

        server_random = b""
        server_certificate = b""

        if reader.remaining() >= 4:
            server_random_len = reader.read_u32_le()
            if reader.remaining() >= 4:
                server_cert_len = reader.read_u32_le()
                if server_random_len > 0 and reader.remaining() >= server_random_len:
                    server_random = reader.read_bytes(server_random_len)
                if server_cert_len > 0 and reader.remaining() >= server_cert_len:
                    server_certificate = reader.read_bytes(server_cert_len)

        return cls(
            encryption_method=encryption_method,
            encryption_level=encryption_level,
            server_random=server_random,
            server_certificate=server_certificate,
        )

    def serialize(self) -> bytes:
        """Serialize ServerSecurityData to binary (without block header)."""
        w = ByteWriter()
        w.write_u32_le(self.encryption_method)
        w.write_u32_le(self.encryption_level)
        if self.server_random or self.server_certificate:
            w.write_u32_le(len(self.server_random))
            w.write_u32_le(len(self.server_certificate))
            w.write_bytes(self.server_random)
            w.write_bytes(self.server_certificate)
        return w.to_bytes()


@dataclass
class ServerNetworkData(Pdu):
    """Server Network Data block [MS-RDPBCGR] 2.2.1.4.4.

    Contains the MCS channel ID assignments for the I/O channel and
    all requested static virtual channels.
    """

    mcs_channel_id: int = 0x03EB  # Default I/O channel (1003)
    channel_ids: list[int] = field(default_factory=list)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse ServerNetworkData from binary data (without block header)."""
        reader = ByteReader(data, pdu_type="ServerNetworkData")
        mcs_channel_id = reader.read_u16_le()
        channel_count = reader.read_u16_le()
        channel_ids: list[int] = []
        for _ in range(channel_count):
            channel_ids.append(reader.read_u16_le())
        # Padding: if channel_count is odd, there's a 2-byte pad
        if channel_count % 2 != 0 and reader.remaining() >= 2:
            reader.read_u16_le()  # discard pad
        return cls(mcs_channel_id=mcs_channel_id, channel_ids=channel_ids)

    def serialize(self) -> bytes:
        """Serialize ServerNetworkData to binary (without block header)."""
        w = ByteWriter()
        w.write_u16_le(self.mcs_channel_id)
        w.write_u16_le(len(self.channel_ids))
        for cid in self.channel_ids:
            w.write_u16_le(cid)
        # Pad if channel_count is odd
        if len(self.channel_ids) % 2 != 0:
            w.write_u16_le(0)
        return w.to_bytes()


# ---------------------------------------------------------------------------
# GCC Conference Create Request/Response Encoding
# ---------------------------------------------------------------------------


def _write_data_block(block_type: int, payload: bytes) -> bytes:
    """Write a data block with its header (type u16 LE + length u16 LE).

    Length includes the 4-byte header itself.
    """
    w = ByteWriter()
    w.write_u16_le(block_type)
    w.write_u16_le(len(payload) + 4)  # length includes header
    w.write_bytes(payload)
    return w.to_bytes()


def encode_gcc_conference_create_request(
    core: ClientCoreData,
    security: ClientSecurityData,
    network: ClientNetworkData,
) -> bytes:
    """Encode client data blocks into a GCC Conference Create Request.

    Wraps the client data blocks in the T.124 GCC Conference Create Request
    PER-encoded structure used by RDP. (Req 2, AC 1)

    Args:
        core: Client core data block.
        security: Client security data block.
        network: Client network data block.

    Returns:
        The complete GCC Conference Create Request bytes ready to be
        embedded in an MCS Connect Initial PDU.
    """
    # Serialize each client data block with its header
    user_data = bytearray()
    user_data.extend(_write_data_block(CS_CORE, core.serialize()))
    user_data.extend(_write_data_block(CS_SECURITY, security.serialize()))
    if network.channel_names:
        user_data.extend(_write_data_block(CS_NET, network.serialize()))

    user_data_bytes = bytes(user_data)
    user_data_len = len(user_data_bytes)

    # Build the GCC Conference Create Request header
    # The structure is PER-encoded T.124 with well-known constants for RDP.
    header = bytearray()

    # Object identifier: T.124 (0.0.20.124.0.1)
    header.extend(b"\x00\x05\x00\x14\x7c\x00\x01")

    # ConnectData::connectPDU length (PER length encoding)
    # This is the length of everything after this point
    connect_pdu_len = 14 + user_data_len  # fixed fields + user data
    if connect_pdu_len > 0x7F:
        header.append(0x80 | ((connect_pdu_len >> 8) & 0x7F))
        header.append(connect_pdu_len & 0xFF)
    else:
        header.append(connect_pdu_len & 0x7F)

    # ConferenceCreateRequest fixed fields
    # PER encoding of the Conference Create Request
    header.extend(b"\x08\x00\x10\x00\x01\xc0\x00")

    # H.221 non-standard identifier key "Duca" (McDn in some docs)
    header.extend(b"\x44\x75\x63\x61")

    # User data length (PER length encoding)
    if user_data_len > 0x7F:
        header.append(0x80 | ((user_data_len >> 8) & 0x7F))
        header.append(user_data_len & 0xFF)
    else:
        header.append(user_data_len & 0x7F)

    return bytes(header) + user_data_bytes


def decode_gcc_conference_create_response(
    data: bytes,
) -> tuple[ServerCoreData, ServerSecurityData, ServerNetworkData]:
    """Decode server data blocks from a GCC Conference Create Response.

    Parses the T.124 GCC Conference Create Response structure and extracts
    the server core, security, and network data blocks. (Req 2, AC 2)

    Args:
        data: The raw GCC Conference Create Response bytes from the
              MCS Connect Response PDU user data field.

    Returns:
        Tuple of (ServerCoreData, ServerSecurityData, ServerNetworkData).

    Raises:
        PduParseError: If the response is malformed or missing required blocks.
    """
    reader = ByteReader(data, pdu_type="GccConferenceCreateResponse")

    # Skip the GCC Conference Create Response header
    # The response starts with the T.124 object identifier and PER-encoded
    # conference response structure. We need to find the user data.

    # Read and validate the object identifier prefix
    # Expected: 0x00 0x05 0x00 0x14 0x7c 0x00 0x01
    if reader.remaining() < 7:
        raise PduParseError(
            pdu_type="GccConferenceCreateResponse",
            offset=0,
            description="data too short for GCC response header",
        )

    oid = reader.read_bytes(7)
    if oid != _GCC_RESPONSE_OID:
        raise PduParseError(
            pdu_type="GccConferenceCreateResponse",
            offset=0,
            description="invalid T.124 object identifier",
        )

    # Read ConnectData::connectPDU length (PER length)
    _read_per_length(reader)

    # Skip the Conference Create Response fixed fields
    # 0x14 0x76 0x0a 0x01 0x01 0x00 0x01 0xc0 0x00 (node ID, tag, result)
    # The exact structure varies but we need to find "McDn" (0x4d 0x63 0x44 0x6e)
    # which marks the start of the H.221 user data key in the response.
    _skip_to_user_data(reader)

    # Read user data length (PER length)
    user_data_len = _read_per_length(reader)

    # Parse server data blocks
    server_core: ServerCoreData | None = None
    server_security: ServerSecurityData | None = None
    server_network: ServerNetworkData | None = None

    end_offset = reader.offset + user_data_len
    while reader.offset < end_offset and reader.remaining() >= 4:
        block_type = reader.read_u16_le()
        block_length = reader.read_u16_le()
        # block_length includes the 4-byte header
        payload_length = block_length - 4
        if payload_length < 0 or reader.remaining() < payload_length:
            break
        block_data = reader.read_bytes(payload_length)

        if block_type == SC_CORE:
            server_core = ServerCoreData.parse(block_data)
        elif block_type == SC_SECURITY:
            server_security = ServerSecurityData.parse(block_data)
        elif block_type == SC_NET:
            server_network = ServerNetworkData.parse(block_data)

    if server_core is None:
        raise PduParseError(
            pdu_type="GccConferenceCreateResponse",
            offset=reader.offset,
            description="missing SC_CORE data block",
        )
    if server_security is None:
        raise PduParseError(
            pdu_type="GccConferenceCreateResponse",
            offset=reader.offset,
            description="missing SC_SECURITY data block",
        )
    if server_network is None:
        raise PduParseError(
            pdu_type="GccConferenceCreateResponse",
            offset=reader.offset,
            description="missing SC_NET data block",
        )

    return server_core, server_security, server_network


def _read_per_length(reader: ByteReader) -> int:
    """Read a PER-encoded length value from the reader.

    PER length encoding:
    - If high bit is 0: single byte, value is 0–127
    - If high bit is 1: two bytes, value is ((first & 0x7F) << 8) | second
    """
    first = reader.read_u8()
    if first & 0x80:
        second = reader.read_u8()
        return ((first & 0x7F) << 8) | second
    return first


def _skip_to_user_data(reader: ByteReader) -> None:
    """Skip GCC Conference Create Response header fields to reach user data.

    The response contains PER-encoded fields before the H.221 key "McDn"
    (0x4d 0x63 0x44 0x6e) which marks the server user data section.
    """
    # The GCC Conference Create Response after the OID has:
    # - ConnectPDU length (already read)
    # - A fixed sequence of PER-encoded fields
    # We scan for the "McDn" marker which precedes the user data length.
    start = reader.offset
    search_data = reader._data[start:]

    # Look for "McDn" (H.221 non-standard key for Microsoft server data)
    target = b"\x4d\x63\x44\x6e"
    for i in range(len(search_data) - 3):
        if bytes(search_data[i : i + 4]) == target:
            # Advance reader past "McDn"
            reader.read_bytes(i + 4)
            return

    raise PduParseError(
        pdu_type="GccConferenceCreateResponse",
        offset=reader.offset,
        description="could not find 'McDn' user data marker in GCC response",
    )
