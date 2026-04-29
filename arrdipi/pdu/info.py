"""Client Info PDU and Extended Info Packet [MS-RDPBCGR] 2.2.1.11.

Implements the TS_INFO_PACKET, ExtendedInfoPacket, and TimezoneInfo structures
sent during Phase 5 (Secure Settings Exchange) of the RDP connection sequence.

References:
- [MS-RDPBCGR] 2.2.1.11 — Client Info PDU
- [MS-RDPBCGR] 2.2.1.11.1.1 — Info Packet (TS_INFO_PACKET)
- [MS-RDPBCGR] 2.2.1.11.1.1.1 — Extended Info Packet
- [MS-RDPBCGR] 2.2.1.11.1.1.1.1 — Time Zone Information (TS_TIME_ZONE_INFORMATION)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntFlag
from typing import Self

from arrdipi.errors import PduParseError
from arrdipi.pdu.base import ByteReader, ByteWriter, Pdu
from arrdipi.pdu.types import CompressionType, PerformanceFlags


# ---------------------------------------------------------------------------
# Info Packet Flags [MS-RDPBCGR] 2.2.1.11.1.1
# ---------------------------------------------------------------------------


class InfoFlags(IntFlag):
    """Flags for the TS_INFO_PACKET flags field."""

    INFO_MOUSE = 0x00000001
    INFO_DISABLECTRLALTDEL = 0x00000002
    INFO_AUTOLOGON = 0x00000008
    INFO_UNICODE = 0x00000010
    INFO_MAXIMIZESHELL = 0x00000020
    INFO_LOGONNOTIFY = 0x00000040
    INFO_COMPRESSION = 0x00000080
    INFO_ENABLEWINDOWSKEY = 0x00000100
    INFO_NOAUDIOPLAYBACK = 0x00002000
    INFO_FORCE_ENCRYPTED_CS_PDU = 0x00004000
    INFO_RAIL = 0x00008000
    INFO_LOGONERRORS = 0x00010000
    INFO_MOUSE_HAS_WHEEL = 0x00020000
    INFO_PASSWORD_IS_SC_PIN = 0x00040000
    INFO_NOAUDIOPLAYBACK_2 = 0x00080000
    INFO_USING_SAVED_CREDS = 0x00100000
    INFO_AUDIOCAPTURE = 0x00200000
    INFO_VIDEO_DISABLE = 0x00400000
    INFO_HIDEF_RAIL_SUPPORTED = 0x02000000


# Default flags per design document
DEFAULT_INFO_FLAGS = (
    InfoFlags.INFO_MOUSE
    | InfoFlags.INFO_UNICODE
    | InfoFlags.INFO_LOGONNOTIFY
    | InfoFlags.INFO_LOGONERRORS
    | InfoFlags.INFO_DISABLECTRLALTDEL
    | InfoFlags.INFO_ENABLEWINDOWSKEY
    | InfoFlags.INFO_MOUSE_HAS_WHEEL
)

# Address family constants
AF_INET = 0x0002

# SYSTEMTIME size: 8 x u16 = 16 bytes
_SYSTEMTIME_SIZE = 16

# TimezoneInfo total size: bias(4) + standardName(64) + standardDate(16) +
# standardBias(4) + daylightName(64) + daylightDate(16) + daylightBias(4) = 172
_TIMEZONE_INFO_SIZE = 172


# ---------------------------------------------------------------------------
# SYSTEMTIME helper
# ---------------------------------------------------------------------------


@dataclass
class SystemTime:
    """SYSTEMTIME structure [MS-RDPBCGR] 2.2.1.11.1.1.1.1.

    Fields (16 bytes total):
        year: u16 LE
        month: u16 LE
        day_of_week: u16 LE
        day: u16 LE
        hour: u16 LE
        minute: u16 LE
        second: u16 LE
        milliseconds: u16 LE
    """

    year: int = 0
    month: int = 0
    day_of_week: int = 0
    day: int = 0
    hour: int = 0
    minute: int = 0
    second: int = 0
    milliseconds: int = 0

    def serialize(self) -> bytes:
        """Serialize to 16 bytes."""
        return struct.pack(
            "<8H",
            self.year,
            self.month,
            self.day_of_week,
            self.day,
            self.hour,
            self.minute,
            self.second,
            self.milliseconds,
        )

    @classmethod
    def parse(cls, reader: ByteReader) -> Self:
        """Parse a SYSTEMTIME from the reader (consumes 16 bytes)."""
        data = reader.read_bytes(_SYSTEMTIME_SIZE)
        values = struct.unpack_from("<8H", data)
        return cls(
            year=values[0],
            month=values[1],
            day_of_week=values[2],
            day=values[3],
            hour=values[4],
            minute=values[5],
            second=values[6],
            milliseconds=values[7],
        )


# ---------------------------------------------------------------------------
# TimezoneInfo [MS-RDPBCGR] 2.2.1.11.1.1.1.1
# ---------------------------------------------------------------------------


@dataclass
class TimezoneInfo(Pdu):
    """Time Zone Information structure (TS_TIME_ZONE_INFORMATION).

    Total size: 172 bytes.

    Fields:
        bias: i32 LE — UTC offset in minutes.
        standard_name: str — Standard timezone name (max 31 UTF-16LE chars).
        standard_date: SystemTime — Date when standard time begins.
        standard_bias: i32 LE — Additional bias during standard time.
        daylight_name: str — Daylight timezone name (max 31 UTF-16LE chars).
        daylight_date: SystemTime — Date when daylight time begins.
        daylight_bias: i32 LE — Additional bias during daylight time.
    """

    bias: int = 0
    standard_name: str = ""
    standard_date: SystemTime = field(default_factory=SystemTime)
    standard_bias: int = 0
    daylight_name: str = ""
    daylight_date: SystemTime = field(default_factory=SystemTime)
    daylight_bias: int = 0

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse TimezoneInfo from 172 bytes of binary data."""
        reader = ByteReader(data, pdu_type="TimezoneInfo")
        return cls._parse_from_reader(reader)

    @classmethod
    def _parse_from_reader(cls, reader: ByteReader) -> Self:
        """Parse TimezoneInfo from a ByteReader."""
        bias = reader.read_i32_le()
        standard_name_bytes = reader.read_bytes(64)
        standard_date = SystemTime.parse(reader)
        standard_bias = reader.read_i32_le()
        daylight_name_bytes = reader.read_bytes(64)
        daylight_date = SystemTime.parse(reader)
        daylight_bias = reader.read_i32_le()

        standard_name = _decode_padded_utf16(standard_name_bytes)
        daylight_name = _decode_padded_utf16(daylight_name_bytes)

        return cls(
            bias=bias,
            standard_name=standard_name,
            standard_date=standard_date,
            standard_bias=standard_bias,
            daylight_name=daylight_name,
            daylight_date=daylight_date,
            daylight_bias=daylight_bias,
        )

    def serialize(self) -> bytes:
        """Serialize to exactly 172 bytes."""
        writer = ByteWriter()
        writer.write_i32_le(self.bias)
        writer.write_bytes(_encode_padded_utf16(self.standard_name, 64))
        writer.write_bytes(self.standard_date.serialize())
        writer.write_i32_le(self.standard_bias)
        writer.write_bytes(_encode_padded_utf16(self.daylight_name, 64))
        writer.write_bytes(self.daylight_date.serialize())
        writer.write_i32_le(self.daylight_bias)
        return writer.to_bytes()


# ---------------------------------------------------------------------------
# ExtendedInfoPacket [MS-RDPBCGR] 2.2.1.11.1.1.1
# ---------------------------------------------------------------------------


@dataclass
class ExtendedInfoPacket(Pdu):
    """Extended Info Packet structure.

    Fields:
        client_address_family: u16 LE — AF_INET (0x0002).
        client_address: str — Client IP address.
        client_dir: str — Client working directory.
        client_timezone: TimezoneInfo — Client timezone (172 bytes).
        client_session_id: u32 LE — Session ID.
        performance_flags: PerformanceFlags — Performance preferences.
        auto_reconnect_cookie: bytes | None — Auto-reconnect cookie (optional).
        cb_auto_reconnect_cookie: int — Length of auto-reconnect cookie.
    """

    client_address_family: int = AF_INET
    client_address: str = ""
    client_dir: str = ""
    client_timezone: TimezoneInfo = field(default_factory=TimezoneInfo)
    client_session_id: int = 0
    performance_flags: PerformanceFlags = PerformanceFlags(0)
    auto_reconnect_cookie: bytes | None = None

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse ExtendedInfoPacket from binary data."""
        reader = ByteReader(data, pdu_type="ExtendedInfoPacket")
        return cls._parse_from_reader(reader)

    @classmethod
    def _parse_from_reader(cls, reader: ByteReader) -> Self:
        """Parse ExtendedInfoPacket from a ByteReader."""
        client_address_family = reader.read_u16_le()
        cb_client_address = reader.read_u16_le()
        client_address_bytes = reader.read_bytes(cb_client_address)
        client_address = _decode_utf16_with_null(client_address_bytes)

        cb_client_dir = reader.read_u16_le()
        client_dir_bytes = reader.read_bytes(cb_client_dir)
        client_dir = _decode_utf16_with_null(client_dir_bytes)

        # TimezoneInfo is always 172 bytes
        tz_data = reader.read_bytes(_TIMEZONE_INFO_SIZE)
        client_timezone = TimezoneInfo.parse(tz_data)

        client_session_id = reader.read_u32_le()
        performance_flags = PerformanceFlags(reader.read_u32_le())

        # Auto-reconnect cookie
        auto_reconnect_cookie: bytes | None = None
        if reader.remaining() >= 2:
            cb_auto_reconnect_cookie = reader.read_u16_le()
            if cb_auto_reconnect_cookie > 0:
                auto_reconnect_cookie = reader.read_bytes(cb_auto_reconnect_cookie)

        return cls(
            client_address_family=client_address_family,
            client_address=client_address,
            client_dir=client_dir,
            client_timezone=client_timezone,
            client_session_id=client_session_id,
            performance_flags=performance_flags,
            auto_reconnect_cookie=auto_reconnect_cookie,
        )

    def serialize(self) -> bytes:
        """Serialize the ExtendedInfoPacket to binary wire format."""
        writer = ByteWriter()
        writer.write_u16_le(self.client_address_family)

        # clientAddress: UTF-16LE + null terminator
        address_encoded = _encode_utf16_with_null(self.client_address)
        writer.write_u16_le(len(address_encoded))
        writer.write_bytes(address_encoded)

        # clientDir: UTF-16LE + null terminator
        dir_encoded = _encode_utf16_with_null(self.client_dir)
        writer.write_u16_le(len(dir_encoded))
        writer.write_bytes(dir_encoded)

        # TimezoneInfo (172 bytes)
        writer.write_bytes(self.client_timezone.serialize())

        # clientSessionId
        writer.write_u32_le(self.client_session_id)

        # performanceFlags
        writer.write_u32_le(int(self.performance_flags))

        # Auto-reconnect cookie
        if self.auto_reconnect_cookie is not None:
            writer.write_u16_le(len(self.auto_reconnect_cookie))
            writer.write_bytes(self.auto_reconnect_cookie)
        else:
            writer.write_u16_le(0)

        return writer.to_bytes()


# ---------------------------------------------------------------------------
# ClientInfoPdu [MS-RDPBCGR] 2.2.1.11
# ---------------------------------------------------------------------------


@dataclass
class ClientInfoPdu(Pdu):
    """Client Info PDU (TS_INFO_PACKET) [MS-RDPBCGR] 2.2.1.11.

    Contains user credentials and session preferences sent during Phase 5
    (Secure Settings Exchange).

    Fields:
        code_page: u32 LE — Code page identifier.
        flags: InfoFlags — Info packet flags.
        domain: str — User domain name.
        username: str — Username.
        password: str — Password.
        alternate_shell: str — Alternate shell to launch.
        working_dir: str — Working directory.
        extra_info: ExtendedInfoPacket | None — Extended info (present when INFO_UNICODE set).
        security_flags: int — Security header flags (always included per Req 5, AC 5).
        security_flags_hi: int — Security header high flags.
    """

    code_page: int = 0
    flags: InfoFlags = field(default_factory=lambda: DEFAULT_INFO_FLAGS)
    domain: str = ""
    username: str = ""
    password: str = ""
    alternate_shell: str = ""
    working_dir: str = ""
    extra_info: ExtendedInfoPacket | None = field(default_factory=ExtendedInfoPacket)
    security_flags: int = 0x0040  # SEC_INFO_PKT
    security_flags_hi: int = 0

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse a ClientInfoPdu from binary data.

        The data includes the security header (4 bytes) followed by the
        info packet payload.

        Raises PduParseError on malformed/truncated data.
        """
        reader = ByteReader(data, pdu_type="ClientInfoPdu")

        # Security header (always present per Req 5, AC 5)
        security_flags = reader.read_u16_le()
        security_flags_hi = reader.read_u16_le()

        # Info Packet fields
        code_page = reader.read_u32_le()
        flags_value = reader.read_u32_le()
        flags = InfoFlags(flags_value)

        cb_domain = reader.read_u16_le()
        cb_username = reader.read_u16_le()
        cb_password = reader.read_u16_le()
        cb_alternate_shell = reader.read_u16_le()
        cb_working_dir = reader.read_u16_le()

        # String fields: each is cb bytes + 2-byte null terminator
        domain_bytes = reader.read_bytes(cb_domain + 2)
        username_bytes = reader.read_bytes(cb_username + 2)
        password_bytes = reader.read_bytes(cb_password + 2)
        alternate_shell_bytes = reader.read_bytes(cb_alternate_shell + 2)
        working_dir_bytes = reader.read_bytes(cb_working_dir + 2)

        domain = _decode_utf16_with_null(domain_bytes)
        username = _decode_utf16_with_null(username_bytes)
        password = _decode_utf16_with_null(password_bytes)
        alternate_shell = _decode_utf16_with_null(alternate_shell_bytes)
        working_dir = _decode_utf16_with_null(working_dir_bytes)

        # Extended Info Packet (present when INFO_UNICODE is set)
        extra_info: ExtendedInfoPacket | None = None
        if (flags & InfoFlags.INFO_UNICODE) and reader.remaining() > 0:
            remaining_data = reader.read_bytes(reader.remaining())
            extra_reader = ByteReader(remaining_data, pdu_type="ExtendedInfoPacket")
            extra_info = ExtendedInfoPacket._parse_from_reader(extra_reader)

        return cls(
            code_page=code_page,
            flags=flags,
            domain=domain,
            username=username,
            password=password,
            alternate_shell=alternate_shell,
            working_dir=working_dir,
            extra_info=extra_info,
            security_flags=security_flags,
            security_flags_hi=security_flags_hi,
        )

    def serialize(self) -> bytes:
        """Serialize the ClientInfoPdu to binary wire format.

        Includes the security header (Req 5, AC 5) followed by the info packet.
        """
        writer = ByteWriter()

        # Security header (always included per Req 5, AC 5)
        writer.write_u16_le(self.security_flags)
        writer.write_u16_le(self.security_flags_hi)

        # Info Packet
        writer.write_u32_le(self.code_page)
        writer.write_u32_le(int(self.flags))

        # Encode strings as UTF-16LE
        domain_encoded = self.domain.encode("utf-16-le")
        username_encoded = self.username.encode("utf-16-le")
        password_encoded = self.password.encode("utf-16-le")
        alternate_shell_encoded = self.alternate_shell.encode("utf-16-le")
        working_dir_encoded = self.working_dir.encode("utf-16-le")

        # cbDomain, cbUserName, etc. are the byte lengths WITHOUT null terminator
        writer.write_u16_le(len(domain_encoded))
        writer.write_u16_le(len(username_encoded))
        writer.write_u16_le(len(password_encoded))
        writer.write_u16_le(len(alternate_shell_encoded))
        writer.write_u16_le(len(working_dir_encoded))

        # String data: encoded bytes + 2-byte null terminator
        writer.write_bytes(domain_encoded + b"\x00\x00")
        writer.write_bytes(username_encoded + b"\x00\x00")
        writer.write_bytes(password_encoded + b"\x00\x00")
        writer.write_bytes(alternate_shell_encoded + b"\x00\x00")
        writer.write_bytes(working_dir_encoded + b"\x00\x00")

        # Extended Info Packet
        if self.extra_info is not None:
            writer.write_bytes(self.extra_info.serialize())

        return writer.to_bytes()


# ---------------------------------------------------------------------------
# Helper functions for UTF-16LE encoding/decoding
# ---------------------------------------------------------------------------


def _encode_utf16_with_null(s: str) -> bytes:
    """Encode a string as UTF-16LE with a 2-byte null terminator."""
    return s.encode("utf-16-le") + b"\x00\x00"


def _decode_utf16_with_null(data: bytes) -> str:
    """Decode UTF-16LE bytes, stripping the trailing null terminator."""
    # Remove trailing null terminator (2 bytes)
    if len(data) >= 2 and data[-2:] == b"\x00\x00":
        data = data[:-2]
    return data.decode("utf-16-le")


def _encode_padded_utf16(s: str, total_bytes: int) -> bytes:
    """Encode a string as UTF-16LE, null-padded to exactly total_bytes."""
    encoded = s.encode("utf-16-le")
    # Truncate if too long (leave room for at least one null char)
    max_content = total_bytes - 2
    if len(encoded) > max_content:
        encoded = encoded[:max_content]
    # Pad with null bytes to reach total_bytes
    return encoded + b"\x00" * (total_bytes - len(encoded))


def _decode_padded_utf16(data: bytes) -> str:
    """Decode null-padded UTF-16LE bytes, stripping trailing nulls."""
    # Find the first null character (pair of zero bytes on even boundary)
    for i in range(0, len(data) - 1, 2):
        if data[i] == 0 and data[i + 1] == 0:
            data = data[:i]
            break
    return data.decode("utf-16-le")
