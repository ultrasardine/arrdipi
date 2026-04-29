"""Tests for arrdipi/pdu/info.py: ClientInfoPdu, ExtendedInfoPacket, TimezoneInfo."""

from __future__ import annotations

import pytest

from arrdipi.errors import PduParseError
from arrdipi.pdu.info import (
    AF_INET,
    DEFAULT_INFO_FLAGS,
    ClientInfoPdu,
    ExtendedInfoPacket,
    InfoFlags,
    SystemTime,
    TimezoneInfo,
)
from arrdipi.pdu.types import CompressionType, PerformanceFlags


# ---------------------------------------------------------------------------
# TimezoneInfo tests
# ---------------------------------------------------------------------------


class TestTimezoneInfoRoundTrip:
    """Round-trip: construct → serialize → parse → compare equality."""

    def test_default_timezone(self) -> None:
        """Default TimezoneInfo round-trips correctly."""
        original = TimezoneInfo()
        serialized = original.serialize()
        assert len(serialized) == 172
        parsed = TimezoneInfo.parse(serialized)
        assert parsed == original

    def test_timezone_with_names_and_bias(self) -> None:
        """TimezoneInfo with populated names and bias values."""
        original = TimezoneInfo(
            bias=-480,
            standard_name="Pacific Standard Time",
            standard_date=SystemTime(month=11, day_of_week=0, day=1, hour=2),
            standard_bias=0,
            daylight_name="Pacific Daylight Time",
            daylight_date=SystemTime(month=3, day_of_week=0, day=2, hour=2),
            daylight_bias=-60,
        )
        serialized = original.serialize()
        assert len(serialized) == 172
        parsed = TimezoneInfo.parse(serialized)
        assert parsed == original

    def test_timezone_positive_bias(self) -> None:
        """TimezoneInfo with positive bias (east of UTC)."""
        original = TimezoneInfo(
            bias=330,
            standard_name="India Standard Time",
            standard_date=SystemTime(),
            standard_bias=0,
            daylight_name="India Daylight Time",
            daylight_date=SystemTime(),
            daylight_bias=0,
        )
        serialized = original.serialize()
        assert len(serialized) == 172
        parsed = TimezoneInfo.parse(serialized)
        assert parsed == original

    def test_serialized_size_always_172(self) -> None:
        """TimezoneInfo always serializes to exactly 172 bytes."""
        tz = TimezoneInfo(
            bias=0,
            standard_name="A" * 31,  # Max length
            daylight_name="B" * 31,
        )
        assert len(tz.serialize()) == 172


class TestTimezoneInfoMalformed:
    """Truncated data raises PduParseError."""

    def test_empty_data(self) -> None:
        with pytest.raises(PduParseError) as exc_info:
            TimezoneInfo.parse(b"")
        assert exc_info.value.pdu_type == "TimezoneInfo"

    def test_truncated_data(self) -> None:
        with pytest.raises(PduParseError):
            TimezoneInfo.parse(b"\x00" * 100)


# ---------------------------------------------------------------------------
# SystemTime tests
# ---------------------------------------------------------------------------


class TestSystemTimeRoundTrip:
    """Round-trip for SystemTime helper."""

    def test_default_systemtime(self) -> None:
        original = SystemTime()
        serialized = original.serialize()
        assert len(serialized) == 16
        from arrdipi.pdu.base import ByteReader

        reader = ByteReader(serialized, pdu_type="SystemTime")
        parsed = SystemTime.parse(reader)
        assert parsed == original

    def test_populated_systemtime(self) -> None:
        original = SystemTime(
            year=2024, month=3, day_of_week=0, day=10,
            hour=2, minute=0, second=0, milliseconds=0,
        )
        serialized = original.serialize()
        assert len(serialized) == 16
        from arrdipi.pdu.base import ByteReader

        reader = ByteReader(serialized, pdu_type="SystemTime")
        parsed = SystemTime.parse(reader)
        assert parsed == original


# ---------------------------------------------------------------------------
# ExtendedInfoPacket tests
# ---------------------------------------------------------------------------


class TestExtendedInfoPacketRoundTrip:
    """Round-trip: construct → serialize → parse → compare equality."""

    def test_default_extended_info(self) -> None:
        """Default ExtendedInfoPacket round-trips correctly."""
        original = ExtendedInfoPacket()
        serialized = original.serialize()
        parsed = ExtendedInfoPacket.parse(serialized)
        assert parsed == original

    def test_with_all_fields_populated(self) -> None:
        """ExtendedInfoPacket with all fields populated."""
        original = ExtendedInfoPacket(
            client_address_family=AF_INET,
            client_address="192.168.1.100",
            client_dir="C:\\Windows\\System32\\mstsc.exe",
            client_timezone=TimezoneInfo(
                bias=-300,
                standard_name="Eastern Standard Time",
                standard_date=SystemTime(month=11, day=1, hour=2),
                standard_bias=0,
                daylight_name="Eastern Daylight Time",
                daylight_date=SystemTime(month=3, day=2, hour=2),
                daylight_bias=-60,
            ),
            client_session_id=0,
            performance_flags=(
                PerformanceFlags.DISABLE_WALLPAPER
                | PerformanceFlags.DISABLE_FULLWINDOWDRAG
                | PerformanceFlags.DISABLE_MENUANIMATIONS
            ),
            auto_reconnect_cookie=b"\x01\x02\x03\x04\x05\x06\x07\x08" * 3,
        )
        serialized = original.serialize()
        parsed = ExtendedInfoPacket.parse(serialized)
        assert parsed == original

    def test_without_auto_reconnect_cookie(self) -> None:
        """ExtendedInfoPacket without auto-reconnect cookie."""
        original = ExtendedInfoPacket(
            client_address="10.0.0.1",
            client_dir="C:\\WINNT",
            client_timezone=TimezoneInfo(bias=0),
            client_session_id=42,
            performance_flags=PerformanceFlags(0),
            auto_reconnect_cookie=None,
        )
        serialized = original.serialize()
        parsed = ExtendedInfoPacket.parse(serialized)
        assert parsed == original

    def test_with_performance_flags(self) -> None:
        """ExtendedInfoPacket with various performance flags (Req 5, AC 3)."""
        original = ExtendedInfoPacket(
            client_address="127.0.0.1",
            client_dir="",
            performance_flags=(
                PerformanceFlags.DISABLE_WALLPAPER
                | PerformanceFlags.DISABLE_THEMING
                | PerformanceFlags.ENABLE_FONT_SMOOTHING
                | PerformanceFlags.ENABLE_DESKTOP_COMPOSITION
            ),
        )
        serialized = original.serialize()
        parsed = ExtendedInfoPacket.parse(serialized)
        assert parsed == original

    def test_with_auto_reconnect_cookie(self) -> None:
        """ExtendedInfoPacket with auto-reconnect cookie (Req 5, AC 4)."""
        cookie = bytes(range(28))  # 28-byte ARC_SC_PRIVATE_PACKET
        original = ExtendedInfoPacket(
            client_address="192.168.0.1",
            client_dir="",
            auto_reconnect_cookie=cookie,
        )
        serialized = original.serialize()
        parsed = ExtendedInfoPacket.parse(serialized)
        assert parsed == original
        assert parsed.auto_reconnect_cookie == cookie


class TestExtendedInfoPacketMalformed:
    """Truncated data raises PduParseError."""

    def test_empty_data(self) -> None:
        with pytest.raises(PduParseError) as exc_info:
            ExtendedInfoPacket.parse(b"")
        assert exc_info.value.pdu_type == "ExtendedInfoPacket"

    def test_truncated_before_timezone(self) -> None:
        """Data truncated before timezone info."""
        # Just address family + cbClientAddress + minimal address
        data = b"\x02\x00\x02\x00\x00\x00"
        with pytest.raises(PduParseError):
            ExtendedInfoPacket.parse(data)


# ---------------------------------------------------------------------------
# ClientInfoPdu tests
# ---------------------------------------------------------------------------


class TestClientInfoPduRoundTrip:
    """Round-trip: construct → serialize → parse → compare equality (Req 3, AC 4–5)."""

    def test_all_fields_populated(self) -> None:
        """ClientInfoPdu with all fields populated round-trips correctly."""
        original = ClientInfoPdu(
            code_page=0,
            flags=DEFAULT_INFO_FLAGS | InfoFlags.INFO_AUTOLOGON,
            domain="MYDOMAIN",
            username="testuser",
            password="P@ssw0rd!",
            alternate_shell="",
            working_dir="",
            extra_info=ExtendedInfoPacket(
                client_address_family=AF_INET,
                client_address="192.168.1.50",
                client_dir="C:\\Windows\\System32\\mstsc.exe",
                client_timezone=TimezoneInfo(
                    bias=-480,
                    standard_name="Pacific Standard Time",
                    standard_date=SystemTime(month=11, day_of_week=0, day=1, hour=2),
                    standard_bias=0,
                    daylight_name="Pacific Daylight Time",
                    daylight_date=SystemTime(month=3, day_of_week=0, day=2, hour=2),
                    daylight_bias=-60,
                ),
                client_session_id=0,
                performance_flags=(
                    PerformanceFlags.DISABLE_WALLPAPER
                    | PerformanceFlags.DISABLE_FULLWINDOWDRAG
                ),
                auto_reconnect_cookie=b"\xAA\xBB\xCC\xDD" * 7,
            ),
            security_flags=0x0040,
            security_flags_hi=0,
        )
        serialized = original.serialize()
        parsed = ClientInfoPdu.parse(serialized)
        assert parsed == original

    def test_optional_fields_absent(self) -> None:
        """ClientInfoPdu with optional fields absent round-trips correctly."""
        original = ClientInfoPdu(
            code_page=0,
            flags=DEFAULT_INFO_FLAGS,
            domain="",
            username="admin",
            password="",
            alternate_shell="",
            working_dir="",
            extra_info=ExtendedInfoPacket(
                client_address="",
                client_dir="",
                client_timezone=TimezoneInfo(),
                client_session_id=0,
                performance_flags=PerformanceFlags(0),
                auto_reconnect_cookie=None,
            ),
            security_flags=0x0040,
            security_flags_hi=0,
        )
        serialized = original.serialize()
        parsed = ClientInfoPdu.parse(serialized)
        assert parsed == original

    def test_unicode_domain_and_username(self) -> None:
        """ClientInfoPdu with Unicode characters in domain/username."""
        original = ClientInfoPdu(
            domain="DOMÄIN",
            username="ユーザー",
            password="密码",
            alternate_shell="",
            working_dir="",
            extra_info=ExtendedInfoPacket(),
        )
        serialized = original.serialize()
        parsed = ClientInfoPdu.parse(serialized)
        assert parsed == original
        assert parsed.domain == "DOMÄIN"
        assert parsed.username == "ユーザー"
        assert parsed.password == "密码"

    def test_security_header_always_present(self) -> None:
        """Security header is always included in serialized output (Req 5, AC 5)."""
        pdu = ClientInfoPdu(
            domain="TEST",
            username="user",
            password="pass",
            security_flags=0x0040,
            security_flags_hi=0x0000,
        )
        serialized = pdu.serialize()
        # First 4 bytes are the security header
        assert len(serialized) >= 4
        # Verify security flags are at the start
        import struct

        flags, flags_hi = struct.unpack_from("<HH", serialized, 0)
        assert flags == 0x0040
        assert flags_hi == 0x0000

    def test_without_extended_info(self) -> None:
        """ClientInfoPdu without extended info (extra_info=None)."""
        original = ClientInfoPdu(
            flags=InfoFlags.INFO_MOUSE | InfoFlags.INFO_DISABLECTRLALTDEL,
            domain="CORP",
            username="jdoe",
            password="secret",
            alternate_shell="explorer.exe",
            working_dir="C:\\Users\\jdoe",
            extra_info=None,
        )
        serialized = original.serialize()
        parsed = ClientInfoPdu.parse(serialized)
        assert parsed == original
        assert parsed.extra_info is None

    def test_with_alternate_shell_and_working_dir(self) -> None:
        """ClientInfoPdu with alternate shell and working directory."""
        original = ClientInfoPdu(
            domain="",
            username="admin",
            password="admin123",
            alternate_shell="cmd.exe /k dir",
            working_dir="C:\\Temp",
            extra_info=ExtendedInfoPacket(),
        )
        serialized = original.serialize()
        parsed = ClientInfoPdu.parse(serialized)
        assert parsed == original

    def test_default_flags_include_required(self) -> None:
        """Default flags include all required flags per design."""
        assert DEFAULT_INFO_FLAGS & InfoFlags.INFO_MOUSE
        assert DEFAULT_INFO_FLAGS & InfoFlags.INFO_UNICODE
        assert DEFAULT_INFO_FLAGS & InfoFlags.INFO_LOGONNOTIFY
        assert DEFAULT_INFO_FLAGS & InfoFlags.INFO_LOGONERRORS
        assert DEFAULT_INFO_FLAGS & InfoFlags.INFO_DISABLECTRLALTDEL
        assert DEFAULT_INFO_FLAGS & InfoFlags.INFO_ENABLEWINDOWSKEY
        assert DEFAULT_INFO_FLAGS & InfoFlags.INFO_MOUSE_HAS_WHEEL

    def test_compression_type_in_flags(self) -> None:
        """Compression type is encoded in flags field (Req 5, AC 6)."""
        # INFO_COMPRESSION flag indicates compression support
        original = ClientInfoPdu(
            flags=DEFAULT_INFO_FLAGS | InfoFlags.INFO_COMPRESSION,
            domain="",
            username="user",
            password="",
            extra_info=ExtendedInfoPacket(),
        )
        serialized = original.serialize()
        parsed = ClientInfoPdu.parse(serialized)
        assert parsed.flags & InfoFlags.INFO_COMPRESSION


class TestClientInfoPduMalformed:
    """Truncated data raises PduParseError with correct context (Req 3, AC 6)."""

    def test_empty_data(self) -> None:
        with pytest.raises(PduParseError) as exc_info:
            ClientInfoPdu.parse(b"")
        assert exc_info.value.pdu_type == "ClientInfoPdu"
        assert exc_info.value.offset == 0

    def test_truncated_security_header(self) -> None:
        """Only 2 bytes of security header."""
        with pytest.raises(PduParseError) as exc_info:
            ClientInfoPdu.parse(b"\x40\x00")
        assert exc_info.value.pdu_type == "ClientInfoPdu"

    def test_truncated_info_packet(self) -> None:
        """Security header present but info packet truncated."""
        # 4 bytes security header + 4 bytes code_page only
        data = b"\x40\x00\x00\x00" + b"\x00\x00\x00\x00"
        with pytest.raises(PduParseError) as exc_info:
            ClientInfoPdu.parse(data)
        assert exc_info.value.pdu_type == "ClientInfoPdu"

    def test_truncated_string_data(self) -> None:
        """Header claims string lengths but data is truncated."""
        import struct

        # Security header
        data = struct.pack("<HH", 0x0040, 0x0000)
        # code_page + flags
        data += struct.pack("<II", 0, int(DEFAULT_INFO_FLAGS))
        # cb fields: domain=10 bytes, rest=0
        data += struct.pack("<HHHHH", 10, 0, 0, 0, 0)
        # But no actual string data follows
        with pytest.raises(PduParseError):
            ClientInfoPdu.parse(data)
