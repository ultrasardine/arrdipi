"""Tests for the clipboard redirection channel (CLIPRDR)."""

from __future__ import annotations

import asyncio
import struct
from unittest.mock import AsyncMock

import pytest

from arrdipi.channels.clipboard import (
    CB_RESPONSE_OK,
    CB_USE_LONG_FORMAT_NAMES,
    CF_UNICODETEXT,
    CLIPRDR_CAPABILITIES,
    CLIPRDR_FORMAT_DATA_REQUEST,
    CLIPRDR_FORMAT_DATA_RESPONSE,
    CLIPRDR_FORMAT_LIST,
    CLIPRDR_FORMAT_LIST_RESPONSE,
    CLIPRDR_MONITOR_READY,
    CLIPRDR_TEMP_DIRECTORY,
    ClipboardCapabilitiesPdu,
    ClipboardChannel,
    ClipboardFormat,
    FormatDataRequestPdu,
    FormatDataResponsePdu,
    FormatListPdu,
    MonitorReadyPdu,
    TemporaryDirectoryPdu,
)


class TestMonitorReadyPdu:
    """Tests for MonitorReadyPdu."""

    def test_serialize(self) -> None:
        pdu = MonitorReadyPdu()
        data = pdu.serialize()
        assert len(data) == 8
        msg_type, msg_flags, data_len = struct.unpack_from("<HHI", data, 0)
        assert msg_type == CLIPRDR_MONITOR_READY
        assert data_len == 0

    def test_parse(self) -> None:
        pdu = MonitorReadyPdu.parse(b"")
        assert pdu.msg_flags == 0


class TestClipboardCapabilitiesPdu:
    """Tests for ClipboardCapabilitiesPdu."""

    def test_serialize_and_parse(self) -> None:
        pdu = ClipboardCapabilitiesPdu(general_flags=CB_USE_LONG_FORMAT_NAMES)
        data = pdu.serialize()

        # Parse the body (skip 8-byte header)
        body = data[8:]
        parsed = ClipboardCapabilitiesPdu.parse(body)
        assert parsed.general_flags == CB_USE_LONG_FORMAT_NAMES

    def test_serialize_header(self) -> None:
        pdu = ClipboardCapabilitiesPdu()
        data = pdu.serialize()
        msg_type = struct.unpack_from("<H", data, 0)[0]
        assert msg_type == CLIPRDR_CAPABILITIES


class TestTemporaryDirectoryPdu:
    """Tests for TemporaryDirectoryPdu."""

    def test_serialize(self) -> None:
        pdu = TemporaryDirectoryPdu(temp_dir="C:\\Temp")
        data = pdu.serialize()
        msg_type = struct.unpack_from("<H", data, 0)[0]
        data_len = struct.unpack_from("<I", data, 4)[0]
        assert msg_type == CLIPRDR_TEMP_DIRECTORY
        assert data_len == 520

    def test_parse(self) -> None:
        pdu = TemporaryDirectoryPdu(temp_dir="C:\\Temp")
        data = pdu.serialize()
        body = data[8:]
        parsed = TemporaryDirectoryPdu.parse(body)
        assert parsed.temp_dir == "C:\\Temp"


class TestFormatListPdu:
    """Tests for FormatListPdu."""

    def test_serialize_long_format(self) -> None:
        formats = [ClipboardFormat(format_id=CF_UNICODETEXT, format_name="")]
        pdu = FormatListPdu(formats=formats, use_long_names=True)
        data = pdu.serialize()
        msg_type = struct.unpack_from("<H", data, 0)[0]
        assert msg_type == CLIPRDR_FORMAT_LIST

    def test_parse_long_format(self) -> None:
        formats = [
            ClipboardFormat(format_id=CF_UNICODETEXT, format_name=""),
            ClipboardFormat(format_id=1, format_name="Text"),
        ]
        pdu = FormatListPdu(formats=formats, use_long_names=True)
        data = pdu.serialize()
        body = data[8:]
        parsed = FormatListPdu.parse(body, use_long_names=True)
        assert len(parsed.formats) == 2
        assert parsed.formats[0].format_id == CF_UNICODETEXT
        assert parsed.formats[1].format_id == 1
        assert parsed.formats[1].format_name == "Text"

    def test_serialize_short_format(self) -> None:
        formats = [ClipboardFormat(format_id=CF_UNICODETEXT, format_name="Unicode")]
        pdu = FormatListPdu(formats=formats, use_long_names=False)
        data = pdu.serialize()
        body = data[8:]
        # Short format: 4 bytes format_id + 32 bytes name = 36 bytes per entry
        assert len(body) == 36

    def test_parse_short_format(self) -> None:
        formats = [ClipboardFormat(format_id=CF_UNICODETEXT, format_name="Unicode")]
        pdu = FormatListPdu(formats=formats, use_long_names=False)
        data = pdu.serialize()
        body = data[8:]
        parsed = FormatListPdu.parse(body, use_long_names=False)
        assert len(parsed.formats) == 1
        assert parsed.formats[0].format_id == CF_UNICODETEXT
        assert parsed.formats[0].format_name == "Unicode"


class TestFormatDataRequestPdu:
    """Tests for FormatDataRequestPdu."""

    def test_serialize(self) -> None:
        pdu = FormatDataRequestPdu(requested_format_id=CF_UNICODETEXT)
        data = pdu.serialize()
        msg_type = struct.unpack_from("<H", data, 0)[0]
        assert msg_type == CLIPRDR_FORMAT_DATA_REQUEST
        body = data[8:]
        format_id = struct.unpack_from("<I", body, 0)[0]
        assert format_id == CF_UNICODETEXT

    def test_parse(self) -> None:
        body = struct.pack("<I", CF_UNICODETEXT)
        parsed = FormatDataRequestPdu.parse(body)
        assert parsed.requested_format_id == CF_UNICODETEXT


class TestFormatDataResponsePdu:
    """Tests for FormatDataResponsePdu."""

    def test_serialize_success(self) -> None:
        text_data = "Hello".encode("utf-16-le") + b"\x00\x00"
        pdu = FormatDataResponsePdu(data=text_data, is_success=True)
        data = pdu.serialize()
        msg_type = struct.unpack_from("<H", data, 0)[0]
        msg_flags = struct.unpack_from("<H", data, 2)[0]
        assert msg_type == CLIPRDR_FORMAT_DATA_RESPONSE
        assert msg_flags == CB_RESPONSE_OK

    def test_serialize_failure(self) -> None:
        pdu = FormatDataResponsePdu(data=b"", is_success=False)
        data = pdu.serialize()
        msg_flags = struct.unpack_from("<H", data, 2)[0]
        assert msg_flags != CB_RESPONSE_OK

    def test_parse_success(self) -> None:
        text_data = "World".encode("utf-16-le") + b"\x00\x00"
        parsed = FormatDataResponsePdu.parse(text_data, msg_flags=CB_RESPONSE_OK)
        assert parsed.is_success is True
        assert parsed.data == text_data


class TestClipboardChannel:
    """Tests for ClipboardChannel."""

    @pytest.mark.asyncio
    async def test_monitor_ready_handshake(self) -> None:
        """Monitor Ready → sends Capabilities + Temporary Directory."""
        send_fn = AsyncMock()
        channel = ClipboardChannel(send_fn)

        # Simulate server sending Monitor Ready
        monitor_ready = struct.pack("<HHI", CLIPRDR_MONITOR_READY, 0, 0)
        await channel.handle_message(monitor_ready)

        assert channel.ready is True
        assert send_fn.call_count == 2

        # First call: Capabilities PDU
        caps_data = send_fn.call_args_list[0][0][0]
        caps_type = struct.unpack_from("<H", caps_data, 0)[0]
        assert caps_type == CLIPRDR_CAPABILITIES

        # Second call: Temporary Directory PDU
        temp_data = send_fn.call_args_list[1][0][0]
        temp_type = struct.unpack_from("<H", temp_data, 0)[0]
        assert temp_type == CLIPRDR_TEMP_DIRECTORY

    @pytest.mark.asyncio
    async def test_set_clipboard_text_sends_format_list(self) -> None:
        """set_clipboard_text() sends Format List with CF_UNICODETEXT."""
        send_fn = AsyncMock()
        channel = ClipboardChannel(send_fn)

        await channel.set_clipboard_text("Hello, World!")

        send_fn.assert_called_once()
        data = send_fn.call_args[0][0]
        msg_type = struct.unpack_from("<H", data, 0)[0]
        assert msg_type == CLIPRDR_FORMAT_LIST

        # Parse the format list body
        data_len = struct.unpack_from("<I", data, 4)[0]
        body = data[8 : 8 + data_len]
        format_list = FormatListPdu.parse(body, use_long_names=True)
        assert len(format_list.formats) == 1
        assert format_list.formats[0].format_id == CF_UNICODETEXT

    @pytest.mark.asyncio
    async def test_handle_format_data_request_responds_with_text(self) -> None:
        """Format Data Request for CF_UNICODETEXT → responds with clipboard data."""
        send_fn = AsyncMock()
        channel = ClipboardChannel(send_fn)
        channel._local_clipboard_text = "Test Data"

        # Simulate Format Data Request
        body = struct.pack("<I", CF_UNICODETEXT)
        request_pdu = struct.pack("<HHI", CLIPRDR_FORMAT_DATA_REQUEST, 0, len(body)) + body
        await channel.handle_message(request_pdu)

        send_fn.assert_called_once()
        response_data = send_fn.call_args[0][0]
        msg_type = struct.unpack_from("<H", response_data, 0)[0]
        msg_flags = struct.unpack_from("<H", response_data, 2)[0]
        assert msg_type == CLIPRDR_FORMAT_DATA_RESPONSE
        assert msg_flags == CB_RESPONSE_OK

        # Verify the text content
        data_len = struct.unpack_from("<I", response_data, 4)[0]
        text_bytes = response_data[8 : 8 + data_len]
        text = text_bytes.decode("utf-16-le").rstrip("\x00")
        assert text == "Test Data"

    @pytest.mark.asyncio
    async def test_handle_server_format_list(self) -> None:
        """Server Format List → parse and store available formats."""
        send_fn = AsyncMock()
        channel = ClipboardChannel(send_fn)

        # Build a server format list with CF_UNICODETEXT
        formats = [ClipboardFormat(format_id=CF_UNICODETEXT, format_name="")]
        format_list = FormatListPdu(formats=formats, use_long_names=True)
        pdu_data = format_list.serialize()

        await channel.handle_message(pdu_data)

        # Verify formats were stored
        assert len(channel.server_formats) == 1
        assert channel.server_formats[0].format_id == CF_UNICODETEXT

        # Verify Format List Response was sent
        send_fn.assert_called_once()
        response = send_fn.call_args[0][0]
        resp_type = struct.unpack_from("<H", response, 0)[0]
        assert resp_type == CLIPRDR_FORMAT_LIST_RESPONSE

    @pytest.mark.asyncio
    async def test_get_server_clipboard_text(self) -> None:
        """get_server_clipboard_text() requests and returns text from server."""
        send_fn = AsyncMock()
        channel = ClipboardChannel(send_fn)

        # Set up server formats
        channel._server_formats = [ClipboardFormat(format_id=CF_UNICODETEXT, format_name="")]

        # Simulate the response arriving after the request
        async def simulate_response() -> None:
            await asyncio.sleep(0.01)
            text_data = "Server Text".encode("utf-16-le") + b"\x00\x00"
            response_pdu = struct.pack(
                "<HHI", CLIPRDR_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, len(text_data)
            ) + text_data
            await channel.handle_message(response_pdu)

        # Start the response simulation
        asyncio.create_task(simulate_response())

        result = await channel.get_server_clipboard_text(timeout=2.0)
        assert result == "Server Text"

        # Verify a Format Data Request was sent
        send_fn.assert_called()
        request_data = send_fn.call_args_list[0][0][0]
        msg_type = struct.unpack_from("<H", request_data, 0)[0]
        assert msg_type == CLIPRDR_FORMAT_DATA_REQUEST

    @pytest.mark.asyncio
    async def test_get_server_clipboard_text_no_formats(self) -> None:
        """get_server_clipboard_text() returns empty when no text format available."""
        send_fn = AsyncMock()
        channel = ClipboardChannel(send_fn)
        channel._server_formats = []

        result = await channel.get_server_clipboard_text()
        assert result == ""
        send_fn.assert_not_called()

    @pytest.mark.asyncio
    async def test_format_data_request_unknown_format(self) -> None:
        """Format Data Request for unknown format → responds with failure."""
        send_fn = AsyncMock()
        channel = ClipboardChannel(send_fn)

        body = struct.pack("<I", 999)  # Unknown format
        request_pdu = struct.pack("<HHI", CLIPRDR_FORMAT_DATA_REQUEST, 0, len(body)) + body
        await channel.handle_message(request_pdu)

        response_data = send_fn.call_args[0][0]
        msg_flags = struct.unpack_from("<H", response_data, 2)[0]
        # Should be failure (not CB_RESPONSE_OK)
        assert msg_flags != CB_RESPONSE_OK
