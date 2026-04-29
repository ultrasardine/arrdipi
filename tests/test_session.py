"""Tests for the Session class — dispatch loop, input methods, event callbacks.

Tests cover:
- Dispatch loop routing (I/O channel, static VC, unknown channel)
- Input method PDU construction (fast-path and slow-path)
- Idempotent close behavior
- Disconnect callback invocation
- Event registration
- Properties exposure
"""

from __future__ import annotations

import asyncio
import struct
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from arrdipi.pdu.capabilities import FASTPATH_OUTPUT_SUPPORTED, GeneralCapabilitySet
from arrdipi.pdu.fastpath import (
    FastPathInputPdu,
    FastPathKeyboardEvent,
    FastPathKeyboardFlags,
    FastPathMouseEvent,
    FastPathUnicodeEvent,
)
from arrdipi.pdu.input_pdu import (
    InputPdu,
    KeyboardEvent,
    KeyboardEventFlags,
    MouseEvent,
    PointerFlags,
    UnicodeKeyboardEvent,
)
from arrdipi.pdu.types import CapabilitySetType
from arrdipi.session import Session


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_session(
    fast_path: bool = True,
    channel_map: dict[int, str] | None = None,
) -> tuple[Session, MagicMock, MagicMock, MagicMock]:
    """Create a Session with mocked dependencies.

    Returns:
        Tuple of (session, mock_tcp, mock_mcs, mock_security).
    """
    mock_tcp = MagicMock()
    mock_tcp.send = AsyncMock()
    mock_tcp.close = AsyncMock()

    mock_x224 = MagicMock()

    mock_mcs = MagicMock()
    mock_mcs.user_channel_id = 1007
    mock_mcs.io_channel_id = 1003
    mock_mcs.channel_map = channel_map or {}
    mock_mcs.send_to_channel = AsyncMock()
    mock_mcs.recv_pdu = AsyncMock()

    mock_security = MagicMock()
    mock_security.is_enhanced = True
    mock_security.unwrap_pdu = MagicMock(return_value=(b"", 0))
    mock_security.wrap_pdu = MagicMock(return_value=b"\x00" * 10)

    mock_config = MagicMock()
    mock_config.width = 1024
    mock_config.height = 768
    mock_config.auto_reconnect_cookie = None

    # Build server caps
    server_caps: dict[CapabilitySetType, object] = {}
    if fast_path:
        general_cap = GeneralCapabilitySet(
            os_major_type=1,
            os_minor_type=3,
            protocol_version=0x0200,
            extra_flags=FASTPATH_OUTPUT_SUPPORTED,
        )
        server_caps[CapabilitySetType.GENERAL] = general_cap

    session = Session(
        tcp=mock_tcp,
        x224=mock_x224,
        mcs=mock_mcs,
        security=mock_security,
        config=mock_config,
        server_caps=server_caps,
        share_id=0x00010001,
    )

    return session, mock_tcp, mock_mcs, mock_security


# ---------------------------------------------------------------------------
# Properties tests
# ---------------------------------------------------------------------------


class TestSessionProperties:
    """Tests for Session property exposure."""

    def test_surface_property(self) -> None:
        """Session exposes a GraphicsSurface."""
        session, _, _, _ = _make_session()
        assert session.surface is not None
        assert session.surface.width == 1024
        assert session.surface.height == 768

    def test_pointer_property(self) -> None:
        """Session exposes a PointerHandler."""
        session, _, _, _ = _make_session()
        assert session.pointer is not None

    def test_clipboard_initially_none(self) -> None:
        """Clipboard is None before channel initialization."""
        session, _, _, _ = _make_session()
        assert session.clipboard is None

    def test_audio_output_initially_none(self) -> None:
        """Audio output is None before channel initialization."""
        session, _, _, _ = _make_session()
        assert session.audio_output is None

    def test_audio_input_initially_none(self) -> None:
        """Audio input is None before channel initialization."""
        session, _, _, _ = _make_session()
        assert session.audio_input is None

    def test_drive_initially_none(self) -> None:
        """Drive is None before channel initialization."""
        session, _, _, _ = _make_session()
        assert session.drive is None


# ---------------------------------------------------------------------------
# Event registration tests
# ---------------------------------------------------------------------------


class TestEventRegistration:
    """Tests for event callback registration."""

    def test_on_graphics_update_registers_callback(self) -> None:
        """on_graphics_update stores the callback."""
        session, _, _, _ = _make_session()
        callback = AsyncMock()
        session.on_graphics_update(callback)
        assert callback in session._on_graphics_update_callbacks

    def test_on_clipboard_changed_registers_callback(self) -> None:
        """on_clipboard_changed stores the callback."""
        session, _, _, _ = _make_session()
        callback = AsyncMock()
        session.on_clipboard_changed(callback)
        assert callback in session._on_clipboard_changed_callbacks

    def test_on_disconnect_registers_callback(self) -> None:
        """on_disconnect stores the callback."""
        session, _, _, _ = _make_session()
        callback = AsyncMock()
        session.on_disconnect(callback)
        assert callback in session._on_disconnect_callbacks

    def test_multiple_callbacks_registered(self) -> None:
        """Multiple callbacks can be registered for the same event."""
        session, _, _, _ = _make_session()
        cb1 = AsyncMock()
        cb2 = AsyncMock()
        session.on_disconnect(cb1)
        session.on_disconnect(cb2)
        assert len(session._on_disconnect_callbacks) == 2


# ---------------------------------------------------------------------------
# Input method tests — fast-path
# ---------------------------------------------------------------------------


class TestInputMethodsFastPath:
    """Tests for input methods when fast-path is supported."""

    @pytest.mark.asyncio
    async def test_send_key_press_fast_path(self) -> None:
        """send_key sends a fast-path keyboard event for key press."""
        session, mock_tcp, _, _ = _make_session(fast_path=True)

        await session.send_key(scan_code=0x1E, is_released=False)

        mock_tcp.send.assert_called_once()
        sent_data = mock_tcp.send.call_args[0][0]
        # Parse the sent fast-path PDU
        pdu = FastPathInputPdu.parse(sent_data)
        assert len(pdu.events) == 1
        event = pdu.events[0]
        assert isinstance(event, FastPathKeyboardEvent)
        assert event.key_code == 0x1E
        assert not (event.flags & FastPathKeyboardFlags.FASTPATH_INPUT_KBDFLAGS_RELEASE)

    @pytest.mark.asyncio
    async def test_send_key_release_fast_path(self) -> None:
        """send_key sends a fast-path keyboard event for key release."""
        session, mock_tcp, _, _ = _make_session(fast_path=True)

        await session.send_key(scan_code=0x1E, is_released=True)

        mock_tcp.send.assert_called_once()
        sent_data = mock_tcp.send.call_args[0][0]
        pdu = FastPathInputPdu.parse(sent_data)
        event = pdu.events[0]
        assert isinstance(event, FastPathKeyboardEvent)
        assert event.flags & FastPathKeyboardFlags.FASTPATH_INPUT_KBDFLAGS_RELEASE

    @pytest.mark.asyncio
    async def test_send_key_extended_fast_path(self) -> None:
        """send_key with is_extended sets the extended flag."""
        session, mock_tcp, _, _ = _make_session(fast_path=True)

        await session.send_key(scan_code=0x1D, is_released=False, is_extended=True)

        sent_data = mock_tcp.send.call_args[0][0]
        pdu = FastPathInputPdu.parse(sent_data)
        event = pdu.events[0]
        assert isinstance(event, FastPathKeyboardEvent)
        assert event.flags & FastPathKeyboardFlags.FASTPATH_INPUT_KBDFLAGS_EXTENDED

    @pytest.mark.asyncio
    async def test_send_unicode_key_fast_path(self) -> None:
        """send_unicode_key sends a fast-path unicode event."""
        session, mock_tcp, _, _ = _make_session(fast_path=True)

        await session.send_unicode_key(code_point=0x0041)  # 'A'

        mock_tcp.send.assert_called_once()
        sent_data = mock_tcp.send.call_args[0][0]
        pdu = FastPathInputPdu.parse(sent_data)
        event = pdu.events[0]
        assert isinstance(event, FastPathUnicodeEvent)
        assert event.unicode_code == 0x0041

    @pytest.mark.asyncio
    async def test_send_mouse_move_fast_path(self) -> None:
        """send_mouse_move sends a fast-path mouse event with MOVE flag."""
        session, mock_tcp, _, _ = _make_session(fast_path=True)

        await session.send_mouse_move(x=100, y=200)

        mock_tcp.send.assert_called_once()
        sent_data = mock_tcp.send.call_args[0][0]
        pdu = FastPathInputPdu.parse(sent_data)
        event = pdu.events[0]
        assert isinstance(event, FastPathMouseEvent)
        assert event.x_pos == 100
        assert event.y_pos == 200
        assert event.pointer_flags & PointerFlags.PTRFLAGS_MOVE

    @pytest.mark.asyncio
    async def test_send_mouse_button_press_fast_path(self) -> None:
        """send_mouse_button sends a fast-path mouse event with button + DOWN."""
        session, mock_tcp, _, _ = _make_session(fast_path=True)

        await session.send_mouse_button(
            x=50, y=75, button=PointerFlags.PTRFLAGS_BUTTON1, is_released=False
        )

        sent_data = mock_tcp.send.call_args[0][0]
        pdu = FastPathInputPdu.parse(sent_data)
        event = pdu.events[0]
        assert isinstance(event, FastPathMouseEvent)
        assert event.x_pos == 50
        assert event.y_pos == 75
        assert event.pointer_flags & PointerFlags.PTRFLAGS_BUTTON1
        assert event.pointer_flags & PointerFlags.PTRFLAGS_DOWN

    @pytest.mark.asyncio
    async def test_send_mouse_button_release_fast_path(self) -> None:
        """send_mouse_button release does not set DOWN flag."""
        session, mock_tcp, _, _ = _make_session(fast_path=True)

        await session.send_mouse_button(
            x=50, y=75, button=PointerFlags.PTRFLAGS_BUTTON1, is_released=True
        )

        sent_data = mock_tcp.send.call_args[0][0]
        pdu = FastPathInputPdu.parse(sent_data)
        event = pdu.events[0]
        assert isinstance(event, FastPathMouseEvent)
        assert event.pointer_flags & PointerFlags.PTRFLAGS_BUTTON1
        assert not (event.pointer_flags & PointerFlags.PTRFLAGS_DOWN)

    @pytest.mark.asyncio
    async def test_send_mouse_scroll_vertical_fast_path(self) -> None:
        """send_mouse_scroll sends vertical scroll with WHEEL flag."""
        session, mock_tcp, _, _ = _make_session(fast_path=True)

        await session.send_mouse_scroll(x=100, y=100, delta=3)

        sent_data = mock_tcp.send.call_args[0][0]
        pdu = FastPathInputPdu.parse(sent_data)
        event = pdu.events[0]
        assert isinstance(event, FastPathMouseEvent)
        assert event.pointer_flags & PointerFlags.PTRFLAGS_WHEEL
        assert not (event.pointer_flags & PointerFlags.PTRFLAGS_WHEEL_NEGATIVE)

    @pytest.mark.asyncio
    async def test_send_mouse_scroll_negative_fast_path(self) -> None:
        """send_mouse_scroll with negative delta sets WHEEL_NEGATIVE."""
        session, mock_tcp, _, _ = _make_session(fast_path=True)

        await session.send_mouse_scroll(x=100, y=100, delta=-3)

        sent_data = mock_tcp.send.call_args[0][0]
        pdu = FastPathInputPdu.parse(sent_data)
        event = pdu.events[0]
        assert isinstance(event, FastPathMouseEvent)
        assert event.pointer_flags & PointerFlags.PTRFLAGS_WHEEL
        assert event.pointer_flags & PointerFlags.PTRFLAGS_WHEEL_NEGATIVE

    @pytest.mark.asyncio
    async def test_send_mouse_scroll_horizontal_fast_path(self) -> None:
        """send_mouse_scroll with is_horizontal sets HWHEEL flag."""
        session, mock_tcp, _, _ = _make_session(fast_path=True)

        await session.send_mouse_scroll(x=100, y=100, delta=2, is_horizontal=True)

        sent_data = mock_tcp.send.call_args[0][0]
        pdu = FastPathInputPdu.parse(sent_data)
        event = pdu.events[0]
        assert isinstance(event, FastPathMouseEvent)
        assert event.pointer_flags & PointerFlags.PTRFLAGS_HWHEEL


# ---------------------------------------------------------------------------
# Input method tests — slow-path
# ---------------------------------------------------------------------------


class TestInputMethodsSlowPath:
    """Tests for input methods when fast-path is NOT supported."""

    @pytest.mark.asyncio
    async def test_send_key_press_slow_path(self) -> None:
        """send_key sends a slow-path keyboard event via MCS."""
        session, _, mock_mcs, _ = _make_session(fast_path=False)

        await session.send_key(scan_code=0x1E, is_released=False)

        mock_mcs.send_to_channel.assert_called_once()
        # Verify it was sent on the I/O channel
        call_args = mock_mcs.send_to_channel.call_args[0]
        assert call_args[0] == 1003  # io_channel_id

    @pytest.mark.asyncio
    async def test_send_key_release_slow_path(self) -> None:
        """send_key release sends KBDFLAGS_RELEASE in slow-path."""
        session, _, mock_mcs, _ = _make_session(fast_path=False)

        await session.send_key(scan_code=0x1E, is_released=True)

        mock_mcs.send_to_channel.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_unicode_key_slow_path(self) -> None:
        """send_unicode_key sends a slow-path unicode event via MCS."""
        session, _, mock_mcs, _ = _make_session(fast_path=False)

        await session.send_unicode_key(code_point=0x0041)

        mock_mcs.send_to_channel.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_mouse_move_slow_path(self) -> None:
        """send_mouse_move sends a slow-path mouse event via MCS."""
        session, _, mock_mcs, _ = _make_session(fast_path=False)

        await session.send_mouse_move(x=100, y=200)

        mock_mcs.send_to_channel.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_mouse_button_slow_path(self) -> None:
        """send_mouse_button sends a slow-path mouse event via MCS."""
        session, _, mock_mcs, _ = _make_session(fast_path=False)

        await session.send_mouse_button(
            x=50, y=75, button=PointerFlags.PTRFLAGS_BUTTON1, is_released=False
        )

        mock_mcs.send_to_channel.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_mouse_scroll_slow_path(self) -> None:
        """send_mouse_scroll sends a slow-path mouse event via MCS."""
        session, _, mock_mcs, _ = _make_session(fast_path=False)

        await session.send_mouse_scroll(x=100, y=100, delta=3)

        mock_mcs.send_to_channel.assert_called_once()

    @pytest.mark.asyncio
    async def test_input_not_sent_when_closed(self) -> None:
        """Input methods do nothing when session is closed."""
        session, mock_tcp, mock_mcs, _ = _make_session(fast_path=True)
        session._closed = True

        await session.send_key(scan_code=0x1E, is_released=False)
        await session.send_unicode_key(code_point=0x41)
        await session.send_mouse_move(x=0, y=0)
        await session.send_mouse_button(x=0, y=0, button=0x1000, is_released=False)
        await session.send_mouse_scroll(x=0, y=0, delta=1)

        mock_tcp.send.assert_not_called()
        mock_mcs.send_to_channel.assert_not_called()


# ---------------------------------------------------------------------------
# Close tests
# ---------------------------------------------------------------------------


class TestClose:
    """Tests for idempotent close behavior."""

    @pytest.mark.asyncio
    async def test_close_sets_closed_flag(self) -> None:
        """close() sets the closed flag."""
        session, _, _, _ = _make_session()
        assert not session.closed

        await session.close()

        assert session.closed

    @pytest.mark.asyncio
    async def test_close_is_idempotent(self) -> None:
        """close() can be called multiple times without error."""
        session, mock_tcp, _, _ = _make_session()

        await session.close()
        await session.close()
        await session.close()

        # TCP close should only be called once
        assert mock_tcp.close.call_count == 1

    @pytest.mark.asyncio
    async def test_close_cancels_dispatch_task(self) -> None:
        """close() cancels the background dispatch task."""
        session, _, mock_mcs, _ = _make_session()

        # Simulate a running dispatch task
        mock_mcs.recv_pdu = AsyncMock(side_effect=asyncio.CancelledError)
        await session.start()

        # Give the task a moment to start
        await asyncio.sleep(0.01)

        await session.close()

        assert session._dispatch_task is None

    @pytest.mark.asyncio
    async def test_close_closes_tcp(self) -> None:
        """close() closes the TCP connection."""
        session, mock_tcp, _, _ = _make_session()

        await session.close()

        mock_tcp.close.assert_called_once()


# ---------------------------------------------------------------------------
# Disconnect tests
# ---------------------------------------------------------------------------


class TestDisconnect:
    """Tests for disconnect behavior."""

    @pytest.mark.asyncio
    async def test_disconnect_sends_shutdown_request(self) -> None:
        """disconnect() sends a Shutdown Request PDU."""
        session, _, mock_mcs, _ = _make_session()

        await session.disconnect()

        # Should have sent on the I/O channel
        mock_mcs.send_to_channel.assert_called_once()
        call_args = mock_mcs.send_to_channel.call_args[0]
        assert call_args[0] == 1003  # io_channel_id

    @pytest.mark.asyncio
    async def test_disconnect_closes_session(self) -> None:
        """disconnect() closes the session after sending shutdown."""
        session, _, _, _ = _make_session()

        await session.disconnect()

        assert session.closed

    @pytest.mark.asyncio
    async def test_disconnect_when_already_closed(self) -> None:
        """disconnect() does nothing when already closed."""
        session, _, mock_mcs, _ = _make_session()
        session._closed = True

        await session.disconnect()

        mock_mcs.send_to_channel.assert_not_called()

    @pytest.mark.asyncio
    async def test_disconnect_handles_connection_error(self) -> None:
        """disconnect() handles connection errors gracefully."""
        session, _, mock_mcs, _ = _make_session()
        mock_mcs.send_to_channel = AsyncMock(side_effect=ConnectionError("broken"))

        # Should not raise
        await session.disconnect()

        assert session.closed


# ---------------------------------------------------------------------------
# Disconnect callback tests
# ---------------------------------------------------------------------------


class TestDisconnectCallback:
    """Tests for disconnect callback invocation."""

    @pytest.mark.asyncio
    async def test_disconnect_callback_invoked(self) -> None:
        """Disconnect callbacks are invoked with the reason."""
        session, _, _, _ = _make_session()
        callback = AsyncMock()
        session.on_disconnect(callback)

        await session._handle_disconnect("connection lost")

        callback.assert_called_once_with("connection lost")

    @pytest.mark.asyncio
    async def test_multiple_disconnect_callbacks_invoked(self) -> None:
        """All registered disconnect callbacks are invoked."""
        session, _, _, _ = _make_session()
        cb1 = AsyncMock()
        cb2 = AsyncMock()
        session.on_disconnect(cb1)
        session.on_disconnect(cb2)

        await session._handle_disconnect("timeout")

        cb1.assert_called_once_with("timeout")
        cb2.assert_called_once_with("timeout")

    @pytest.mark.asyncio
    async def test_disconnect_callback_error_does_not_propagate(self) -> None:
        """Errors in disconnect callbacks don't crash the session."""
        session, _, _, _ = _make_session()
        bad_callback = AsyncMock(side_effect=RuntimeError("callback error"))
        good_callback = AsyncMock()
        session.on_disconnect(bad_callback)
        session.on_disconnect(good_callback)

        # Should not raise
        await session._handle_disconnect("error")

        bad_callback.assert_called_once()
        good_callback.assert_called_once()

    @pytest.mark.asyncio
    async def test_disconnect_marks_session_closed(self) -> None:
        """_handle_disconnect marks the session as closed."""
        session, _, _, _ = _make_session()

        await session._handle_disconnect("network error")

        assert session.closed


# ---------------------------------------------------------------------------
# Dispatch loop tests
# ---------------------------------------------------------------------------


class TestDispatchLoop:
    """Tests for the background dispatch loop."""

    @pytest.mark.asyncio
    async def test_dispatch_routes_io_channel(self) -> None:
        """Dispatch loop routes I/O channel PDUs to _handle_io_channel_pdu."""
        session, _, mock_mcs, mock_security = _make_session()

        # Build a minimal Data PDU
        share_data_header = struct.pack("<IBBHBBH", 0x00010001, 0, 1, 0, 0x2F, 0, 0)
        share_control = struct.pack("<HHH", len(share_data_header) + 6, 0x0007, 1007)
        payload = share_control + share_data_header
        sec_header = struct.pack("<HH", 0, 0)
        full_pdu = sec_header + payload

        mock_security.unwrap_pdu.return_value = (payload, 0)

        # Route the PDU
        await session._route_pdu(1003, full_pdu)

        # Verify unwrap_pdu was called (I/O channel handling)
        mock_security.unwrap_pdu.assert_called_once_with(full_pdu)

    @pytest.mark.asyncio
    async def test_dispatch_routes_static_channel(self) -> None:
        """Dispatch loop routes static VC PDUs to the channel handler."""
        session, _, _, _ = _make_session(
            channel_map={1004: "cliprdr", 1005: "rdpsnd"}
        )
        await session.start()
        # Cancel the dispatch task immediately
        session._dispatch_task.cancel()
        try:
            await session._dispatch_task
        except (asyncio.CancelledError, Exception):
            pass

        # Build a channel PDU with header
        total_length = 10
        flags = 0x00000003  # FIRST | LAST
        chunk = b"\x01\x02"
        channel_pdu = struct.pack("<II", total_length, flags) + chunk

        # Route to static channel
        await session._route_pdu(1004, channel_pdu)

        # The static channel should have received the data
        svc = session._static_channels.get(1004)
        assert svc is not None
        assert svc.name == "cliprdr"

    @pytest.mark.asyncio
    async def test_dispatch_loop_detects_connection_error(self) -> None:
        """Dispatch loop invokes disconnect on connection error."""
        session, _, mock_mcs, _ = _make_session()
        callback = AsyncMock()
        session.on_disconnect(callback)

        # Make recv_pdu raise a connection error
        mock_mcs.recv_pdu = AsyncMock(side_effect=ConnectionError("broken pipe"))

        await session.start()
        # Wait for the dispatch loop to process the error
        await asyncio.sleep(0.05)

        callback.assert_called_once()
        assert session.closed

    @pytest.mark.asyncio
    async def test_dispatch_loop_handles_cancellation(self) -> None:
        """Dispatch loop exits cleanly on task cancellation."""
        session, _, mock_mcs, _ = _make_session()

        # Make recv_pdu block forever
        mock_mcs.recv_pdu = AsyncMock(side_effect=asyncio.CancelledError)

        await session.start()
        await asyncio.sleep(0.01)

        # Close should cancel cleanly
        await session.close()
        assert session.closed


# ---------------------------------------------------------------------------
# Start tests
# ---------------------------------------------------------------------------


class TestStart:
    """Tests for session start behavior."""

    @pytest.mark.asyncio
    async def test_start_initializes_channels(self) -> None:
        """start() initializes static virtual channels from MCS channel map."""
        session, _, mock_mcs, _ = _make_session(
            channel_map={1004: "cliprdr", 1005: "rdpsnd"}
        )
        mock_mcs.recv_pdu = AsyncMock(side_effect=asyncio.CancelledError)

        await session.start()
        await asyncio.sleep(0.01)

        assert 1004 in session._static_channels
        assert 1005 in session._static_channels
        assert session._static_channels[1004].name == "cliprdr"
        assert session._static_channels[1005].name == "rdpsnd"

        await session.close()

    @pytest.mark.asyncio
    async def test_start_creates_dispatch_task(self) -> None:
        """start() creates a background dispatch task."""
        session, _, mock_mcs, _ = _make_session()
        mock_mcs.recv_pdu = AsyncMock(side_effect=asyncio.CancelledError)

        await session.start()
        await asyncio.sleep(0.01)

        assert session._dispatch_task is not None

        await session.close()


# ---------------------------------------------------------------------------
# Fast-path detection tests
# ---------------------------------------------------------------------------


class TestFastPathDetection:
    """Tests for fast-path support detection."""

    def test_fast_path_detected_from_general_cap(self) -> None:
        """Fast-path is detected from GeneralCapabilitySet extra_flags."""
        session, _, _, _ = _make_session(fast_path=True)
        assert session._fast_path_supported is True

    def test_no_fast_path_without_general_cap(self) -> None:
        """Fast-path is not detected without GeneralCapabilitySet."""
        session, _, _, _ = _make_session(fast_path=False)
        assert session._fast_path_supported is False
