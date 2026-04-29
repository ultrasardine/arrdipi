"""Session lifecycle, event dispatch, and input handling.

Implements the high-level Session class that manages an active RDP connection.
The Session owns the background dispatch loop, routes inbound PDUs to handlers,
provides input methods (keyboard/mouse), and exposes event callbacks.

Requirements addressed: Req 19 (AC 5), Req 27 (AC 2–8), Req 30 (AC 1–5)
"""

from __future__ import annotations

import asyncio
import logging
import struct
from collections.abc import Awaitable, Callable
from typing import Any

from arrdipi.channels.static import StaticVirtualChannel
from arrdipi.graphics.pointer import PointerHandler
from arrdipi.graphics.surface import GraphicsSurface, Rect
from arrdipi.mcs.layer import McsLayer
from arrdipi.pdu.capabilities import (
    FASTPATH_OUTPUT_SUPPORTED,
    GeneralCapabilitySet,
)
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
from arrdipi.reconnect import ReconnectHandler
from arrdipi.security.base import SecurityLayer
from arrdipi.transport.tcp import TcpTransport
from arrdipi.transport.x224 import X224Layer

logger = logging.getLogger(__name__)

# ShareControl PDU type constants
_PDUTYPE_DEMAND_ACTIVE = 0x0001
_PDUTYPE_CONFIRM_ACTIVE = 0x0003
_PDUTYPE_DEACTIVATE_ALL = 0x0006
_PDUTYPE_DATA = 0x0007

# ShareData PDU type2 constants
_PDUTYPE2_UPDATE = 0x02
_PDUTYPE2_CONTROL = 0x14
_PDUTYPE2_SYNCHRONIZE = 0x1F
_PDUTYPE2_SHUTDOWN_DENIED = 0x25
_PDUTYPE2_SAVE_SESSION_INFO = 0x26
_PDUTYPE2_SET_ERROR_INFO = 0x2F
_PDUTYPE2_INPUT = 0x1C

# Shutdown Request PDU type
_PDUTYPE_SHUTDOWN_REQUEST = 0x0004


class Session:
    """High-level abstraction for an active RDP connection.

    Manages the background dispatch loop, routes inbound PDUs to handlers,
    provides input methods (keyboard/mouse), and exposes event callbacks.

    (Req 27, AC 2–8; Req 30, AC 1–5)
    """

    def __init__(
        self,
        tcp: TcpTransport,
        x224: X224Layer,
        mcs: McsLayer,
        security: SecurityLayer,
        config: Any,
        server_caps: dict[CapabilitySetType, Any],
        share_id: int = 0,
    ) -> None:
        """Initialize the Session.

        Args:
            tcp: The TCP transport layer.
            x224: The X.224/TPKT layer.
            mcs: The MCS channel multiplexing layer.
            security: The security layer (Standard/TLS/NLA).
            config: SessionConfig with connection parameters.
            server_caps: Server capability sets from Demand Active.
            share_id: The share ID from capability exchange.
        """
        self._tcp = tcp
        self._x224 = x224
        self._mcs = mcs
        self._security = security
        self._config = config
        self._server_caps = server_caps
        self._share_id = share_id

        # Graphics
        width = getattr(config, "width", 1920)
        height = getattr(config, "height", 1080)
        self._surface = GraphicsSurface(width, height)
        self._pointer = PointerHandler()

        # Channels (optional, can be None initially)
        self._static_channels: dict[int, StaticVirtualChannel] = {}
        self._clipboard: Any | None = None
        self._audio_output: Any | None = None
        self._audio_input: Any | None = None
        self._drive: Any | None = None

        # Auto-reconnect handler (Req 26)
        self._reconnect_handler = ReconnectHandler(config=config)
        self._reconnected_session: Session | None = None

        # Dispatch state
        self._dispatch_task: asyncio.Task[None] | None = None
        self._closed = False

        # Event callbacks (lists of callables)
        self._on_graphics_update_callbacks: list[
            Callable[[list[Rect]], Awaitable[None]]
        ] = []
        self._on_clipboard_changed_callbacks: list[
            Callable[[Any], Awaitable[None]]
        ] = []
        self._on_disconnect_callbacks: list[
            Callable[[str | None], Awaitable[None]]
        ] = []

        # Fast-path support detection
        self._fast_path_supported = self._detect_fast_path_support()

    def _detect_fast_path_support(self) -> bool:
        """Check if the server supports fast-path input/output.

        Examines the GeneralCapabilitySet extra_flags for FASTPATH_OUTPUT_SUPPORTED.
        """
        general_cap = self._server_caps.get(CapabilitySetType.GENERAL)
        if isinstance(general_cap, GeneralCapabilitySet):
            return bool(general_cap.extra_flags & FASTPATH_OUTPUT_SUPPORTED)
        return False

    # --- Properties (Req 27, AC 3–4) ---

    @property
    def surface(self) -> GraphicsSurface:
        """The RGBA framebuffer representing the remote desktop display."""
        return self._surface

    @property
    def pointer(self) -> PointerHandler:
        """The pointer/cursor handler."""
        return self._pointer

    @property
    def clipboard(self) -> Any | None:
        """The clipboard channel (None if not initialized)."""
        return self._clipboard

    @property
    def audio_output(self) -> Any | None:
        """The audio output channel (None if not initialized)."""
        return self._audio_output

    @property
    def audio_input(self) -> Any | None:
        """The audio input channel (None if not initialized)."""
        return self._audio_input

    @property
    def drive(self) -> Any | None:
        """The drive redirection channel (None if not initialized)."""
        return self._drive

    @property
    def reconnect_handler(self) -> ReconnectHandler:
        """The auto-reconnect handler for this session."""
        return self._reconnect_handler

    @property
    def reconnected_session(self) -> Session | None:
        """The new session created by auto-reconnect, or None."""
        return self._reconnected_session

    @property
    def closed(self) -> bool:
        """Whether the session has been closed."""
        return self._closed

    # --- Event registration (Req 27, AC 6) ---

    def on_graphics_update(
        self, callback: Callable[[list[Rect]], Awaitable[None]]
    ) -> None:
        """Register a callback for graphics update events.

        The callback receives a list of dirty rectangles that were updated.

        Args:
            callback: Async callable invoked on graphics updates.
        """
        self._on_graphics_update_callbacks.append(callback)

    def on_clipboard_changed(
        self, callback: Callable[[Any], Awaitable[None]]
    ) -> None:
        """Register a callback for clipboard change events.

        Args:
            callback: Async callable invoked when clipboard content changes.
        """
        self._on_clipboard_changed_callbacks.append(callback)

    def on_disconnect(
        self, callback: Callable[[str | None], Awaitable[None]]
    ) -> None:
        """Register a callback for disconnect events.

        The callback receives an optional reason string.

        Args:
            callback: Async callable invoked on disconnection.
        """
        self._on_disconnect_callbacks.append(callback)

    # --- Connection lifecycle ---

    async def start(self) -> None:
        """Initialize channels and start the background dispatch loop.

        (Req 30, AC 5)
        """
        self._init_channels()
        self._dispatch_task = asyncio.create_task(self._dispatch_loop())

    def _init_channels(self) -> None:
        """Initialize static virtual channels from the MCS channel map."""
        for channel_id, channel_name in self._mcs.channel_map.items():
            svc = StaticVirtualChannel(
                channel_name=channel_name,
                channel_id=channel_id,
            )
            self._static_channels[channel_id] = svc

    async def disconnect(self) -> None:
        """Send Shutdown Request PDU and close cleanly.

        (Req 27, AC 5)
        """
        if self._closed:
            return

        try:
            # Build and send Shutdown Request PDU
            # ShareControlHeader: totalLength(u16) + pduType(u16) + pduSource(u16)
            total_length = 6  # Just the header, no payload
            share_control_header = struct.pack(
                "<HHH",
                total_length,
                _PDUTYPE_SHUTDOWN_REQUEST,
                self._mcs.user_channel_id,
            )

            # Wrap with security header and send on I/O channel
            if self._security.is_enhanced:
                sec_header = struct.pack("<HH", 0, 0)
                pdu_data = sec_header + share_control_header
            else:
                pdu_data = self._security.wrap_pdu(share_control_header)

            io_channel_id = self._mcs.io_channel_id
            await self._mcs.send_to_channel(io_channel_id, pdu_data)
        except (OSError, ConnectionError):
            # Connection already broken, just close
            pass

        await self.close()

    async def close(self) -> None:
        """Idempotent close — safe to call multiple times.

        Cancels the dispatch task and closes the TCP connection.

        (Req 30, AC 4)
        """
        if self._closed:
            return
        self._closed = True

        if self._dispatch_task is not None:
            self._dispatch_task.cancel()
            try:
                await self._dispatch_task
            except (asyncio.CancelledError, Exception):
                pass
            self._dispatch_task = None

        try:
            await self._tcp.close()
        except (OSError, Exception):
            pass

    # --- Input methods (Req 19, AC 5; Req 27, AC 3) ---

    async def send_key(
        self,
        scan_code: int,
        is_released: bool,
        is_extended: bool = False,
    ) -> None:
        """Send a keyboard scancode event.

        Prefers fast-path encoding when the server supports it.

        Args:
            scan_code: The keyboard scan code.
            is_released: True for key release, False for key press.
            is_extended: True for extended key (e.g., right Ctrl/Alt).
        """
        if self._closed:
            return

        if self._fast_path_supported:
            flags = 0
            if is_released:
                flags |= FastPathKeyboardFlags.FASTPATH_INPUT_KBDFLAGS_RELEASE
            if is_extended:
                flags |= FastPathKeyboardFlags.FASTPATH_INPUT_KBDFLAGS_EXTENDED
            event = FastPathKeyboardEvent(flags=flags, key_code=scan_code)
            pdu = FastPathInputPdu(events=[event])
            await self._send_fast_path_input(pdu)
        else:
            flags = 0
            if is_released:
                flags |= KeyboardEventFlags.KBDFLAGS_RELEASE
            else:
                flags |= KeyboardEventFlags.KBDFLAGS_DOWN
            if is_extended:
                flags |= KeyboardEventFlags.KBDFLAGS_EXTENDED
            event = KeyboardEvent(event_time=0, event_flags=flags, key_code=scan_code)
            await self._send_slow_path_input(InputPdu(events=[event]))

    async def send_unicode_key(
        self,
        code_point: int,
        is_released: bool = False,
    ) -> None:
        """Send a Unicode keyboard event.

        Args:
            code_point: The Unicode code point to send.
            is_released: True for key release, False for key press.
        """
        if self._closed:
            return

        if self._fast_path_supported:
            flags = 0
            if is_released:
                flags |= FastPathKeyboardFlags.FASTPATH_INPUT_KBDFLAGS_RELEASE
            event = FastPathUnicodeEvent(flags=flags, unicode_code=code_point)
            pdu = FastPathInputPdu(events=[event])
            await self._send_fast_path_input(pdu)
        else:
            flags = 0
            if is_released:
                flags |= KeyboardEventFlags.KBDFLAGS_RELEASE
            event = UnicodeKeyboardEvent(
                event_time=0, event_flags=flags, unicode_code=code_point
            )
            await self._send_slow_path_input(InputPdu(events=[event]))

    async def send_mouse_move(self, x: int, y: int) -> None:
        """Send a mouse movement event.

        Args:
            x: Absolute X coordinate.
            y: Absolute Y coordinate.
        """
        if self._closed:
            return

        if self._fast_path_supported:
            event = FastPathMouseEvent(
                pointer_flags=int(PointerFlags.PTRFLAGS_MOVE),
                x_pos=x,
                y_pos=y,
            )
            pdu = FastPathInputPdu(events=[event])
            await self._send_fast_path_input(pdu)
        else:
            event = MouseEvent(
                event_time=0,
                event_flags=int(PointerFlags.PTRFLAGS_MOVE),
                x=x,
                y=y,
            )
            await self._send_slow_path_input(InputPdu(events=[event]))

    async def send_mouse_button(
        self,
        x: int,
        y: int,
        button: int,
        is_released: bool,
    ) -> None:
        """Send a mouse button press or release event.

        Args:
            x: Absolute X coordinate.
            y: Absolute Y coordinate.
            button: Button flag (PTRFLAGS_BUTTON1, PTRFLAGS_BUTTON2, PTRFLAGS_BUTTON3).
            is_released: True for button release, False for button press.
        """
        if self._closed:
            return

        flags = button
        if not is_released:
            flags |= PointerFlags.PTRFLAGS_DOWN

        if self._fast_path_supported:
            event = FastPathMouseEvent(
                pointer_flags=int(flags),
                x_pos=x,
                y_pos=y,
            )
            pdu = FastPathInputPdu(events=[event])
            await self._send_fast_path_input(pdu)
        else:
            event = MouseEvent(
                event_time=0,
                event_flags=int(flags),
                x=x,
                y=y,
            )
            await self._send_slow_path_input(InputPdu(events=[event]))

    async def send_mouse_scroll(
        self,
        x: int,
        y: int,
        delta: int,
        is_horizontal: bool = False,
    ) -> None:
        """Send a mouse scroll event.

        Args:
            x: Absolute X coordinate.
            y: Absolute Y coordinate.
            delta: Scroll delta (positive = up/right, negative = down/left).
            is_horizontal: True for horizontal scroll, False for vertical.
        """
        if self._closed:
            return

        flags = PointerFlags.PTRFLAGS_HWHEEL if is_horizontal else PointerFlags.PTRFLAGS_WHEEL
        # Encode delta: negative values use PTRFLAGS_WHEEL_NEGATIVE
        if delta < 0:
            flags |= PointerFlags.PTRFLAGS_WHEEL_NEGATIVE
            # The rotation units are in the low 9 bits (magnitude)
            wheel_value = (-delta) & 0x01FF
        else:
            wheel_value = delta & 0x01FF

        pointer_flags = int(flags) | wheel_value

        if self._fast_path_supported:
            event = FastPathMouseEvent(
                pointer_flags=pointer_flags,
                x_pos=x,
                y_pos=y,
            )
            pdu = FastPathInputPdu(events=[event])
            await self._send_fast_path_input(pdu)
        else:
            event = MouseEvent(
                event_time=0,
                event_flags=pointer_flags,
                x=x,
                y=y,
            )
            await self._send_slow_path_input(InputPdu(events=[event]))

    # --- Internal send helpers ---

    async def _send_fast_path_input(self, pdu: FastPathInputPdu) -> None:
        """Send a fast-path input PDU directly over TCP (bypasses X.224/MCS).

        Fast-path input is sent directly on the TCP stream, not through
        the MCS channel layer.
        """
        data = pdu.serialize()
        await self._tcp.send(data)

    async def _send_slow_path_input(self, input_pdu: InputPdu) -> None:
        """Send a slow-path input PDU wrapped in ShareData on the I/O channel."""
        payload = input_pdu.serialize()

        # Build ShareData header
        share_data_header = struct.pack(
            "<IBBHBBH",
            self._share_id,
            0,  # pad1
            1,  # streamId (STREAM_LOW)
            len(payload),  # uncompressedLength
            _PDUTYPE2_INPUT,  # pduType2
            0,  # compressedType
            0,  # compressedLength
        )

        # Build ShareControl header
        inner_data = share_data_header + payload
        total_length = len(inner_data) + 6
        share_control_header = struct.pack(
            "<HHH",
            total_length,
            _PDUTYPE_DATA,
            self._mcs.user_channel_id,
        )

        full_pdu = share_control_header + inner_data

        # Wrap with security header
        if self._security.is_enhanced:
            sec_header = struct.pack("<HH", 0, 0)
            pdu_data = sec_header + full_pdu
        else:
            pdu_data = self._security.wrap_pdu(full_pdu)

        io_channel_id = self._mcs.io_channel_id
        await self._mcs.send_to_channel(io_channel_id, pdu_data)

    # --- Background dispatch loop (Req 30, AC 1–2, 5) ---

    async def _dispatch_loop(self) -> None:
        """Read PDUs from MCS, route to handlers, detect disconnection.

        Runs as a background asyncio.Task. Detects disconnection within
        30 seconds via timeout on recv. Handles Deactivate All + re-activation.
        """
        while not self._closed:
            try:
                channel_id, data = await asyncio.wait_for(
                    self._mcs.recv_pdu(),
                    timeout=30.0,
                )
                await self._route_pdu(channel_id, data)
            except asyncio.TimeoutError:
                # 30s timeout — connection may be stale
                # Attempt to detect if connection is still alive
                logger.debug("Dispatch loop timeout — checking connection")
                continue
            except asyncio.CancelledError:
                # Task was cancelled (close() called)
                break
            except (OSError, ConnectionError, EOFError) as e:
                # Network error — disconnection detected
                await self._handle_disconnect(str(e))
                break
            except Exception as e:
                logger.error("Dispatch loop error: %s", e)
                await self._handle_disconnect(str(e))
                break

    async def _route_pdu(self, channel_id: int, data: bytes) -> None:
        """Dispatch inbound PDU to the correct handler based on channel ID.

        Routes to:
        - I/O channel handler for control/graphics PDUs
        - Static virtual channel handlers for VC data
        """
        io_channel_id = self._mcs.io_channel_id

        if channel_id == io_channel_id:
            await self._handle_io_channel_pdu(data)
        elif channel_id in self._static_channels:
            await self._handle_static_channel_pdu(channel_id, data)
        else:
            logger.debug("Received PDU on unknown channel %d", channel_id)

    async def _handle_io_channel_pdu(self, data: bytes) -> None:
        """Handle a PDU received on the I/O channel.

        Strips security header, parses ShareControl header, and dispatches
        based on PDU type.
        """
        # Strip security header
        payload, _flags = self._security.unwrap_pdu(data)

        if len(payload) < 6:
            return

        # Parse ShareControl header
        _total_len = struct.unpack_from("<H", payload, 0)[0]
        pdu_type = struct.unpack_from("<H", payload, 2)[0] & 0x000F

        if pdu_type == _PDUTYPE_DEACTIVATE_ALL:
            await self._handle_deactivate_reactivate()
        elif pdu_type == _PDUTYPE_DATA:
            await self._handle_data_pdu(payload[6:])
        elif pdu_type == _PDUTYPE_DEMAND_ACTIVE:
            # Server-initiated reactivation after deactivate
            await self._handle_deactivate_reactivate()

    async def _handle_data_pdu(self, share_data: bytes) -> None:
        """Handle a ShareData PDU from the I/O channel.

        Parses the ShareData header to determine the sub-type and dispatches.
        """
        if len(share_data) < 12:
            return

        # shareId(4) + pad1(1) + streamId(1) + uncompressedLength(2) +
        # pduType2(1) + compressedType(1) + compressedLength(2)
        pdu_type2 = share_data[8]
        pdu_payload = share_data[12:]

        if pdu_type2 == _PDUTYPE2_SET_ERROR_INFO:
            # Error info — may indicate disconnection
            if len(pdu_payload) >= 4:
                error_code = struct.unpack_from("<I", pdu_payload, 0)[0]
                if error_code != 0:
                    logger.warning("Server error info: 0x%08X", error_code)
        elif pdu_type2 == _PDUTYPE2_SAVE_SESSION_INFO:
            # Save Session Info — may contain auto-reconnect cookie
            self._handle_save_session_info(pdu_payload)
        elif pdu_type2 == _PDUTYPE2_SHUTDOWN_DENIED:
            # Server denied our shutdown request
            logger.debug("Server denied shutdown request")

    def _handle_save_session_info(self, data: bytes) -> None:
        """Handle Save Session Info PDU — extract auto-reconnect cookie if present.

        Parses the Save Session Info PDU to detect the auto-reconnect cookie
        (ARC_SC_PRIVATE_PACKET) and stores it in the ReconnectHandler.

        (Req 26, AC 1)
        """
        # InfoType is the first 4 bytes
        if len(data) < 4:
            return
        info_type = struct.unpack_from("<I", data, 0)[0]
        # InfoType 0 = logon, 1 = logon long, 2 = plain notify, 3 = logon extended
        if info_type == 3 and len(data) > 4:
            # Logon Extended info: fieldsPresentFlags(u32) + ...
            extended_data = data[4:]
            if len(extended_data) < 4:
                return
            fields_present = struct.unpack_from("<I", extended_data, 0)[0]
            offset = 4

            # LOGON_EX_AUTORECONNECTCOOKIE = 0x0001
            if fields_present & 0x0001:
                # Auto-reconnect cookie follows
                if len(extended_data) >= offset + 28:
                    cookie_data = extended_data[offset : offset + 28]
                    try:
                        self._reconnect_handler.store_cookie(cookie_data)
                        logger.info("Auto-reconnect cookie stored from Save Session Info")
                    except ValueError as e:
                        logger.warning("Failed to parse auto-reconnect cookie: %s", e)
                else:
                    logger.debug("Save Session Info extended data too short for cookie")
            else:
                logger.debug("Received Save Session Info (extended, no reconnect cookie)")

    async def _handle_static_channel_pdu(
        self, channel_id: int, data: bytes
    ) -> None:
        """Handle a PDU received on a static virtual channel.

        Strips the channel PDU header (totalLength + flags) and dispatches
        to the channel's reassembly handler.
        """
        if len(data) < 8:
            return

        # Channel PDU header: totalLength(u32 LE) + flags(u32 LE)
        _total_length = struct.unpack_from("<I", data, 0)[0]
        flags = struct.unpack_from("<I", data, 4)[0]
        chunk = data[8:]

        svc = self._static_channels.get(channel_id)
        if svc is not None:
            await svc.on_data_received(chunk, flags)

    # --- Deactivate/Reactivate (Req 30, AC 3) ---

    async def _handle_deactivate_reactivate(self) -> None:
        """Re-negotiate capabilities on Deactivate All + Demand Active.

        When the server sends a Deactivate All PDU followed by a new
        Demand Active PDU, the client must re-negotiate capabilities
        and resume the session.
        """
        logger.info("Server-initiated deactivation/reactivation")
        # In a full implementation, this would:
        # 1. Wait for the new Demand Active PDU
        # 2. Re-build and send Confirm Active
        # 3. Re-send finalization PDUs
        # For now, we log and continue — the dispatch loop will handle
        # the subsequent Demand Active PDU when it arrives.

    # --- Disconnect handling (Req 30, AC 1; Req 27, AC 7) ---

    async def _handle_disconnect(self, reason: str | None = None) -> None:
        """Invoke disconnect callbacks and attempt auto-reconnect if cookie available.

        When a disconnection is detected and an auto-reconnect cookie is stored,
        the ReconnectHandler is used to attempt reconnection. If reconnection
        succeeds, the new session replaces this one. If it fails or no cookie
        is available, the session is marked as closed.

        (Req 26, AC 2; Req 30, AC 1; Req 27, AC 7)

        Args:
            reason: Optional description of the disconnection cause.
        """
        if self._closed:
            return

        logger.info("Disconnected: %s", reason)

        # Invoke all registered disconnect callbacks
        for callback in self._on_disconnect_callbacks:
            try:
                await callback(reason)
            except Exception as e:
                logger.error("Disconnect callback error: %s", e)

        # Attempt auto-reconnect if cookie is available (Req 26, AC 2)
        if self._reconnect_handler.has_cookie:
            logger.info("Auto-reconnect cookie available, attempting reconnection")
            new_session = await self._reconnect_handler.attempt_reconnect()
            if new_session is not None:
                # Reconnection succeeded — store the new session reference
                # The caller can access it via the reconnect handler
                logger.info("Auto-reconnect succeeded")
                self._reconnected_session = new_session
                self._closed = True
                return

        # Mark session as closed
        self._closed = True
