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

from arrdipi.channels.audio_input import AudioInputChannel
from arrdipi.channels.audio_output import AudioOutputChannel
from arrdipi.channels.clipboard import CLIPRDR_FORMAT_LIST, ClipboardChannel
from arrdipi.channels.dynamic import DrdynvcHandler
from arrdipi.channels.static import StaticVirtualChannel
from arrdipi.codec.mppc import MppcDecompressor
from arrdipi.codec.rdp6_bitmap import Rdp6BitmapCodec
from arrdipi.codec.rle import RleCodec
from arrdipi.errors import CodecError, MppcDecompressError, PduParseError, RleDecodeError
from arrdipi.pdu.base import ByteReader
from arrdipi.graphics.gdi import GdiOrderProcessor
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
    FastPathOutputFragmentation,
    FastPathOutputPdu,
    FastPathOutputUpdateCode,
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
from arrdipi.pdu.pointer_pdu import (
    CachedPointerUpdate,
    ColorPointerUpdate,
    LargePointerUpdate,
    NewPointerUpdate,
    PointerPositionUpdate,
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
        self._gdi = GdiOrderProcessor(self._surface)
        self._pointer = PointerHandler()
        self._mppc = MppcDecompressor()

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

        # Fragment reassembly (Req 6)
        self._fragment_buffers: dict[int, bytearray] = {}
        self._max_request_size: int = 262144  # 256 KB — matches TS_MULTIFRAGMENTUPDATE_CAPABILITYSET

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

    # --- Fragment reassembly (Req 6, AC 1–8) ---

    def _reassemble_fragment(
        self, update_code: int, fragmentation: int, data: bytes
    ) -> bytes | None:
        """Accumulate a fragmented fast-path update.

        Handles the four fragmentation states per [MS-RDPBCGR] 2.2.9.1.2.1:
        - SINGLE (0x00): return data as-is (complete update).
        - FIRST (0x02): start a new accumulation buffer.
        - NEXT (0x03): append to the existing buffer.
        - LAST (0x01): complete and return reassembled bytes.

        Returns:
            The complete reassembled data when LAST fragment arrives,
            the original data for SINGLE, or None if still accumulating.
        """
        from arrdipi.pdu.fastpath import FastPathOutputFragmentation

        if fragmentation == FastPathOutputFragmentation.FASTPATH_FRAGMENT_FIRST:
            if update_code in self._fragment_buffers:
                logger.warning(
                    "Discarding incomplete fragment buffer for update 0x%02X",
                    update_code,
                )
            self._fragment_buffers[update_code] = bytearray(data)
            return None

        elif fragmentation == FastPathOutputFragmentation.FASTPATH_FRAGMENT_NEXT:
            buf = self._fragment_buffers.get(update_code)
            if buf is None:
                logger.error(
                    "NEXT fragment without FIRST for update 0x%02X", update_code
                )
                return None
            buf.extend(data)
            if len(buf) > self._max_request_size:
                logger.error(
                    "Fragment buffer exceeds MaxRequestSize for update 0x%02X",
                    update_code,
                )
                del self._fragment_buffers[update_code]
                return None
            return None

        elif fragmentation == FastPathOutputFragmentation.FASTPATH_FRAGMENT_LAST:
            buf = self._fragment_buffers.pop(update_code, None)
            if buf is None:
                logger.error(
                    "LAST fragment without preceding FIRST for update 0x%02X",
                    update_code,
                )
                return None
            buf.extend(data)
            return bytes(buf)

        # SINGLE — return data directly
        return data

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
        logger.info("_init_channels: channel_map=%s", self._mcs.channel_map)
        for channel_id, channel_name in self._mcs.channel_map.items():
            svc = StaticVirtualChannel(
                channel_name=channel_name,
                channel_id=channel_id,
            )
            if channel_name == "cliprdr":
                async def _cliprdr_send(data: bytes, svc: StaticVirtualChannel = svc) -> None:
                    logger.debug("CLIPRDR send: len=%d hex=%s", len(data), data[:16].hex())
                    await svc.send(self._mcs, data)
                clipboard = ClipboardChannel(send_fn=_cliprdr_send)
                svc.register_handler(self._make_clipboard_handler(clipboard))
                self._clipboard = clipboard
            elif channel_name == "rdpsnd":
                audio_output = AudioOutputChannel(
                    send_fn=lambda data, svc=svc: svc.send(self._mcs, data)
                )
                svc.register_handler(audio_output.handle_message)
                self._audio_output = audio_output
            elif channel_name == "rdpdr":
                from arrdipi.channels.drive import DriveChannel
                drive = DriveChannel(
                    send_fn=lambda data, svc=svc: svc.send(self._mcs, data),
                    drives=getattr(self._config, "drive_paths", []),
                )
                svc.register_handler(drive.handle_message)
                self._drive = drive
            elif channel_name == "drdynvc":
                drdynvc = DrdynvcHandler(
                    send_fn=lambda data, svc=svc: svc.send(self._mcs, data)
                )

                def _make_audin_send(dvc: DrdynvcHandler, static_svc: StaticVirtualChannel) -> Callable[[bytes], Awaitable[None]]:
                    async def _send(data: bytes) -> None:
                        from arrdipi.channels.dynamic import DynvcData
                        for ch in dvc.channels.values():
                            if ch.channel_name == "AUDIO_INPUT":
                                pdu = DynvcData(channel_id=ch.channel_id, data=data)
                                await static_svc.send(self._mcs, pdu.serialize())
                                return
                    return _send

                audio_input = AudioInputChannel(send_fn=_make_audin_send(drdynvc, svc))
                drdynvc.register_channel_factory("AUDIO_INPUT", audio_input.create_handler)
                self._audio_input = audio_input
                svc.register_handler(drdynvc.handle_message)
            self._static_channels[channel_id] = svc

    def _make_clipboard_handler(
        self, clipboard: ClipboardChannel
    ) -> Callable[[bytes], Awaitable[None]]:
        """Create static-channel handler for CLIPRDR messages."""

        async def _handle_clipboard_message(data: bytes) -> None:
            msg_type = struct.unpack_from("<H", data, 0)[0] if len(data) >= 2 else None
            await clipboard.handle_message(data)

            if msg_type == CLIPRDR_FORMAT_LIST:
                for callback in self._on_clipboard_changed_callbacks:
                    try:
                        await callback(clipboard.server_formats)
                    except Exception:
                        logger.exception("Clipboard callback failed")

        return _handle_clipboard_message

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

    # --- Fast-path output handling (Req 3, AC 1–10; Req 8, AC 1, 3, 5; Req 9, AC 3) ---

    async def _handle_fast_path_output(self, data: bytes) -> None:
        """Parse and dispatch fast-path output PDU updates.

        Applies MPPC decompression and fragment reassembly before routing
        each update to its type-specific handler.

        Args:
            data: Raw fast-path output PDU bytes (including header).
        """
        try:
            pdu = FastPathOutputPdu.parse(data)
        except PduParseError as exc:
            logger.error(
                "FastPath parse error: %s | hex: %s", exc, data[:32].hex()
            )
            return

        for update in pdu.updates:
            # Step 1: MPPC bulk decompression if compression bit is set
            update_data = update.data
            if update.compression:
                try:
                    update_data = self._mppc.decompress(
                        update.compression_flags, update_data
                    )
                except MppcDecompressError as exc:
                    logger.error(
                        "MPPC decompress failed for update 0x%02X: %s",
                        update.update_code,
                        exc,
                    )
                    continue

            # Step 2: Fragment reassembly
            if update.fragmentation != FastPathOutputFragmentation.FASTPATH_FRAGMENT_SINGLE:
                update_data = self._reassemble_fragment(
                    update.update_code, update.fragmentation, update_data
                )
                if update_data is None:
                    continue

            # Step 3: Dispatch by update type
            match update.update_code:
                case FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_BITMAP:
                    await self._process_bitmap_update(update_data)
                case FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_ORDERS:
                    await self._process_orders_update(update_data)
                case FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_SYNCHRONIZE:
                    pass  # No action needed
                case FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_PTR_NULL:
                    self._pointer.handle_system_pointer(0x0000)
                case FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_PTR_DEFAULT:
                    self._pointer.handle_system_pointer(0x7F00)
                case FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_PTR_POSITION:
                    pos = PointerPositionUpdate.parse(update_data)
                    self._pointer.handle_position_update(pos.x, pos.y)
                case FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_COLOR:
                    color_ptr = ColorPointerUpdate.parse(update_data)
                    self._pointer.handle_color_pointer(color_ptr)
                case FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_CACHED:
                    cached_ptr = CachedPointerUpdate.parse(update_data)
                    self._pointer.handle_cached_pointer(cached_ptr.cache_index)
                case FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_POINTER:
                    new_ptr = NewPointerUpdate.parse(update_data)
                    self._pointer.handle_new_pointer(new_ptr)
                case FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_LARGE_POINTER:
                    large_ptr = LargePointerUpdate.parse(update_data)
                    self._pointer.handle_large_pointer(large_ptr)
                case (
                    FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_PALETTE
                    | FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_SURFCMDS
                ):
                    logger.info(
                        "Unimplemented fast-path update: 0x%02X",
                        update.update_code,
                    )
                case _:
                    logger.debug(
                        "Unknown fast-path update: 0x%02X", update.update_code
                    )

        # Dispatch dirty rects to registered callbacks
        dirty = self._surface.get_dirty_rects()
        if dirty:
            for cb in self._on_graphics_update_callbacks:
                try:
                    await cb(dirty)
                except Exception:
                    logger.exception("Graphics update callback failed")

    async def _process_bitmap_update(self, data: bytes) -> None:
        """Process a FASTPATH_UPDATETYPE_BITMAP update.

        Parses TS_UPDATE_BITMAP_DATA per [MS-RDPBCGR] 2.2.9.1.1.3.1.2 and
        feeds each TS_BITMAP_DATA rect through the appropriate decompressor.

        Handles:
        - Compressed < 32 bpp via Interleaved RLE (RleCodec)
        - Compressed 32 bpp via RDP 6.0 Bitmap Compression (Rdp6BitmapCodec)
        - Optional bitmapComprHdr (TS_CD_HEADER, 8 bytes) when BITMAP_COMPRESSION
          is set and NO_BITMAP_COMPRESSION_HDR is NOT set
        - Uncompressed bitmap data (bottom-up, row-padded)

        Individual decompression failures skip the failed rect with a warning
        and continue processing remaining rects.

        (Req 4, AC 1–9; Req 8, AC 2, 7)
        """
        # Flag constants per [MS-RDPBCGR] 2.2.9.1.1.3.1.2.2
        BITMAP_COMPRESSION = 0x0001
        NO_BITMAP_COMPRESSION_HDR = 0x0400

        def _can_parse_bitmap_rects(payload: bytes) -> bool:
            """Validate payload shape: u16 rect count + TS_BITMAP_DATA entries."""
            if len(payload) < 2:
                return False

            num = struct.unpack_from("<H", payload, 0)[0]
            if num == 0:
                return False

            offset = 2
            for _ in range(num):
                if offset + 18 > len(payload):
                    return False
                bitmap_length = struct.unpack_from("<H", payload, offset + 16)[0]
                offset += 18
                if offset + bitmap_length > len(payload):
                    return False
                offset += bitmap_length
            return True

        # Some servers include an UpdateType(u16=0x0001) prefix before
        # numberRectangles. Detect and strip it so field alignment stays correct.
        if len(data) >= 4 and struct.unpack_from("<H", data, 0)[0] == 0x0001:
            raw_ok = _can_parse_bitmap_rects(data)
            shifted_ok = _can_parse_bitmap_rects(data[2:])
            if shifted_ok and not raw_ok:
                data = data[2:]
            elif shifted_ok and raw_ok and len(data) >= 18:
                bpp_raw = struct.unpack_from("<H", data, 14)[0]
                bpp_shifted = struct.unpack_from("<H", data, 16)[0]
                supported_bpp = {8, 15, 16, 24, 32}
                if bpp_raw not in supported_bpp and bpp_shifted in supported_bpp:
                    data = data[2:]

        reader = ByteReader(data, "BitmapUpdate")
        num_rects = reader.read_u16_le()

        for i in range(num_rects):
            try:
                dest_left = reader.read_u16_le()
                dest_top = reader.read_u16_le()
                dest_right = reader.read_u16_le()
                dest_bottom = reader.read_u16_le()
                width = reader.read_u16_le()
                height = reader.read_u16_le()
                bpp = reader.read_u16_le()
                flags = reader.read_u16_le()
                bitmap_length = reader.read_u16_le()
                bitmap_data = reader.read_bytes(bitmap_length)

                compressed = bool(flags & BITMAP_COMPRESSION)

                if compressed:
                    # Handle optional bitmapComprHdr (TS_CD_HEADER, 8 bytes)
                    if not (flags & NO_BITMAP_COMPRESSION_HDR):
                        bitmap_data = bitmap_data[8:]

                    if bpp == 32:
                        rgba = Rdp6BitmapCodec.decompress(bitmap_data, width, height)
                    else:
                        rgba = RleCodec.decompress(
                            bitmap_data, width, height, bpp,
                            compressed=True, rect_index=i,
                        )
                else:
                    rgba = RleCodec.decompress(
                        bitmap_data, width, height, bpp,
                        compressed=False, rect_index=i,
                    )

                w = dest_right - dest_left + 1
                h = dest_bottom - dest_top + 1
                await self._surface.write_pixels(dest_left, dest_top, w, h, rgba)

            except (RleDecodeError, CodecError) as exc:
                logger.warning("Bitmap decompression failed for rect %d: %s", i, exc)
                continue

    async def _process_orders_update(self, data: bytes) -> None:
        """Process a FASTPATH_UPDATETYPE_ORDERS update.

        Forwards raw drawing order data to the GDI order processor which handles
        primary, secondary, and alternate secondary orders per [MS-RDPEGDI] 2.2.2.1.

        (Req 5, AC 1–3)
        """
        await self._gdi.process_order_data(data)

    # --- Background dispatch loop (Req 30, AC 1–2, 5) ---

    async def _dispatch_loop(self) -> None:
        """Read PDUs from X.224, route fast-path and slow-path, detect disconnection.

        Runs as a background asyncio.Task. Uses X224Layer.recv_any() to receive
        both fast-path and slow-path PDUs. Fast-path PDUs are routed to
        _handle_fast_path_output(); slow-path PDUs are parsed via MCS
        SendDataIndication and routed to _route_pdu().

        Detects disconnection within 30 seconds via timeout on recv.
        Handles Deactivate All + re-activation.

        (Req 2, AC 1–5; Req 8, AC 6)
        """
        while not self._closed:
            try:
                is_fp, raw = await asyncio.wait_for(
                    self._x224.recv_any(),
                    timeout=30.0,
                )
                if is_fp:
                    await self._handle_fast_path_output(raw)
                else:
                    channel_id, payload = self._mcs.parse_send_data_indication(raw)
                    await self._route_pdu(channel_id, payload)
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
            logger.debug("_route_pdu: routing channel_id=%d to static channel", channel_id)
            await self._handle_static_channel_pdu(channel_id, data)
        else:
            logger.debug("_route_pdu: unknown channel_id=%d (io=%d, known=%s)",
                         channel_id, io_channel_id, list(self._static_channels.keys()))

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
            logger.debug("_handle_static_channel_pdu: channel=%d data too short (%d)", channel_id, len(data))
            return

        _total_length = struct.unpack_from("<I", data, 0)[0]
        flags = struct.unpack_from("<I", data, 4)[0]
        chunk = data[8:]

        logger.debug("_handle_static_channel_pdu: channel=%d total_len=%d flags=0x%08X chunk_len=%d hex=%s",
                     channel_id, _total_length, flags, len(chunk), chunk[:16].hex())

        svc = self._static_channels.get(channel_id)
        if svc is not None:
            await svc.on_data_received(chunk, flags)
        else:
            logger.debug("_handle_static_channel_pdu: no SVC for channel_id=%d", channel_id)

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
