"""Tests for Session._handle_fast_path_output() — tasks 8.1 through 8.13.

Tests cover:
- Parsing fast-path output PDUs and dispatching updates
- MPPC decompression when compression bit is set
- Fragment reassembly for non-SINGLE fragmentation
- Routing BITMAP, ORDERS, SYNCHRONIZE, and pointer types
- Logging PALETTE and SURFCMDS at INFO level
- Logging unknown update codes at DEBUG level
- Dirty rect callback dispatch with per-callback error handling
- PduParseError handling with hex dump logging
- MppcDecompressError handling and update skip
"""

from __future__ import annotations

import asyncio
import struct
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from arrdipi.errors import MppcDecompressError, PduParseError
from arrdipi.graphics.pointer import PointerHandler
from arrdipi.pdu.capabilities import FASTPATH_OUTPUT_SUPPORTED, GeneralCapabilitySet
from arrdipi.pdu.fastpath import (
    FastPathOutputFragmentation,
    FastPathOutputPdu,
    FastPathOutputUpdate,
    FastPathOutputUpdateCode,
)
from arrdipi.pdu.types import CapabilitySetType
from arrdipi.session import Session


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_session() -> Session:
    """Create a Session with mocked dependencies for fast-path testing."""
    mock_tcp = MagicMock()
    mock_tcp.send = AsyncMock()
    mock_tcp.close = AsyncMock()

    mock_x224 = MagicMock()

    mock_mcs = MagicMock()
    mock_mcs.user_channel_id = 1007
    mock_mcs.io_channel_id = 1003
    mock_mcs.channel_map = {}
    mock_mcs.send_to_channel = AsyncMock()
    mock_mcs.recv_pdu = AsyncMock()

    mock_security = MagicMock()
    mock_security.is_enhanced = True
    mock_security.unwrap_pdu = MagicMock(return_value=(b"", 0))

    mock_config = MagicMock()
    mock_config.width = 1024
    mock_config.height = 768
    mock_config.auto_reconnect_cookie = None

    general_cap = GeneralCapabilitySet(
        os_major_type=1,
        os_minor_type=3,
        protocol_version=0x0200,
        extra_flags=FASTPATH_OUTPUT_SUPPORTED,
    )
    server_caps = {CapabilitySetType.GENERAL: general_cap}

    session = Session(
        tcp=mock_tcp,
        x224=mock_x224,
        mcs=mock_mcs,
        security=mock_security,
        config=mock_config,
        server_caps=server_caps,
        share_id=0x00010001,
    )
    return session


def _build_fp_pdu(updates: list[FastPathOutputUpdate]) -> bytes:
    """Build a raw fast-path output PDU from a list of updates."""
    pdu = FastPathOutputPdu(updates=updates)
    return pdu.serialize()


# ---------------------------------------------------------------------------
# Tests: Task 8.1 — Method exists on Session
# ---------------------------------------------------------------------------


class TestHandleFastPathOutputExists:
    """Task 8.1: _handle_fast_path_output method exists on Session."""

    def test_method_exists(self) -> None:
        session = _make_session()
        assert hasattr(session, "_handle_fast_path_output")
        assert asyncio.iscoroutinefunction(session._handle_fast_path_output)


# ---------------------------------------------------------------------------
# Tests: Task 8.2 — Calls FastPathOutputPdu.parse()
# ---------------------------------------------------------------------------


class TestFastPathOutputParsing:
    """Task 8.2: _handle_fast_path_output calls FastPathOutputPdu.parse()."""

    @pytest.mark.asyncio
    async def test_parses_synchronize_update(self) -> None:
        """A SYNCHRONIZE update is parsed without error (no-op)."""
        session = _make_session()
        update = FastPathOutputUpdate(
            update_code=FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_SYNCHRONIZE,
            fragmentation=FastPathOutputFragmentation.FASTPATH_FRAGMENT_SINGLE,
            compression=0,
            data=b"",
        )
        raw = _build_fp_pdu([update])
        # Should not raise
        await session._handle_fast_path_output(raw)


# ---------------------------------------------------------------------------
# Tests: Task 8.3 — MPPC decompression when compression bit set
# ---------------------------------------------------------------------------


class TestMppcDecompression:
    """Task 8.3: MPPC decompression is applied when compression bit is set."""

    @pytest.mark.asyncio
    async def test_decompresses_when_compression_set(self) -> None:
        """When compression=1, _mppc.decompress is called with the flags and data."""
        session = _make_session()
        session._mppc = MagicMock()
        session._mppc.decompress = MagicMock(return_value=b"\x00\x00")

        update = FastPathOutputUpdate(
            update_code=FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_SYNCHRONIZE,
            fragmentation=FastPathOutputFragmentation.FASTPATH_FRAGMENT_SINGLE,
            compression=1,
            compression_flags=0x20,  # PACKET_COMPRESSED
            data=b"\xAB\xCD",
        )
        raw = _build_fp_pdu([update])
        await session._handle_fast_path_output(raw)

        session._mppc.decompress.assert_called_once_with(0x20, b"\xAB\xCD")

    @pytest.mark.asyncio
    async def test_no_decompression_when_compression_not_set(self) -> None:
        """When compression=0, _mppc.decompress is NOT called."""
        session = _make_session()
        session._mppc = MagicMock()
        session._mppc.decompress = MagicMock()

        update = FastPathOutputUpdate(
            update_code=FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_SYNCHRONIZE,
            fragmentation=FastPathOutputFragmentation.FASTPATH_FRAGMENT_SINGLE,
            compression=0,
            data=b"\x00\x00",
        )
        raw = _build_fp_pdu([update])
        await session._handle_fast_path_output(raw)

        session._mppc.decompress.assert_not_called()


# ---------------------------------------------------------------------------
# Tests: Task 8.4 — Fragment reassembly
# ---------------------------------------------------------------------------


class TestFragmentReassembly:
    """Task 8.4: Fragment reassembly skips update until complete."""

    @pytest.mark.asyncio
    async def test_first_fragment_returns_none(self) -> None:
        """FIRST fragment accumulates; no dispatch occurs."""
        session = _make_session()
        session._process_bitmap_update = AsyncMock()

        update = FastPathOutputUpdate(
            update_code=FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_BITMAP,
            fragmentation=FastPathOutputFragmentation.FASTPATH_FRAGMENT_FIRST,
            compression=0,
            data=b"\x01\x02\x03",
        )
        raw = _build_fp_pdu([update])
        await session._handle_fast_path_output(raw)

        session._process_bitmap_update.assert_not_called()

    @pytest.mark.asyncio
    async def test_full_fragment_sequence(self) -> None:
        """FIRST + LAST fragments are reassembled and dispatched."""
        session = _make_session()
        session._process_bitmap_update = AsyncMock()

        first = FastPathOutputUpdate(
            update_code=FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_BITMAP,
            fragmentation=FastPathOutputFragmentation.FASTPATH_FRAGMENT_FIRST,
            compression=0,
            data=b"\x01\x02",
        )
        last = FastPathOutputUpdate(
            update_code=FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_BITMAP,
            fragmentation=FastPathOutputFragmentation.FASTPATH_FRAGMENT_LAST,
            compression=0,
            data=b"\x03\x04",
        )
        raw = _build_fp_pdu([first, last])
        await session._handle_fast_path_output(raw)

        session._process_bitmap_update.assert_called_once_with(b"\x01\x02\x03\x04")


# ---------------------------------------------------------------------------
# Tests: Task 8.5 — Route BITMAP to _process_bitmap_update
# ---------------------------------------------------------------------------


class TestBitmapRouting:
    """Task 8.5: FASTPATH_UPDATETYPE_BITMAP routes to _process_bitmap_update."""

    @pytest.mark.asyncio
    async def test_bitmap_routed(self) -> None:
        session = _make_session()
        session._process_bitmap_update = AsyncMock()

        update = FastPathOutputUpdate(
            update_code=FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_BITMAP,
            fragmentation=FastPathOutputFragmentation.FASTPATH_FRAGMENT_SINGLE,
            compression=0,
            data=b"\xDE\xAD\xBE\xEF",
        )
        raw = _build_fp_pdu([update])
        await session._handle_fast_path_output(raw)

        session._process_bitmap_update.assert_called_once_with(b"\xDE\xAD\xBE\xEF")


# ---------------------------------------------------------------------------
# Tests: Task 8.6 — Route ORDERS to _process_orders_update
# ---------------------------------------------------------------------------


class TestOrdersRouting:
    """Task 8.6: FASTPATH_UPDATETYPE_ORDERS routes to _process_orders_update."""

    @pytest.mark.asyncio
    async def test_orders_routed(self) -> None:
        session = _make_session()
        session._process_orders_update = AsyncMock()

        update = FastPathOutputUpdate(
            update_code=FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_ORDERS,
            fragmentation=FastPathOutputFragmentation.FASTPATH_FRAGMENT_SINGLE,
            compression=0,
            data=b"\x01\x02\x03",
        )
        raw = _build_fp_pdu([update])
        await session._handle_fast_path_output(raw)

        session._process_orders_update.assert_called_once_with(b"\x01\x02\x03")


# ---------------------------------------------------------------------------
# Tests: Task 8.7 — SYNCHRONIZE is a no-op
# ---------------------------------------------------------------------------


class TestSynchronizeNoOp:
    """Task 8.7: FASTPATH_UPDATETYPE_SYNCHRONIZE is a no-op."""

    @pytest.mark.asyncio
    async def test_synchronize_no_error(self) -> None:
        session = _make_session()
        update = FastPathOutputUpdate(
            update_code=FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_SYNCHRONIZE,
            fragmentation=FastPathOutputFragmentation.FASTPATH_FRAGMENT_SINGLE,
            compression=0,
            data=b"",
        )
        raw = _build_fp_pdu([update])
        # Should not raise or call any handler
        await session._handle_fast_path_output(raw)


# ---------------------------------------------------------------------------
# Tests: Task 8.8 — Pointer type routing
# ---------------------------------------------------------------------------


class TestPointerRouting:
    """Task 8.8: All pointer types route to PointerHandler methods."""

    @pytest.mark.asyncio
    async def test_ptr_null_hides_pointer(self) -> None:
        session = _make_session()
        update = FastPathOutputUpdate(
            update_code=FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_PTR_NULL,
            fragmentation=FastPathOutputFragmentation.FASTPATH_FRAGMENT_SINGLE,
            compression=0,
            data=b"",
        )
        raw = _build_fp_pdu([update])
        await session._handle_fast_path_output(raw)
        assert session._pointer.visible is False

    @pytest.mark.asyncio
    async def test_ptr_default_shows_pointer(self) -> None:
        session = _make_session()
        # First hide it, then set default
        session._pointer.handle_system_pointer(0x0000)
        assert session._pointer.visible is False

        update = FastPathOutputUpdate(
            update_code=FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_PTR_DEFAULT,
            fragmentation=FastPathOutputFragmentation.FASTPATH_FRAGMENT_SINGLE,
            compression=0,
            data=b"",
        )
        raw = _build_fp_pdu([update])
        await session._handle_fast_path_output(raw)
        assert session._pointer.visible is True

    @pytest.mark.asyncio
    async def test_ptr_position_updates_position(self) -> None:
        session = _make_session()
        # PointerPositionUpdate: x(u16 LE) + y(u16 LE)
        pos_data = struct.pack("<HH", 100, 200)
        update = FastPathOutputUpdate(
            update_code=FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_PTR_POSITION,
            fragmentation=FastPathOutputFragmentation.FASTPATH_FRAGMENT_SINGLE,
            compression=0,
            data=pos_data,
        )
        raw = _build_fp_pdu([update])
        await session._handle_fast_path_output(raw)
        assert session._pointer.position == (100, 200)

    @pytest.mark.asyncio
    async def test_ptr_cached_switches_pointer(self) -> None:
        """CACHED pointer update switches to a cached pointer by index."""
        session = _make_session()
        # Pre-populate cache with a pointer at index 5
        from arrdipi.graphics.pointer import PointerImage

        dummy_pointer = PointerImage(
            width=1, height=1, hotspot_x=0, hotspot_y=0, rgba_data=b"\xff\x00\x00\xff"
        )
        session._pointer._cache[5] = dummy_pointer

        # CachedPointerUpdate: cache_index(u16 LE)
        cached_data = struct.pack("<H", 5)
        update = FastPathOutputUpdate(
            update_code=FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_CACHED,
            fragmentation=FastPathOutputFragmentation.FASTPATH_FRAGMENT_SINGLE,
            compression=0,
            data=cached_data,
        )
        raw = _build_fp_pdu([update])
        await session._handle_fast_path_output(raw)
        assert session._pointer.active_pointer is dummy_pointer


# ---------------------------------------------------------------------------
# Tests: Task 8.9 — PALETTE and SURFCMDS logged at INFO, skipped
# ---------------------------------------------------------------------------


class TestPaletteAndSurfcmds:
    """Task 8.9: PALETTE and SURFCMDS logged at INFO level."""

    @pytest.mark.asyncio
    async def test_palette_logged(self, caplog: pytest.LogCaptureFixture) -> None:
        import logging

        session = _make_session()
        update = FastPathOutputUpdate(
            update_code=FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_PALETTE,
            fragmentation=FastPathOutputFragmentation.FASTPATH_FRAGMENT_SINGLE,
            compression=0,
            data=b"\x00",
        )
        raw = _build_fp_pdu([update])
        with caplog.at_level(logging.INFO, logger="arrdipi.session"):
            await session._handle_fast_path_output(raw)
        assert "Unimplemented fast-path update" in caplog.text

    @pytest.mark.asyncio
    async def test_surfcmds_logged(self, caplog: pytest.LogCaptureFixture) -> None:
        import logging

        session = _make_session()
        update = FastPathOutputUpdate(
            update_code=FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_SURFCMDS,
            fragmentation=FastPathOutputFragmentation.FASTPATH_FRAGMENT_SINGLE,
            compression=0,
            data=b"\x00",
        )
        raw = _build_fp_pdu([update])
        with caplog.at_level(logging.INFO, logger="arrdipi.session"):
            await session._handle_fast_path_output(raw)
        assert "Unimplemented fast-path update" in caplog.text


# ---------------------------------------------------------------------------
# Tests: Task 8.10 — Unknown update codes logged at DEBUG
# ---------------------------------------------------------------------------


class TestUnknownUpdateCode:
    """Task 8.10: Unknown update codes logged at DEBUG level."""

    @pytest.mark.asyncio
    async def test_unknown_code_logged(self, caplog: pytest.LogCaptureFixture) -> None:
        import logging

        session = _make_session()
        # Use a code value that doesn't exist in the enum (0x0F)
        update = FastPathOutputUpdate(
            update_code=0x0F,
            fragmentation=FastPathOutputFragmentation.FASTPATH_FRAGMENT_SINGLE,
            compression=0,
            data=b"\x00",
        )
        raw = _build_fp_pdu([update])
        with caplog.at_level(logging.DEBUG, logger="arrdipi.session"):
            await session._handle_fast_path_output(raw)
        assert "Unknown fast-path update" in caplog.text


# ---------------------------------------------------------------------------
# Tests: Task 8.11 — Dirty rects dispatched to callbacks
# ---------------------------------------------------------------------------


class TestDirtyRectCallbacks:
    """Task 8.11: Dirty rects dispatched to callbacks with error handling."""

    @pytest.mark.asyncio
    async def test_callback_invoked_with_dirty_rects(self) -> None:
        session = _make_session()
        callback = AsyncMock()
        session.on_graphics_update(callback)

        # Write some pixels to create dirty rects
        pixels = b"\xff\x00\x00\xff" * (4 * 4)
        await session._surface.write_pixels(0, 0, 4, 4, pixels)

        # Trigger _handle_fast_path_output with a no-op update
        update = FastPathOutputUpdate(
            update_code=FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_SYNCHRONIZE,
            fragmentation=FastPathOutputFragmentation.FASTPATH_FRAGMENT_SINGLE,
            compression=0,
            data=b"",
        )
        raw = _build_fp_pdu([update])
        await session._handle_fast_path_output(raw)

        callback.assert_called_once()
        dirty_rects = callback.call_args[0][0]
        assert len(dirty_rects) == 1
        assert dirty_rects[0].x == 0
        assert dirty_rects[0].y == 0

    @pytest.mark.asyncio
    async def test_failing_callback_does_not_block_others(self) -> None:
        """A callback that raises does not prevent other callbacks from running."""
        session = _make_session()
        failing_cb = AsyncMock(side_effect=RuntimeError("boom"))
        good_cb = AsyncMock()
        session.on_graphics_update(failing_cb)
        session.on_graphics_update(good_cb)

        # Write pixels to create a dirty rect
        pixels = b"\xff\x00\x00\xff" * (2 * 2)
        await session._surface.write_pixels(0, 0, 2, 2, pixels)

        update = FastPathOutputUpdate(
            update_code=FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_SYNCHRONIZE,
            fragmentation=FastPathOutputFragmentation.FASTPATH_FRAGMENT_SINGLE,
            compression=0,
            data=b"",
        )
        raw = _build_fp_pdu([update])
        await session._handle_fast_path_output(raw)

        # Both callbacks were invoked despite the first one failing
        failing_cb.assert_called_once()
        good_cb.assert_called_once()


# ---------------------------------------------------------------------------
# Tests: Task 8.12 — PduParseError caught with hex dump log
# ---------------------------------------------------------------------------


class TestPduParseErrorHandling:
    """Task 8.12: PduParseError from parse() is caught and logged."""

    @pytest.mark.asyncio
    async def test_malformed_pdu_logged(self, caplog: pytest.LogCaptureFixture) -> None:
        import logging

        session = _make_session()
        # Completely malformed data — just a few bytes that will cause parse error
        malformed = b"\x00\x05\x01"  # header=0, length=5, then truncated

        with caplog.at_level(logging.ERROR, logger="arrdipi.session"):
            await session._handle_fast_path_output(malformed)

        assert "FastPath parse error" in caplog.text
        assert "hex:" in caplog.text


# ---------------------------------------------------------------------------
# Tests: Task 8.13 — MppcDecompressError caught per-update
# ---------------------------------------------------------------------------


class TestMppcDecompressErrorHandling:
    """Task 8.13: MPPC decompression errors skip the update and continue."""

    @pytest.mark.asyncio
    async def test_mppc_error_skips_update(self, caplog: pytest.LogCaptureFixture) -> None:
        import logging

        session = _make_session()
        session._mppc = MagicMock()
        session._mppc.decompress = MagicMock(
            side_effect=MppcDecompressError("test error")
        )
        session._process_bitmap_update = AsyncMock()

        # A compressed BITMAP update followed by an uncompressed SYNCHRONIZE
        compressed_update = FastPathOutputUpdate(
            update_code=FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_BITMAP,
            fragmentation=FastPathOutputFragmentation.FASTPATH_FRAGMENT_SINGLE,
            compression=1,
            compression_flags=0x20,
            data=b"\xFF\xFF",
        )
        sync_update = FastPathOutputUpdate(
            update_code=FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_SYNCHRONIZE,
            fragmentation=FastPathOutputFragmentation.FASTPATH_FRAGMENT_SINGLE,
            compression=0,
            data=b"",
        )
        raw = _build_fp_pdu([compressed_update, sync_update])

        with caplog.at_level(logging.ERROR, logger="arrdipi.session"):
            await session._handle_fast_path_output(raw)

        # The BITMAP update was skipped due to MPPC error
        session._process_bitmap_update.assert_not_called()
        assert "MPPC decompress failed" in caplog.text
