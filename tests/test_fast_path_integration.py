"""End-to-end integration tests for the fast-path graphics pipeline.

Tests the full pipeline: recv_any() -> _handle_fast_path_output() ->
_process_bitmap_update() -> surface.write_pixels() -> get_dirty_rects() ->
callback invocation.

Covers:
- Task 14.1: Full pipeline with raw fast-path bytes (bitmap updates)
- Task 14.2: Dirty rects correctness and callback invocation
- Task 14.3: Fragmented updates (FIRST + NEXT + LAST) through reassembly
- Task 14.4: MPPC-compressed update through decompression + processing

Requirements: All requirements (integration validation)
"""

from __future__ import annotations

import asyncio
import struct
from unittest.mock import AsyncMock, MagicMock

import pytest

from arrdipi.codec.mppc import MppcCompressor, PACKET_COMPRESSED
from arrdipi.graphics.surface import Rect
from arrdipi.pdu.capabilities import (
    FASTPATH_OUTPUT_SUPPORTED,
    GeneralCapabilitySet,
)
from arrdipi.pdu.fastpath import (
    FastPathOutputFragmentation,
    FastPathOutputPdu,
    FastPathOutputUpdate,
    FastPathOutputUpdateCode,
)
from arrdipi.pdu.types import CapabilitySetType
from arrdipi.session import Session


# ---------------------------------------------------------------------------
# Flag constants (per [MS-RDPBCGR] 2.2.9.1.1.3.1.2.2)
# ---------------------------------------------------------------------------
BITMAP_COMPRESSION = 0x0001
NO_BITMAP_COMPRESSION_HDR = 0x0400


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_session(width: int = 64, height: int = 64) -> Session:
    """Create a Session with mocked transport/MCS but real surface + codecs."""
    mock_tcp = MagicMock()
    mock_tcp.send = AsyncMock()
    mock_tcp.close = AsyncMock()

    mock_x224 = MagicMock()
    mock_x224.recv_any = AsyncMock()

    mock_mcs = MagicMock()
    mock_mcs.user_channel_id = 1007
    mock_mcs.io_channel_id = 1003
    mock_mcs.channel_map = {}
    mock_mcs.send_to_channel = AsyncMock()

    mock_security = MagicMock()
    mock_security.is_enhanced = True

    mock_config = MagicMock()
    mock_config.width = width
    mock_config.height = height
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


def _build_uncompressed_32bpp_bitmap(width: int, height: int) -> tuple[bytes, bytes]:
    """Build uncompressed 32bpp bitmap data in RDP BGRX format (bottom-up).

    Returns:
        Tuple of (raw_bitmap_data, expected_rgba_after_decode) where
        expected_rgba is in top-down RGBA order after flip + conversion.
    """
    # Build pixel rows in bottom-up order (RDP convention).
    # Row 0 in data = bottom row of the image.
    # After vertical flip by RleCodec, row 0 becomes the last row.
    #
    # We'll fill each row with a distinct color:
    # Bottom row (row 0 in data): Blue pixels -> BGRX = (0xFF, 0x00, 0x00, 0xFF)
    # Top row (row height-1 in data): Red pixels -> BGRX = (0x00, 0x00, 0xFF, 0xFF)
    rows_bgrx = []
    for row_idx in range(height):
        if row_idx < height // 2:
            # Bottom half: blue pixels (B=0xFF, G=0x00, R=0x00, X=0xFF)
            pixel = bytes([0xFF, 0x00, 0x00, 0xFF])
        else:
            # Top half: red pixels (B=0x00, G=0x00, R=0xFF, X=0xFF)
            pixel = bytes([0x00, 0x00, 0xFF, 0xFF])
        rows_bgrx.append(pixel * width)

    raw_bitmap = b"".join(rows_bgrx)

    # Expected RGBA after _convert_to_rgba (BGRX -> RGBA) and _flip_vertical:
    # After flip: top rows of the image come from last rows in data (red),
    # bottom rows come from first rows in data (blue).
    # RGBA: Red pixel = (0xFF, 0x00, 0x00, 0xFF)
    # RGBA: Blue pixel = (0x00, 0x00, 0xFF, 0xFF)
    expected_rows = []
    for row_idx in range(height - 1, -1, -1):
        if row_idx < height // 2:
            # This was bottom half in data = blue
            pixel_rgba = bytes([0x00, 0x00, 0xFF, 0xFF])
        else:
            # This was top half in data = red
            pixel_rgba = bytes([0xFF, 0x00, 0x00, 0xFF])
        expected_rows.append(pixel_rgba * width)

    expected_rgba = b"".join(expected_rows)
    return raw_bitmap, expected_rgba


def _build_ts_bitmap_data(
    dest_left: int,
    dest_top: int,
    dest_right: int,
    dest_bottom: int,
    width: int,
    height: int,
    bpp: int,
    flags: int,
    bitmap_data: bytes,
) -> bytes:
    """Build a single TS_BITMAP_DATA structure per [MS-RDPBCGR] 2.2.9.1.1.3.1.2.2."""
    bitmap_length = len(bitmap_data)
    header = struct.pack(
        "<HHHHHHHHHH",
        dest_left,
        dest_top,
        dest_right,
        dest_bottom,
        width,
        height,
        bpp,
        flags,
        bitmap_length,
        0,  # padding (not actually in spec, but bitmapLength is last before data)
    )
    # Actually the struct is: 9 u16 fields + bitmap_data bytes
    # destLeft(2) + destTop(2) + destRight(2) + destBottom(2) +
    # width(2) + height(2) + bpp(2) + flags(2) + bitmapLength(2) = 18 bytes
    header = struct.pack(
        "<HHHHHHHHH",
        dest_left,
        dest_top,
        dest_right,
        dest_bottom,
        width,
        height,
        bpp,
        flags,
        bitmap_length,
    )
    return header + bitmap_data


def _build_bitmap_update_payload(rects: list[bytes]) -> bytes:
    """Build a TS_UPDATE_BITMAP_DATA payload (numberRectangles + rect data)."""
    num_rects = struct.pack("<H", len(rects))
    return num_rects + b"".join(rects)


def _build_fast_path_pdu_with_bitmap(bitmap_payload: bytes) -> bytes:
    """Build a complete fast-path output PDU containing a single bitmap update.

    Uses FastPathOutputPdu.serialize() for correctness.
    """
    update = FastPathOutputUpdate(
        update_code=FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_BITMAP,
        fragmentation=FastPathOutputFragmentation.FASTPATH_FRAGMENT_SINGLE,
        compression=0,
        compression_flags=0,
        data=bitmap_payload,
    )
    pdu = FastPathOutputPdu(updates=[update], flags=0)
    return pdu.serialize()


# ---------------------------------------------------------------------------
# Task 14.1 + 14.2: Full pipeline integration test
# ---------------------------------------------------------------------------


class TestFullPipelineIntegration:
    """End-to-end: raw fast-path bytes -> surface pixels -> dirty rects -> callback."""

    @pytest.mark.asyncio
    async def test_bitmap_update_full_pipeline(self) -> None:
        """Feed raw fast-path bitmap bytes through the entire pipeline.

        Verifies:
        - FastPathOutputPdu parses correctly
        - _handle_fast_path_output dispatches to _process_bitmap_update
        - RleCodec.decompress handles uncompressed 32bpp (BGRX -> RGBA + flip)
        - GraphicsSurface.write_pixels stores pixels at correct location
        - get_dirty_rects returns the correct rect
        - on_graphics_update callback is invoked with expected rects
        """
        session = _make_session(width=64, height=64)

        # Build a 4x4 uncompressed 32bpp bitmap at position (10, 10)
        bm_width, bm_height = 4, 4
        raw_bitmap, expected_rgba = _build_uncompressed_32bpp_bitmap(
            bm_width, bm_height
        )

        # Destination rect: (10, 10) to (13, 13) inclusive
        dest_left, dest_top = 10, 10
        dest_right, dest_bottom = 13, 13

        # Build TS_BITMAP_DATA: uncompressed (flags=0)
        ts_bitmap = _build_ts_bitmap_data(
            dest_left=dest_left,
            dest_top=dest_top,
            dest_right=dest_right,
            dest_bottom=dest_bottom,
            width=bm_width,
            height=bm_height,
            bpp=32,
            flags=0,  # uncompressed
            bitmap_data=raw_bitmap,
        )

        # Build bitmap update payload
        bitmap_payload = _build_bitmap_update_payload([ts_bitmap])

        # Build complete fast-path PDU
        fp_pdu_bytes = _build_fast_path_pdu_with_bitmap(bitmap_payload)

        # Register a callback to capture dirty rects
        callback_rects: list[list[Rect]] = []

        async def on_update(rects: list[Rect]) -> None:
            callback_rects.append(rects)

        session.on_graphics_update(on_update)

        # Feed through the pipeline
        await session._handle_fast_path_output(fp_pdu_bytes)

        # Verify callback was invoked
        assert len(callback_rects) == 1, "Callback should be called once"
        rects = callback_rects[0]
        assert len(rects) == 1, "Should have exactly one dirty rect"

        # Verify dirty rect matches destination
        rect = rects[0]
        expected_w = dest_right - dest_left + 1
        expected_h = dest_bottom - dest_top + 1
        assert rect == Rect(dest_left, dest_top, expected_w, expected_h)

        # Verify pixels in the surface
        surface_pixels = await session._surface.read_pixels(
            dest_left, dest_top, expected_w, expected_h
        )
        assert surface_pixels == expected_rgba


    @pytest.mark.asyncio
    async def test_multiple_rects_in_single_pdu(self) -> None:
        """Multiple bitmap rects in one PDU produce multiple dirty rects in one callback."""
        session = _make_session(width=64, height=64)

        # Build two small 2x2 bitmaps at different positions
        bm_w, bm_h = 2, 2
        raw_bitmap, _ = _build_uncompressed_32bpp_bitmap(bm_w, bm_h)

        rect1 = _build_ts_bitmap_data(0, 0, 1, 1, bm_w, bm_h, 32, 0, raw_bitmap)
        rect2 = _build_ts_bitmap_data(10, 10, 11, 11, bm_w, bm_h, 32, 0, raw_bitmap)

        bitmap_payload = _build_bitmap_update_payload([rect1, rect2])
        fp_pdu_bytes = _build_fast_path_pdu_with_bitmap(bitmap_payload)

        callback_rects: list[list[Rect]] = []

        async def on_update(rects: list[Rect]) -> None:
            callback_rects.append(rects)

        session.on_graphics_update(on_update)
        await session._handle_fast_path_output(fp_pdu_bytes)

        # Callback should be called once with both rects
        assert len(callback_rects) == 1
        rects = callback_rects[0]
        assert len(rects) == 2
        assert Rect(0, 0, 2, 2) in rects
        assert Rect(10, 10, 2, 2) in rects

    @pytest.mark.asyncio
    async def test_recv_any_to_callback_via_dispatch(self) -> None:
        """Simulate recv_any -> dispatch_loop -> full pipeline -> callback."""
        session = _make_session(width=64, height=64)

        bm_w, bm_h = 2, 2
        raw_bitmap, expected_rgba = _build_uncompressed_32bpp_bitmap(bm_w, bm_h)
        ts_bitmap = _build_ts_bitmap_data(0, 0, 1, 1, bm_w, bm_h, 32, 0, raw_bitmap)
        bitmap_payload = _build_bitmap_update_payload([ts_bitmap])
        fp_pdu_bytes = _build_fast_path_pdu_with_bitmap(bitmap_payload)

        # Mock recv_any to return our PDU then stop
        session._x224.recv_any = AsyncMock(
            side_effect=[(True, fp_pdu_bytes), asyncio.CancelledError()]
        )

        callback_rects: list[list[Rect]] = []

        async def on_update(rects: list[Rect]) -> None:
            callback_rects.append(rects)

        session.on_graphics_update(on_update)

        await session.start()
        await asyncio.sleep(0.05)
        await session.close()

        assert len(callback_rects) == 1
        assert callback_rects[0] == [Rect(0, 0, 2, 2)]

        # Verify pixels
        surface_pixels = await session._surface.read_pixels(0, 0, 2, 2)
        assert surface_pixels == expected_rgba


# ---------------------------------------------------------------------------
# Task 14.3: Fragmented updates (FIRST + NEXT + LAST) reassembly
# ---------------------------------------------------------------------------


class TestFragmentedUpdateIntegration:
    """End-to-end: fragmented bitmap update through reassembly -> surface."""

    @pytest.mark.asyncio
    async def test_fragmented_bitmap_reassembly_full_pipeline(self) -> None:
        """FIRST + NEXT + LAST fragments are reassembled and processed.

        Splits a bitmap update payload into 3 fragments, feeds each as a
        separate fast-path PDU, and verifies the final reassembled bitmap
        is correctly written to the surface.
        """
        session = _make_session(width=64, height=64)

        # Build a 4x4 uncompressed 32bpp bitmap
        bm_w, bm_h = 4, 4
        raw_bitmap, expected_rgba = _build_uncompressed_32bpp_bitmap(bm_w, bm_h)

        ts_bitmap = _build_ts_bitmap_data(0, 0, 3, 3, bm_w, bm_h, 32, 0, raw_bitmap)
        bitmap_payload = _build_bitmap_update_payload([ts_bitmap])

        # Split the payload into 3 fragments
        total_len = len(bitmap_payload)
        chunk_size = total_len // 3
        frag_first = bitmap_payload[:chunk_size]
        frag_next = bitmap_payload[chunk_size : chunk_size * 2]
        frag_last = bitmap_payload[chunk_size * 2 :]

        # Build 3 fast-path PDUs with fragmentation flags
        def _build_fragmented_pdu(
            data: bytes, fragmentation: int
        ) -> bytes:
            update = FastPathOutputUpdate(
                update_code=FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_BITMAP,
                fragmentation=fragmentation,
                compression=0,
                compression_flags=0,
                data=data,
            )
            pdu = FastPathOutputPdu(updates=[update], flags=0)
            return pdu.serialize()

        pdu_first = _build_fragmented_pdu(
            frag_first, FastPathOutputFragmentation.FASTPATH_FRAGMENT_FIRST
        )
        pdu_next = _build_fragmented_pdu(
            frag_next, FastPathOutputFragmentation.FASTPATH_FRAGMENT_NEXT
        )
        pdu_last = _build_fragmented_pdu(
            frag_last, FastPathOutputFragmentation.FASTPATH_FRAGMENT_LAST
        )

        callback_rects: list[list[Rect]] = []

        async def on_update(rects: list[Rect]) -> None:
            callback_rects.append(rects)

        session.on_graphics_update(on_update)

        # Feed FIRST fragment — should not trigger callback (no dirty rects)
        await session._handle_fast_path_output(pdu_first)
        assert len(callback_rects) == 0

        # Feed NEXT fragment — still accumulating
        await session._handle_fast_path_output(pdu_next)
        assert len(callback_rects) == 0

        # Feed LAST fragment — reassembly completes, bitmap processed
        await session._handle_fast_path_output(pdu_last)
        assert len(callback_rects) == 1

        # Verify dirty rect
        rects = callback_rects[0]
        assert len(rects) == 1
        assert rects[0] == Rect(0, 0, 4, 4)

        # Verify pixels in the surface
        surface_pixels = await session._surface.read_pixels(0, 0, 4, 4)
        assert surface_pixels == expected_rgba


    @pytest.mark.asyncio
    async def test_fragmented_with_interleaved_single_update(self) -> None:
        """Non-fragmented updates are not blocked by in-progress fragment reassembly.

        Sends FIRST fragment, then a complete SYNCHRONIZE update, then LAST.
        The SYNCHRONIZE should process immediately; the LAST should complete
        the bitmap reassembly.
        """
        session = _make_session(width=64, height=64)

        bm_w, bm_h = 2, 2
        raw_bitmap, expected_rgba = _build_uncompressed_32bpp_bitmap(bm_w, bm_h)
        ts_bitmap = _build_ts_bitmap_data(5, 5, 6, 6, bm_w, bm_h, 32, 0, raw_bitmap)
        bitmap_payload = _build_bitmap_update_payload([ts_bitmap])

        # Split into FIRST + LAST (no NEXT for simplicity)
        mid = len(bitmap_payload) // 2
        frag_first = bitmap_payload[:mid]
        frag_last = bitmap_payload[mid:]

        # FIRST fragment
        update_first = FastPathOutputUpdate(
            update_code=FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_BITMAP,
            fragmentation=FastPathOutputFragmentation.FASTPATH_FRAGMENT_FIRST,
            compression=0,
            data=frag_first,
        )
        # SYNCHRONIZE (non-fragmented, different update type)
        update_sync = FastPathOutputUpdate(
            update_code=FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_SYNCHRONIZE,
            fragmentation=FastPathOutputFragmentation.FASTPATH_FRAGMENT_SINGLE,
            compression=0,
            data=b"",
        )
        # Both in the same PDU
        pdu_mixed = FastPathOutputPdu(updates=[update_first, update_sync], flags=0)
        pdu_mixed_bytes = pdu_mixed.serialize()

        # LAST fragment in a separate PDU
        update_last = FastPathOutputUpdate(
            update_code=FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_BITMAP,
            fragmentation=FastPathOutputFragmentation.FASTPATH_FRAGMENT_LAST,
            compression=0,
            data=frag_last,
        )
        pdu_last = FastPathOutputPdu(updates=[update_last], flags=0)
        pdu_last_bytes = pdu_last.serialize()

        callback_rects: list[list[Rect]] = []

        async def on_update(rects: list[Rect]) -> None:
            callback_rects.append(rects)

        session.on_graphics_update(on_update)

        # First PDU: FIRST fragment + SYNCHRONIZE — no bitmap written yet
        await session._handle_fast_path_output(pdu_mixed_bytes)
        assert len(callback_rects) == 0

        # Second PDU: LAST fragment — bitmap reassembled and processed
        await session._handle_fast_path_output(pdu_last_bytes)
        assert len(callback_rects) == 1
        assert callback_rects[0] == [Rect(5, 5, 2, 2)]

        # Verify pixels
        surface_pixels = await session._surface.read_pixels(5, 5, 2, 2)
        assert surface_pixels == expected_rgba


# ---------------------------------------------------------------------------
# Task 14.4: MPPC-compressed update integration test
# ---------------------------------------------------------------------------


class TestMppcCompressedUpdateIntegration:
    """End-to-end: MPPC-compressed bitmap update -> decompress -> surface."""

    @pytest.mark.asyncio
    async def test_mppc_compressed_bitmap_full_pipeline(self) -> None:
        """Compress a bitmap payload with MppcCompressor, set compression bit,
        and verify the full pipeline decompresses and processes it correctly.
        """
        session = _make_session(width=64, height=64)

        # Build a 4x4 uncompressed 32bpp bitmap
        bm_w, bm_h = 4, 4
        raw_bitmap, expected_rgba = _build_uncompressed_32bpp_bitmap(bm_w, bm_h)

        ts_bitmap = _build_ts_bitmap_data(
            20, 20, 23, 23, bm_w, bm_h, 32, 0, raw_bitmap
        )
        bitmap_payload = _build_bitmap_update_payload([ts_bitmap])

        # Compress the bitmap payload using MppcCompressor
        compressor = MppcCompressor()
        compressed_data, comp_flags = compressor.compress(bitmap_payload)

        # Build a fast-path update with compression bit set
        update = FastPathOutputUpdate(
            update_code=FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_BITMAP,
            fragmentation=FastPathOutputFragmentation.FASTPATH_FRAGMENT_SINGLE,
            compression=1,
            compression_flags=comp_flags,
            data=compressed_data,
        )
        pdu = FastPathOutputPdu(updates=[update], flags=0)
        fp_pdu_bytes = pdu.serialize()

        callback_rects: list[list[Rect]] = []

        async def on_update(rects: list[Rect]) -> None:
            callback_rects.append(rects)

        session.on_graphics_update(on_update)

        # Feed through the pipeline — should decompress + process
        await session._handle_fast_path_output(fp_pdu_bytes)

        # Verify callback
        assert len(callback_rects) == 1
        rects = callback_rects[0]
        assert len(rects) == 1
        assert rects[0] == Rect(20, 20, 4, 4)

        # Verify pixels
        surface_pixels = await session._surface.read_pixels(20, 20, 4, 4)
        assert surface_pixels == expected_rgba


    @pytest.mark.asyncio
    async def test_mppc_compressed_with_larger_payload(self) -> None:
        """MPPC compression with a larger payload to ensure LZ77 matching works.

        A larger bitmap with repeated patterns should compress well, and the
        pipeline should correctly decompress and render it.
        """
        session = _make_session(width=128, height=128)

        # Build a larger 16x16 bitmap with repeated patterns (good for LZ77)
        bm_w, bm_h = 16, 16
        # Use a simple repeating pattern: alternating red/blue rows
        rows_bgrx = []
        for row_idx in range(bm_h):
            if row_idx % 2 == 0:
                pixel = bytes([0xFF, 0x00, 0x00, 0xFF])  # Blue in BGRX
            else:
                pixel = bytes([0x00, 0x00, 0xFF, 0xFF])  # Red in BGRX
            rows_bgrx.append(pixel * bm_w)
        raw_bitmap = b"".join(rows_bgrx)

        ts_bitmap = _build_ts_bitmap_data(
            0, 0, 15, 15, bm_w, bm_h, 32, 0, raw_bitmap
        )
        bitmap_payload = _build_bitmap_update_payload([ts_bitmap])

        # Compress
        compressor = MppcCompressor()
        compressed_data, comp_flags = compressor.compress(bitmap_payload)

        # Verify compression actually reduced size (the repeating pattern
        # should compress well)
        assert comp_flags & PACKET_COMPRESSED, (
            "Expected PACKET_COMPRESSED flag for compressible data"
        )

        update = FastPathOutputUpdate(
            update_code=FastPathOutputUpdateCode.FASTPATH_UPDATETYPE_BITMAP,
            fragmentation=FastPathOutputFragmentation.FASTPATH_FRAGMENT_SINGLE,
            compression=1,
            compression_flags=comp_flags,
            data=compressed_data,
        )
        pdu = FastPathOutputPdu(updates=[update], flags=0)
        fp_pdu_bytes = pdu.serialize()

        callback_rects: list[list[Rect]] = []

        async def on_update(rects: list[Rect]) -> None:
            callback_rects.append(rects)

        session.on_graphics_update(on_update)
        await session._handle_fast_path_output(fp_pdu_bytes)

        # Verify callback and dirty rect
        assert len(callback_rects) == 1
        assert callback_rects[0] == [Rect(0, 0, 16, 16)]

        # Read surface pixels and verify they match the expected output
        surface_pixels = await session._surface.read_pixels(0, 0, 16, 16)
        # After flip: row 0 on screen was row (bm_h-1) in data
        # Row bm_h-1 in data (idx 15, odd): Red BGRX -> RGBA (0xFF, 0x00, 0x00, 0xFF)
        # The first pixel in the top-left should be from the last row in data
        first_pixel = surface_pixels[0:4]
        # Row 15 (odd) = Red in BGRX = (0x00, 0x00, 0xFF, 0xFF) -> RGBA (0xFF, 0x00, 0x00, 0xFF)
        assert first_pixel == bytes([0xFF, 0x00, 0x00, 0xFF])
