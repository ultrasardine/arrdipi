"""Tests for Session._process_bitmap_update() — tasks 9.1 through 9.11.

Tests cover:
- Parsing numberRectangles and iterating TS_BITMAP_DATA structures
- Handling compressed bitmap with TS_CD_HEADER (8-byte skip)
- Handling compressed bitmap without TS_CD_HEADER (NO_BITMAP_COMPRESSION_HDR set)
- Handling uncompressed bitmap data
- Routing 32 bpp compressed data to Rdp6BitmapCodec
- Error handling per-rect (RleDecodeError, CodecError)
"""

from __future__ import annotations

import struct
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from arrdipi.errors import CodecError, RleDecodeError
from arrdipi.pdu.capabilities import FASTPATH_OUTPUT_SUPPORTED, GeneralCapabilitySet
from arrdipi.pdu.types import CapabilitySetType
from arrdipi.session import Session


# ---------------------------------------------------------------------------
# Flag constants (mirrors session.py implementation)
# ---------------------------------------------------------------------------
BITMAP_COMPRESSION = 0x0001
NO_BITMAP_COMPRESSION_HDR = 0x0400


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_session() -> Session:
    """Create a Session with mocked dependencies for bitmap testing."""
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
    """Build a single TS_BITMAP_DATA structure.

    Per [MS-RDPBCGR] 2.2.9.1.1.3.1.2.2:
    destLeft(u16) + destTop(u16) + destRight(u16) + destBottom(u16) +
    width(u16) + height(u16) + bitsPerPixel(u16) + flags(u16) +
    bitmapLength(u16) + bitmapData(bitmapLength bytes)
    """
    bitmap_length = len(bitmap_data)
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


def _build_bitmap_update(rects: list[bytes]) -> bytes:
    """Build a complete bitmap update payload.

    numberRectangles(u16 LE) followed by concatenated TS_BITMAP_DATA structures.
    """
    num_rects = struct.pack("<H", len(rects))
    return num_rects + b"".join(rects)


# ---------------------------------------------------------------------------
# Tests: Task 9.1 — Method exists and is async
# ---------------------------------------------------------------------------


class TestProcessBitmapUpdateExists:
    """Task 9.1: _process_bitmap_update exists as async method on Session."""

    def test_method_exists(self) -> None:
        import asyncio

        session = _make_session()
        assert hasattr(session, "_process_bitmap_update")
        assert asyncio.iscoroutinefunction(session._process_bitmap_update)


# ---------------------------------------------------------------------------
# Tests: Task 9.2 — Parses numberRectangles and iterates
# ---------------------------------------------------------------------------


class TestNumberRectanglesParsing:
    """Task 9.2: Parses numberRectangles (u16 LE) and iterates."""

    @pytest.mark.asyncio
    async def test_empty_bitmap_update(self) -> None:
        """Zero rectangles produces no surface writes."""
        session = _make_session()
        session._surface = MagicMock()
        session._surface.write_pixels = AsyncMock()

        data = struct.pack("<H", 0)  # 0 rectangles
        await session._process_bitmap_update(data)

        session._surface.write_pixels.assert_not_called()

    @pytest.mark.asyncio
    async def test_multiple_rects_processed(self) -> None:
        """Multiple rectangles are each processed."""
        session = _make_session()
        session._surface = MagicMock()
        session._surface.write_pixels = AsyncMock()

        # Build 2 uncompressed 2x2 16bpp rects
        # 2x2 at 16bpp = 4 pixels * 2 bytes = 8 bytes per row, row_size=4 (already 4-byte aligned)
        # row_size = ((2*2 + 3) & ~3) = 4, so 4 bytes/row, 2 rows = 8 bytes
        pixel_data = b"\x00\x00\x00\x00\x00\x00\x00\x00"  # 2x2 at 16bpp = 8 bytes
        rect1 = _build_ts_bitmap_data(0, 0, 1, 1, 2, 2, 16, 0, pixel_data)
        rect2 = _build_ts_bitmap_data(10, 10, 11, 11, 2, 2, 16, 0, pixel_data)

        data = _build_bitmap_update([rect1, rect2])

        with patch("arrdipi.session.RleCodec") as mock_rle:
            mock_rle.decompress.return_value = b"\x00" * (2 * 2 * 4)  # 4 pixels RGBA
            await session._process_bitmap_update(data)

        assert session._surface.write_pixels.call_count == 2


# ---------------------------------------------------------------------------
# Tests: Task 9.3–9.4 — Compressed with TS_CD_HEADER (skip first 8 bytes)
# ---------------------------------------------------------------------------


class TestCompressedWithHeader:
    """Tasks 9.3–9.4: Compressed bitmap with TS_CD_HEADER present (8 bytes skipped)."""

    @pytest.mark.asyncio
    async def test_compressed_with_cd_header(self) -> None:
        """When BITMAP_COMPRESSION set and NO_BITMAP_COMPRESSION_HDR NOT set,
        first 8 bytes are TS_CD_HEADER and should be skipped."""
        session = _make_session()
        session._surface = MagicMock()
        session._surface.write_pixels = AsyncMock()

        # flags = BITMAP_COMPRESSION only (NO_BITMAP_COMPRESSION_HDR NOT set)
        flags = BITMAP_COMPRESSION
        # 8-byte TS_CD_HEADER + actual compressed data
        cd_header = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        compressed_data = b"\xAB\xCD\xEF"
        bitmap_data = cd_header + compressed_data

        rect = _build_ts_bitmap_data(0, 0, 3, 3, 4, 4, 16, flags, bitmap_data)
        data = _build_bitmap_update([rect])

        with patch("arrdipi.session.RleCodec") as mock_rle:
            mock_rle.decompress.return_value = b"\x00" * (4 * 4 * 4)  # 4x4 RGBA
            await session._process_bitmap_update(data)

            # Verify the TS_CD_HEADER was skipped — only compressed_data passed
            mock_rle.decompress.assert_called_once_with(
                compressed_data, 4, 4, 16, compressed=True, rect_index=0
            )

        # Surface write at correct coordinates
        session._surface.write_pixels.assert_called_once_with(0, 0, 4, 4, mock_rle.decompress.return_value)


# ---------------------------------------------------------------------------
# Tests: Task 9.5 — Compressed without TS_CD_HEADER
# ---------------------------------------------------------------------------


class TestCompressedWithoutHeader:
    """Task 9.5: Compressed bitmap with NO_BITMAP_COMPRESSION_HDR set — all bytes are data."""

    @pytest.mark.asyncio
    async def test_compressed_no_cd_header(self) -> None:
        """When both BITMAP_COMPRESSION and NO_BITMAP_COMPRESSION_HDR set,
        all bitmapLength bytes are compressed data (no header to skip)."""
        session = _make_session()
        session._surface = MagicMock()
        session._surface.write_pixels = AsyncMock()

        flags = BITMAP_COMPRESSION | NO_BITMAP_COMPRESSION_HDR
        compressed_data = b"\xAB\xCD\xEF\x01\x02"

        rect = _build_ts_bitmap_data(5, 5, 8, 8, 4, 4, 16, flags, compressed_data)
        data = _build_bitmap_update([rect])

        with patch("arrdipi.session.RleCodec") as mock_rle:
            mock_rle.decompress.return_value = b"\x00" * (4 * 4 * 4)
            await session._process_bitmap_update(data)

            # All bytes passed directly — no 8-byte skip
            mock_rle.decompress.assert_called_once_with(
                compressed_data, 4, 4, 16, compressed=True, rect_index=0
            )


# ---------------------------------------------------------------------------
# Tests: Task 9.6 — Compressed bpp < 32 routes to RleCodec
# ---------------------------------------------------------------------------


class TestCompressedRleRouting:
    """Task 9.6: Compressed bpp < 32 calls RleCodec.decompress with compressed=True."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("bpp", [8, 16, 24])
    async def test_rle_called_for_sub32_bpp(self, bpp: int) -> None:
        session = _make_session()
        session._surface = MagicMock()
        session._surface.write_pixels = AsyncMock()

        flags = BITMAP_COMPRESSION | NO_BITMAP_COMPRESSION_HDR
        compressed_data = b"\x00" * 10

        rect = _build_ts_bitmap_data(0, 0, 1, 1, 2, 2, bpp, flags, compressed_data)
        data = _build_bitmap_update([rect])

        with patch("arrdipi.session.RleCodec") as mock_rle:
            mock_rle.decompress.return_value = b"\x00" * (2 * 2 * 4)
            await session._process_bitmap_update(data)

            mock_rle.decompress.assert_called_once_with(
                compressed_data, 2, 2, bpp, compressed=True, rect_index=0
            )


# ---------------------------------------------------------------------------
# Tests: Task 9.7 — Compressed bpp == 32 routes to Rdp6BitmapCodec
# ---------------------------------------------------------------------------


class TestCompressed32bppRouting:
    """Task 9.7: Compressed 32 bpp calls Rdp6BitmapCodec.decompress."""

    @pytest.mark.asyncio
    async def test_rdp6_codec_called_for_32bpp(self) -> None:
        session = _make_session()
        session._surface = MagicMock()
        session._surface.write_pixels = AsyncMock()

        flags = BITMAP_COMPRESSION | NO_BITMAP_COMPRESSION_HDR
        compressed_data = b"\x10" + b"\xFF" * 20  # header byte + some data

        rect = _build_ts_bitmap_data(0, 0, 1, 1, 2, 2, 32, flags, compressed_data)
        data = _build_bitmap_update([rect])

        with patch("arrdipi.session.Rdp6BitmapCodec") as mock_rdp6:
            mock_rdp6.decompress.return_value = b"\x00" * (2 * 2 * 4)
            await session._process_bitmap_update(data)

            mock_rdp6.decompress.assert_called_once_with(compressed_data, 2, 2)

    @pytest.mark.asyncio
    async def test_rdp6_with_cd_header_skipped(self) -> None:
        """32 bpp compressed with TS_CD_HEADER present: header is skipped."""
        session = _make_session()
        session._surface = MagicMock()
        session._surface.write_pixels = AsyncMock()

        flags = BITMAP_COMPRESSION  # NO_BITMAP_COMPRESSION_HDR NOT set
        cd_header = b"\x00" * 8
        actual_data = b"\x10" + b"\xFF" * 10
        bitmap_data = cd_header + actual_data

        rect = _build_ts_bitmap_data(0, 0, 1, 1, 2, 2, 32, flags, bitmap_data)
        data = _build_bitmap_update([rect])

        with patch("arrdipi.session.Rdp6BitmapCodec") as mock_rdp6:
            mock_rdp6.decompress.return_value = b"\x00" * (2 * 2 * 4)
            await session._process_bitmap_update(data)

            mock_rdp6.decompress.assert_called_once_with(actual_data, 2, 2)


# ---------------------------------------------------------------------------
# Tests: Task 9.8 — Uncompressed calls RleCodec with compressed=False
# ---------------------------------------------------------------------------


class TestUncompressedBitmap:
    """Task 9.8: Uncompressed bitmap calls RleCodec.decompress(compressed=False)."""

    @pytest.mark.asyncio
    async def test_uncompressed_routes_to_rle(self) -> None:
        session = _make_session()
        session._surface = MagicMock()
        session._surface.write_pixels = AsyncMock()

        flags = 0  # No compression flags set
        # Uncompressed 2x2 at 16bpp: row_size = ((2*2+3)&~3) = 4, 2 rows = 8 bytes
        raw_data = b"\x00" * 8

        rect = _build_ts_bitmap_data(0, 0, 1, 1, 2, 2, 16, flags, raw_data)
        data = _build_bitmap_update([rect])

        with patch("arrdipi.session.RleCodec") as mock_rle:
            mock_rle.decompress.return_value = b"\x00" * (2 * 2 * 4)
            await session._process_bitmap_update(data)

            mock_rle.decompress.assert_called_once_with(
                raw_data, 2, 2, 16, compressed=False, rect_index=0
            )


# ---------------------------------------------------------------------------
# Tests: Task 9.9 — Write RGBA to surface with correct dimensions
# ---------------------------------------------------------------------------


class TestSurfaceWrite:
    """Task 9.9: RGBA written to surface.write_pixels with correct coordinates."""

    @pytest.mark.asyncio
    async def test_write_pixels_correct_dimensions(self) -> None:
        """write_pixels called with w=destRight-destLeft+1, h=destBottom-destTop+1."""
        session = _make_session()
        session._surface = MagicMock()
        session._surface.write_pixels = AsyncMock()

        # destLeft=10, destTop=20, destRight=13, destBottom=22
        # w = 13 - 10 + 1 = 4, h = 22 - 20 + 1 = 3
        flags = BITMAP_COMPRESSION | NO_BITMAP_COMPRESSION_HDR
        compressed_data = b"\x00" * 5

        rect = _build_ts_bitmap_data(10, 20, 13, 22, 4, 3, 16, flags, compressed_data)
        data = _build_bitmap_update([rect])

        rgba = b"\xFF" * (4 * 3 * 4)  # 4x3 RGBA
        with patch("arrdipi.session.RleCodec") as mock_rle:
            mock_rle.decompress.return_value = rgba
            await session._process_bitmap_update(data)

        session._surface.write_pixels.assert_called_once_with(10, 20, 4, 3, rgba)


# ---------------------------------------------------------------------------
# Tests: Task 9.10 — Error handling per-rect
# ---------------------------------------------------------------------------


class TestPerRectErrorHandling:
    """Task 9.10: RleDecodeError and CodecError caught per-rect, continue processing."""

    @pytest.mark.asyncio
    async def test_rle_error_skips_rect_continues(self) -> None:
        """RleDecodeError on one rect doesn't prevent subsequent rects."""
        session = _make_session()
        session._surface = MagicMock()
        session._surface.write_pixels = AsyncMock()

        flags = BITMAP_COMPRESSION | NO_BITMAP_COMPRESSION_HDR
        compressed_data = b"\x00" * 5

        rect1 = _build_ts_bitmap_data(0, 0, 1, 1, 2, 2, 16, flags, compressed_data)
        rect2 = _build_ts_bitmap_data(5, 5, 6, 6, 2, 2, 16, flags, compressed_data)
        data = _build_bitmap_update([rect1, rect2])

        call_count = [0]

        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise RleDecodeError(0, 0, "test RLE error")
            return b"\x00" * (2 * 2 * 4)

        with patch("arrdipi.session.RleCodec") as mock_rle:
            mock_rle.decompress.side_effect = side_effect
            await session._process_bitmap_update(data)

        # Only the second rect was written (first failed)
        assert session._surface.write_pixels.call_count == 1
        session._surface.write_pixels.assert_called_once_with(5, 5, 2, 2, b"\x00" * 16)

    @pytest.mark.asyncio
    async def test_codec_error_skips_rect_continues(self) -> None:
        """CodecError on one rect doesn't prevent subsequent rects."""
        session = _make_session()
        session._surface = MagicMock()
        session._surface.write_pixels = AsyncMock()

        # First rect: 32bpp compressed (will fail)
        # Second rect: 16bpp compressed (will succeed)
        flags = BITMAP_COMPRESSION | NO_BITMAP_COMPRESSION_HDR
        rect1 = _build_ts_bitmap_data(0, 0, 1, 1, 2, 2, 32, flags, b"\x10\xFF\xFF")
        rect2 = _build_ts_bitmap_data(5, 5, 6, 6, 2, 2, 16, flags, b"\x00" * 5)
        data = _build_bitmap_update([rect1, rect2])

        with (
            patch("arrdipi.session.Rdp6BitmapCodec") as mock_rdp6,
            patch("arrdipi.session.RleCodec") as mock_rle,
        ):
            mock_rdp6.decompress.side_effect = CodecError("test codec error")
            mock_rle.decompress.return_value = b"\x00" * (2 * 2 * 4)
            await session._process_bitmap_update(data)

        # Only the second rect (16bpp) was written
        assert session._surface.write_pixels.call_count == 1

    @pytest.mark.asyncio
    async def test_error_logged_with_rect_index(self, caplog: pytest.LogCaptureFixture) -> None:
        """Warning log includes rect index."""
        import logging

        session = _make_session()
        session._surface = MagicMock()
        session._surface.write_pixels = AsyncMock()

        flags = BITMAP_COMPRESSION | NO_BITMAP_COMPRESSION_HDR
        rect = _build_ts_bitmap_data(0, 0, 1, 1, 2, 2, 16, flags, b"\x00" * 5)
        data = _build_bitmap_update([rect])

        with patch("arrdipi.session.RleCodec") as mock_rle:
            mock_rle.decompress.side_effect = RleDecodeError(0, 0, "bad data")
            with caplog.at_level(logging.WARNING, logger="arrdipi.session"):
                await session._process_bitmap_update(data)

        assert "rect 0" in caplog.text
        assert "Bitmap decompression failed" in caplog.text


# ---------------------------------------------------------------------------
# Tests: Task 9.11 — Integration-style with synthetic TS_BITMAP_DATA
# ---------------------------------------------------------------------------


class TestSyntheticBitmapData:
    """Task 9.11: Integration tests with synthetic TS_BITMAP_DATA."""

    @pytest.mark.asyncio
    async def test_full_uncompressed_16bpp(self) -> None:
        """Full pipeline: uncompressed 16bpp rect → RleCodec → surface."""
        session = _make_session()

        # Create a 2x2 uncompressed 16bpp bitmap
        # Row size = ((2*2+3) & ~3) = 4 bytes; 2 rows = 8 bytes
        # All black pixels (RGB565: 0x0000)
        raw_pixels = b"\x00\x00\x00\x00" * 2  # 2 rows of 4 bytes each
        flags = 0  # Uncompressed

        rect = _build_ts_bitmap_data(0, 0, 1, 1, 2, 2, 16, flags, raw_pixels)
        data = _build_bitmap_update([rect])

        await session._process_bitmap_update(data)

        # Verify surface was written (2x2 pixels = 16 bytes RGBA)
        dirty = session._surface.get_dirty_rects()
        assert len(dirty) == 1
        assert dirty[0].x == 0
        assert dirty[0].y == 0
        assert dirty[0].w == 2
        assert dirty[0].h == 2

    @pytest.mark.asyncio
    async def test_full_compressed_no_header_16bpp(self) -> None:
        """Compressed 16bpp with NO_BITMAP_COMPRESSION_HDR through real RleCodec."""
        session = _make_session()

        # Create a simple compressed bitmap using a BLACK_ORDER + another pixel
        # For a 1x1 16bpp bitmap: just one pixel
        # Use the actual RLE codec: F9 = BLACK_ORDER (single black pixel)
        rle_data = b"\xF9"  # BLACK_ORDER → 1 pixel of black
        flags = BITMAP_COMPRESSION | NO_BITMAP_COMPRESSION_HDR

        rect = _build_ts_bitmap_data(0, 0, 0, 0, 1, 1, 16, flags, rle_data)
        data = _build_bitmap_update([rect])

        await session._process_bitmap_update(data)

        dirty = session._surface.get_dirty_rects()
        assert len(dirty) == 1
        assert dirty[0].w == 1
        assert dirty[0].h == 1

    @pytest.mark.asyncio
    async def test_full_compressed_with_header_16bpp(self) -> None:
        """Compressed 16bpp with TS_CD_HEADER present (8 bytes skipped)."""
        session = _make_session()

        # TS_CD_HEADER (8 bytes) + RLE data (BLACK_ORDER)
        cd_header = b"\x00" * 8
        rle_data = b"\xF9"  # BLACK_ORDER → 1 black pixel
        bitmap_data = cd_header + rle_data
        flags = BITMAP_COMPRESSION  # NO_BITMAP_COMPRESSION_HDR NOT set

        rect = _build_ts_bitmap_data(0, 0, 0, 0, 1, 1, 16, flags, bitmap_data)
        data = _build_bitmap_update([rect])

        await session._process_bitmap_update(data)

        dirty = session._surface.get_dirty_rects()
        assert len(dirty) == 1

    @pytest.mark.asyncio
    async def test_full_compressed_32bpp_rdp6(self) -> None:
        """Compressed 32bpp routes to Rdp6BitmapCodec through real codec."""
        session = _make_session()

        # Build a valid RDP 6.0 compressed 1x1 bitmap:
        # Header byte: NO_ALPHA(0x10) | RLE flags 0 = all raw planes
        # Each plane: 1 byte for 1 pixel (R, G, B)
        header_byte = 0x10  # NO_ALPHA, all planes raw
        red_plane = b"\xFF"  # 1 pixel red=255
        green_plane = b"\x00"  # 1 pixel green=0
        blue_plane = b"\x00"  # 1 pixel blue=0
        compressed_data = bytes([header_byte]) + red_plane + green_plane + blue_plane

        flags = BITMAP_COMPRESSION | NO_BITMAP_COMPRESSION_HDR

        rect = _build_ts_bitmap_data(0, 0, 0, 0, 1, 1, 32, flags, compressed_data)
        data = _build_bitmap_update([rect])

        await session._process_bitmap_update(data)

        dirty = session._surface.get_dirty_rects()
        assert len(dirty) == 1

        # Read back the pixel — should be R=255, G=0, B=0, A=255
        pixel = await session._surface.read_pixels(0, 0, 1, 1)
        assert pixel == b"\xFF\x00\x00\xFF"

    @pytest.mark.asyncio
    async def test_mixed_rects_partial_failure(self) -> None:
        """Multiple rects where one fails — others still processed."""
        session = _make_session()

        # Rect 1: valid uncompressed 1x1 16bpp (black pixel)
        raw_1 = b"\x00\x00\x00\x00"  # row_size=((1*2+3)&~3)=4, 1 row = 4 bytes
        rect1 = _build_ts_bitmap_data(0, 0, 0, 0, 1, 1, 16, 0, raw_1)

        # Rect 2: compressed but data is invalid/truncated → will cause error
        flags = BITMAP_COMPRESSION | NO_BITMAP_COMPRESSION_HDR
        rect2 = _build_ts_bitmap_data(2, 2, 12, 12, 11, 11, 16, flags, b"\xFF")

        # Rect 3: valid uncompressed 1x1 16bpp
        rect3 = _build_ts_bitmap_data(1, 1, 1, 1, 1, 1, 16, 0, raw_1)

        data = _build_bitmap_update([rect1, rect2, rect3])
        await session._process_bitmap_update(data)

        # Rects 1 and 3 should succeed, rect 2 fails silently
        dirty = session._surface.get_dirty_rects()
        assert len(dirty) >= 2  # At least rects 1 and 3
