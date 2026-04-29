"""Tests for the RLE bitmap decompression codec.

Tests cover:
- Uncompressed bitmap data at each color depth (8, 16, 24, 32 bpp)
- RLE-compressed bitmap data decompression
- Color depth conversion to RGBA
- Error handling for truncated/invalid data
- Vertical flip (bottom-up to top-down)
"""

from __future__ import annotations

import pytest

from arrdipi.codec.rle import RleCodec, _convert_to_rgba, _flip_vertical
from arrdipi.errors import RleDecodeError


class TestUncompressedBitmap:
    """Test uncompressed (raw) bitmap data handling."""

    def test_8bpp_uncompressed_single_pixel(self) -> None:
        """8-bit uncompressed single pixel produces correct RGBA."""
        # 1x1 pixel, value 128 (gray)
        data = bytes([128, 0, 0, 0])  # padded to 4 bytes
        result = RleCodec.decompress(data, 1, 1, 8, compressed=False)
        # Grayscale 128 -> RGBA(128, 128, 128, 255)
        assert result == bytes([128, 128, 128, 255])

    def test_16bpp_uncompressed_single_pixel(self) -> None:
        """16-bit uncompressed single pixel (RGB565) produces correct RGBA."""
        # RGB565: R=31, G=63, B=31 -> 0xFFFF -> white
        data = bytes([0xFF, 0xFF, 0x00, 0x00])  # padded to 4 bytes
        result = RleCodec.decompress(data, 1, 1, 16, compressed=False)
        # Full white in RGB565 -> RGBA(255, 255, 255, 255)
        assert result == bytes([255, 255, 255, 255])

    def test_24bpp_uncompressed_single_pixel(self) -> None:
        """24-bit uncompressed single pixel (BGR) produces correct RGBA."""
        # BGR: B=0, G=128, R=255 -> padded to 4 bytes
        data = bytes([0x00, 0x80, 0xFF, 0x00])  # 3 bytes + 1 padding
        result = RleCodec.decompress(data, 1, 1, 24, compressed=False)
        # BGR(0, 128, 255) -> RGBA(255, 128, 0, 255)
        assert result == bytes([255, 128, 0, 255])

    def test_32bpp_uncompressed_single_pixel(self) -> None:
        """32-bit uncompressed single pixel (BGRX) produces correct RGBA."""
        # BGRX: B=0, G=128, R=255, X=0
        data = bytes([0x00, 0x80, 0xFF, 0x00])
        result = RleCodec.decompress(data, 1, 1, 32, compressed=False)
        # BGRX(0, 128, 255, 0) -> RGBA(255, 128, 0, 255)
        assert result == bytes([255, 128, 0, 255])

    def test_8bpp_uncompressed_2x2(self) -> None:
        """8-bit uncompressed 2x2 bitmap with row padding."""
        # 2 pixels per row, each pixel is 1 byte, row padded to 4 bytes
        # Row 0 (bottom): pixels 0, 255
        # Row 1 (top): pixels 128, 64
        data = bytes([0, 255, 0, 0, 128, 64, 0, 0])  # 2 rows, padded to 4
        result = RleCodec.decompress(data, 2, 2, 8, compressed=False)
        # After vertical flip: row 1 becomes top, row 0 becomes bottom
        # Top row (was row 1): 128, 64
        # Bottom row (was row 0): 0, 255
        expected = bytes([
            128, 128, 128, 255,  # pixel (0,0) = gray 128
            64, 64, 64, 255,    # pixel (1,0) = gray 64
            0, 0, 0, 255,       # pixel (0,1) = black
            255, 255, 255, 255, # pixel (1,1) = white
        ])
        assert result == expected

    def test_16bpp_uncompressed_red_pixel(self) -> None:
        """16-bit RGB565 pure red pixel."""
        # RGB565 red: R=31, G=0, B=0 -> 0xF800 -> little-endian: 0x00, 0xF8
        data = bytes([0x00, 0xF8, 0x00, 0x00])  # padded to 4 bytes
        result = RleCodec.decompress(data, 1, 1, 16, compressed=False)
        # R=31*255//31=255, G=0, B=0
        assert result == bytes([255, 0, 0, 255])

    def test_truncated_uncompressed_raises_error(self) -> None:
        """Truncated uncompressed data raises RleDecodeError."""
        # 2x2 at 32bpp needs 16 bytes, provide only 8
        data = bytes([0] * 8)
        with pytest.raises(RleDecodeError) as exc_info:
            RleCodec.decompress(data, 2, 2, 32, compressed=False)
        assert exc_info.value.rect_index == 0
        assert "Truncated" in str(exc_info.value)

    def test_unsupported_bpp_raises_error(self) -> None:
        """Unsupported color depth raises RleDecodeError."""
        with pytest.raises(RleDecodeError) as exc_info:
            RleCodec.decompress(b"\x00", 1, 1, 4, compressed=False)
        assert "Unsupported color depth" in str(exc_info.value)


class TestRleCompressed:
    """Test RLE-compressed bitmap data decompression."""

    def test_color_run_8bpp(self) -> None:
        """8-bit color run produces repeated pixels."""
        # REGULAR_COLOR_RUN: opcode 0x34 = order_type 0x03, run_length = 4+1=5
        # Followed by 1 byte color value
        width, height = 5, 1
        opcode = 0x34  # order_type=3, low_nibble=4 -> run_length=5
        color = 0x80
        data = bytes([opcode, color])
        result = RleCodec.decompress(data, width, height, 8, compressed=True)
        # 5 pixels of gray 128 -> RGBA
        expected = bytes([128, 128, 128, 255] * 5)
        assert result == expected

    def test_color_run_16bpp(self) -> None:
        """16-bit color run produces repeated pixels."""
        width, height = 3, 1
        # REGULAR_COLOR_RUN: opcode 0x32 = order_type 0x03, run_length = 2+1=3
        opcode = 0x32
        # RGB565 green: R=0, G=63, B=0 -> 0x07E0 -> LE: 0xE0, 0x07
        color = bytes([0xE0, 0x07])
        data = bytes([opcode]) + color
        result = RleCodec.decompress(data, width, height, 16, compressed=True)
        # G=63*255//63=255
        expected = bytes([0, 255, 0, 255] * 3)
        assert result == expected

    def test_color_run_24bpp(self) -> None:
        """24-bit color run produces repeated pixels."""
        width, height = 2, 1
        # REGULAR_COLOR_RUN: opcode 0x31 = order_type 0x03, run_length = 1+1=2
        opcode = 0x31
        # BGR: B=255, G=0, R=0 -> blue
        color = bytes([0xFF, 0x00, 0x00])
        data = bytes([opcode]) + color
        result = RleCodec.decompress(data, width, height, 24, compressed=True)
        # BGR(255, 0, 0) -> RGBA(0, 0, 255, 255)
        expected = bytes([0, 0, 255, 255] * 2)
        assert result == expected

    def test_color_run_32bpp(self) -> None:
        """32-bit color run produces repeated pixels."""
        width, height = 2, 1
        # REGULAR_COLOR_RUN: opcode 0x31 = order_type 0x03, run_length = 1+1=2
        opcode = 0x31
        # BGRX: B=0, G=255, R=0, X=0 -> green
        color = bytes([0x00, 0xFF, 0x00, 0x00])
        data = bytes([opcode]) + color
        result = RleCodec.decompress(data, width, height, 32, compressed=True)
        # BGRX(0, 255, 0, 0) -> RGBA(0, 255, 0, 255)
        expected = bytes([0, 255, 0, 255] * 2)
        assert result == expected

    def test_color_image_8bpp(self) -> None:
        """8-bit color image writes individual pixel values."""
        width, height = 3, 1
        # REGULAR_COLOR_IMAGE: opcode 0x42 = order_type 0x04, run_length = 2+1=3
        opcode = 0x42
        pixels = bytes([10, 20, 30])
        data = bytes([opcode]) + pixels
        result = RleCodec.decompress(data, width, height, 8, compressed=True)
        expected = bytes([
            10, 10, 10, 255,
            20, 20, 20, 255,
            30, 30, 30, 255,
        ])
        assert result == expected

    def test_black_order(self) -> None:
        """BLACK_ORDER writes a single black pixel."""
        width, height = 1, 1
        data = bytes([0xF9])  # BLACK_ORDER
        result = RleCodec.decompress(data, width, height, 8, compressed=True)
        assert result == bytes([0, 0, 0, 255])

    def test_white_order_8bpp(self) -> None:
        """WHITE_ORDER writes a single white pixel at 8bpp."""
        width, height = 1, 1
        data = bytes([0xFA])  # WHITE_ORDER
        result = RleCodec.decompress(data, width, height, 8, compressed=True)
        # 8bpp white = 0xFF -> grayscale 255
        assert result == bytes([255, 255, 255, 255])

    def test_white_order_24bpp(self) -> None:
        """WHITE_ORDER writes a single white pixel at 24bpp."""
        width, height = 1, 1
        data = bytes([0xFA])  # WHITE_ORDER
        result = RleCodec.decompress(data, width, height, 24, compressed=True)
        assert result == bytes([255, 255, 255, 255])

    def test_bg_run_first_scanline(self) -> None:
        """Background run on first scanline writes black pixels."""
        width, height = 3, 1
        # REGULAR_BG_RUN: opcode 0x02 = order_type 0x00, run_length = 2+1=3
        opcode = 0x02
        data = bytes([opcode])
        result = RleCodec.decompress(data, width, height, 8, compressed=True)
        # Background is black on first scanline
        expected = bytes([0, 0, 0, 255] * 3)
        assert result == expected

    def test_fg_run_first_scanline(self) -> None:
        """Foreground run on first scanline writes foreground color."""
        width, height = 3, 1
        # REGULAR_FG_RUN: opcode 0x12 = order_type 0x01, run_length = 2+1=3
        opcode = 0x12
        data = bytes([opcode])
        result = RleCodec.decompress(data, width, height, 8, compressed=True)
        # Default foreground is 0xFF for 8bpp
        expected = bytes([255, 255, 255, 255] * 3)
        assert result == expected

    def test_extended_run_length(self) -> None:
        """Extended run length (low nibble = 0) reads next byte."""
        width, height = 10, 1
        # REGULAR_COLOR_RUN with low nibble 0: opcode 0x30
        # Next byte = 9 -> run_length = 9 + 1 = 10
        opcode = 0x30
        ext_length = 9  # run_length = 9 + 1 = 10
        color = 0x42
        data = bytes([opcode, ext_length, color])
        result = RleCodec.decompress(data, width, height, 8, compressed=True)
        expected = bytes([0x42, 0x42, 0x42, 255] * 10)
        assert result == expected

    def test_bg_run_second_scanline_copies_above(self) -> None:
        """Background run on second scanline copies pixels from above."""
        width, height = 2, 2
        # First scanline: color run of 2 pixels with value 0x80
        # Second scanline: bg run of 2 pixels (copies from above)
        color_run = bytes([0x31, 0x80])  # COLOR_RUN: 2 pixels of 0x80
        bg_run = bytes([0x01])  # BG_RUN: 2 pixels (copies from above)
        data = color_run + bg_run
        result = RleCodec.decompress(data, width, height, 8, compressed=True)
        # After flip: top row was second scanline (copy of first)
        # Both rows should be gray 128
        expected = bytes([128, 128, 128, 255] * 4)
        assert result == expected

    def test_truncated_rle_color_image_raises_error(self) -> None:
        """Truncated RLE color image data raises RleDecodeError."""
        width, height = 5, 1
        # COLOR_IMAGE expecting 5 pixels at 32bpp = 20 bytes, but provide only 4
        opcode = 0x44  # order_type=4, run_length=4+1=5
        data = bytes([opcode, 0x00, 0x00, 0x00, 0x00])  # Only 1 pixel worth
        with pytest.raises(RleDecodeError) as exc_info:
            RleCodec.decompress(data, width, height, 32, compressed=True)
        assert exc_info.value.rect_index == 0

    def test_unknown_opcode_raises_error(self) -> None:
        """Unknown RLE opcode raises RleDecodeError."""
        width, height = 1, 1
        # 0x50 has order_type 0x05 which is not defined
        data = bytes([0x50])
        with pytest.raises(RleDecodeError) as exc_info:
            RleCodec.decompress(data, width, height, 8, compressed=True)
        assert "Unknown RLE opcode" in str(exc_info.value)

    def test_rect_index_in_error(self) -> None:
        """RleDecodeError includes the correct rectangle index."""
        data = bytes([0x50])  # Unknown opcode
        with pytest.raises(RleDecodeError) as exc_info:
            RleCodec.decompress(data, 1, 1, 8, compressed=True, rect_index=7)
        assert exc_info.value.rect_index == 7

    def test_set_fg_fg_run(self) -> None:
        """LITE_SET_FG_FG_RUN sets foreground and writes run."""
        width, height = 3, 1
        # LITE_SET_FG_FG_RUN: opcode 0xC2 = order_type 0x0C, low_nibble=2
        # run_length = 2+1 = 3, followed by new fg color
        opcode = 0xC2
        fg = 0x42
        data = bytes([opcode, fg])
        result = RleCodec.decompress(data, width, height, 8, compressed=True)
        # Foreground 0x42 = gray 66
        expected = bytes([66, 66, 66, 255] * 3)
        assert result == expected

    def test_dithered_run(self) -> None:
        """LITE_DITHERED_RUN alternates two colors."""
        width, height = 4, 1
        # LITE_DITHERED_RUN: opcode 0xE1 = order_type 0x0E, low_nibble=1
        # run_length = 1+1 = 2, produces 2*2=4 pixels alternating
        opcode = 0xE1
        color1 = 0x10
        color2 = 0x20
        data = bytes([opcode, color1, color2])
        result = RleCodec.decompress(data, width, height, 8, compressed=True)
        expected = bytes([
            16, 16, 16, 255,   # color1
            32, 32, 32, 255,   # color2
            16, 16, 16, 255,   # color1
            32, 32, 32, 255,   # color2
        ])
        assert result == expected


class TestColorConversion:
    """Test color depth conversion to RGBA."""

    def test_16bpp_rgb565_blue(self) -> None:
        """16-bit RGB565 pure blue pixel."""
        # RGB565 blue: R=0, G=0, B=31 -> 0x001F -> LE: 0x1F, 0x00
        raw = bytes([0x1F, 0x00])
        result = _convert_to_rgba(raw, 1, 1, 16)
        # B=31*255//31=255
        assert result == bytes([0, 0, 255, 255])

    def test_24bpp_bgr_to_rgba(self) -> None:
        """24-bit BGR to RGBA conversion."""
        # BGR: B=100, G=150, R=200
        raw = bytes([100, 150, 200])
        result = _convert_to_rgba(raw, 1, 1, 24)
        assert result == bytes([200, 150, 100, 255])

    def test_32bpp_bgrx_to_rgba(self) -> None:
        """32-bit BGRX to RGBA conversion (X ignored, alpha=255)."""
        # BGRX: B=50, G=100, R=150, X=99
        raw = bytes([50, 100, 150, 99])
        result = _convert_to_rgba(raw, 1, 1, 32)
        assert result == bytes([150, 100, 50, 255])

    def test_8bpp_grayscale(self) -> None:
        """8-bit grayscale palette conversion."""
        raw = bytes([0, 127, 255])
        result = _convert_to_rgba(raw, 3, 1, 8)
        expected = bytes([
            0, 0, 0, 255,
            127, 127, 127, 255,
            255, 255, 255, 255,
        ])
        assert result == expected


class TestVerticalFlip:
    """Test vertical flip of RGBA data."""

    def test_flip_2_rows(self) -> None:
        """Flipping 2 rows swaps them."""
        # 2x1 image (2 pixels wide, 1 pixel per row for 2 rows)
        width, height = 1, 2
        # Row 0: red, Row 1: blue
        rgba = bytes([
            255, 0, 0, 255,  # row 0 (bottom in RDP)
            0, 0, 255, 255,  # row 1 (top in RDP)
        ])
        result = _flip_vertical(rgba, width, height)
        expected = bytes([
            0, 0, 255, 255,  # row 1 becomes top
            255, 0, 0, 255,  # row 0 becomes bottom
        ])
        assert result == expected

    def test_flip_single_row_unchanged(self) -> None:
        """Flipping a single row returns the same data."""
        width, height = 2, 1
        rgba = bytes([255, 0, 0, 255, 0, 255, 0, 255])
        result = _flip_vertical(rgba, width, height)
        assert result == rgba
