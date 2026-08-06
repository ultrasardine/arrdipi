"""Tests for RDP 6.0 Bitmap Compression codec (arrdipi/codec/rdp6_bitmap.py).

Verifies correct RGBA output from known 32 bpp RDP 6.0 compressed bitmap data.
"""

from __future__ import annotations

import struct

import pytest

from arrdipi.codec.rdp6_bitmap import Rdp6BitmapCodec
from arrdipi.errors import CodecError


# ---------------------------------------------------------------------------
# Helper to build RDP 6.0 compressed streams for testing
# ---------------------------------------------------------------------------


def _rle_encode_plane(plane_data: bytes) -> bytes:
    """Encode a plane using the RDP 6.0 NULL-run RLE scheme.

    - Non-zero bytes: literal.
    - Zero bytes: collapsed into 0x00 + count byte (N), representing N+1 zeros.
    """
    result = bytearray()
    i = 0
    length = len(plane_data)

    while i < length:
        if plane_data[i] != 0:
            result.append(plane_data[i])
            i += 1
        else:
            # Count consecutive zeros
            run_start = i
            while i < length and plane_data[i] == 0 and (i - run_start) < 256:
                i += 1
            run_length = i - run_start
            # Encode as 0x00 + (run_length - 1)
            result.append(0x00)
            result.append(run_length - 1)

    return bytes(result)


def _build_rdp6_stream(
    red: bytes,
    green: bytes,
    blue: bytes,
    alpha: bytes | None = None,
    rle_alpha: bool = False,
    rle_red: bool = False,
    rle_green: bool = False,
    rle_blue: bool = False,
) -> bytes:
    """Build a complete RDP 6.0 compressed bitmap stream.

    Args:
        red: Raw red plane data.
        green: Raw green plane data.
        blue: Raw blue plane data.
        alpha: Raw alpha plane data (None means no alpha, opaque assumed).
        rle_alpha: Whether to RLE-compress the alpha plane.
        rle_red: Whether to RLE-compress the red plane.
        rle_green: Whether to RLE-compress the green plane.
        rle_blue: Whether to RLE-compress the blue plane.

    Returns:
        Complete RDP 6.0 compressed stream with header.
    """
    header = 0x00
    if rle_alpha:
        header |= 0x01
    if rle_red:
        header |= 0x02
    if rle_green:
        header |= 0x04
    if rle_blue:
        header |= 0x08
    if alpha is None:
        header |= 0x10  # NO_ALPHA

    parts = [bytes([header])]

    if alpha is not None:
        parts.append(_rle_encode_plane(alpha) if rle_alpha else alpha)

    parts.append(_rle_encode_plane(red) if rle_red else red)
    parts.append(_rle_encode_plane(green) if rle_green else green)
    parts.append(_rle_encode_plane(blue) if rle_blue else blue)

    return b"".join(parts)


# ---------------------------------------------------------------------------
# Tests: Basic decompression
# ---------------------------------------------------------------------------


class TestRdp6BitmapCodecBasic:
    """Test basic decompression with raw (uncompressed) planes."""

    def test_single_pixel_no_alpha(self) -> None:
        """Decompress a 1x1 bitmap with no alpha plane (opaque)."""
        # Red=0xAA, Green=0xBB, Blue=0xCC, Alpha=0xFF (implied)
        stream = _build_rdp6_stream(
            red=b"\xAA", green=b"\xBB", blue=b"\xCC", alpha=None
        )
        result = Rdp6BitmapCodec.decompress(stream, 1, 1)
        assert result == bytes([0xAA, 0xBB, 0xCC, 0xFF])

    def test_single_pixel_with_alpha(self) -> None:
        """Decompress a 1x1 bitmap with explicit alpha plane."""
        stream = _build_rdp6_stream(
            red=b"\x11", green=b"\x22", blue=b"\x33", alpha=b"\x80"
        )
        result = Rdp6BitmapCodec.decompress(stream, 1, 1)
        assert result == bytes([0x11, 0x22, 0x33, 0x80])

    def test_2x2_no_alpha(self) -> None:
        """Decompress a 2x2 bitmap with raw planes and no alpha."""
        # 4 pixels: (R,G,B,A) for each
        red = bytes([0x10, 0x20, 0x30, 0x40])
        green = bytes([0x50, 0x60, 0x70, 0x80])
        blue = bytes([0x90, 0xA0, 0xB0, 0xC0])

        stream = _build_rdp6_stream(red=red, green=green, blue=blue, alpha=None)
        result = Rdp6BitmapCodec.decompress(stream, 2, 2)

        expected = bytes([
            0x10, 0x50, 0x90, 0xFF,  # pixel (0,0)
            0x20, 0x60, 0xA0, 0xFF,  # pixel (1,0)
            0x30, 0x70, 0xB0, 0xFF,  # pixel (0,1)
            0x40, 0x80, 0xC0, 0xFF,  # pixel (1,1)
        ])
        assert result == expected

    def test_2x2_with_alpha(self) -> None:
        """Decompress a 2x2 bitmap with explicit alpha values."""
        red = bytes([0xFF, 0x00, 0x00, 0xFF])
        green = bytes([0x00, 0xFF, 0x00, 0xFF])
        blue = bytes([0x00, 0x00, 0xFF, 0xFF])
        alpha = bytes([0xFF, 0x80, 0x40, 0x00])

        stream = _build_rdp6_stream(red=red, green=green, blue=blue, alpha=alpha)
        result = Rdp6BitmapCodec.decompress(stream, 2, 2)

        expected = bytes([
            0xFF, 0x00, 0x00, 0xFF,  # Red, full alpha
            0x00, 0xFF, 0x00, 0x80,  # Green, half alpha
            0x00, 0x00, 0xFF, 0x40,  # Blue, quarter alpha
            0xFF, 0xFF, 0xFF, 0x00,  # White, fully transparent
        ])
        assert result == expected

    def test_output_size(self) -> None:
        """Output is always width * height * 4 bytes."""
        width, height = 4, 3
        num_pixels = width * height
        red = bytes([0x42] * num_pixels)
        green = bytes([0x43] * num_pixels)
        blue = bytes([0x44] * num_pixels)

        stream = _build_rdp6_stream(red=red, green=green, blue=blue, alpha=None)
        result = Rdp6BitmapCodec.decompress(stream, width, height)

        assert len(result) == width * height * 4


# ---------------------------------------------------------------------------
# Tests: RLE-compressed planes
# ---------------------------------------------------------------------------


class TestRdp6BitmapCodecRle:
    """Test decompression with RLE-compressed planes."""

    def test_rle_all_zeros_plane(self) -> None:
        """A plane of all zeros (black channel) compresses via RLE."""
        width, height = 4, 4
        num_pixels = width * height
        red = bytes([0x00] * num_pixels)
        green = bytes([0x00] * num_pixels)
        blue = bytes([0x00] * num_pixels)

        stream = _build_rdp6_stream(
            red=red, green=green, blue=blue, alpha=None,
            rle_red=True, rle_green=True, rle_blue=True,
        )
        result = Rdp6BitmapCodec.decompress(stream, width, height)

        # All pixels should be (0, 0, 0, 0xFF) - black, opaque
        for i in range(num_pixels):
            offset = i * 4
            assert result[offset] == 0x00      # R
            assert result[offset + 1] == 0x00  # G
            assert result[offset + 2] == 0x00  # B
            assert result[offset + 3] == 0xFF  # A (no alpha → opaque)

    def test_rle_non_zero_literals(self) -> None:
        """Non-zero values in RLE are passed through as literals."""
        width, height = 3, 1
        # All non-zero values: no RLE encoding needed (just literals)
        red = bytes([0x11, 0x22, 0x33])
        green = bytes([0x44, 0x55, 0x66])
        blue = bytes([0x77, 0x88, 0x99])

        stream = _build_rdp6_stream(
            red=red, green=green, blue=blue, alpha=None,
            rle_red=True, rle_green=True, rle_blue=True,
        )
        result = Rdp6BitmapCodec.decompress(stream, width, height)

        expected = bytes([
            0x11, 0x44, 0x77, 0xFF,
            0x22, 0x55, 0x88, 0xFF,
            0x33, 0x66, 0x99, 0xFF,
        ])
        assert result == expected

    def test_rle_mixed_zeros_and_literals(self) -> None:
        """Planes with a mix of zeros and non-zero values decode correctly."""
        width, height = 6, 1
        # Pattern: [0xFF, 0x00, 0x00, 0x00, 0xFF, 0x42]
        red_raw = bytes([0xFF, 0x00, 0x00, 0x00, 0xFF, 0x42])
        green_raw = bytes([0x10, 0x20, 0x30, 0x40, 0x50, 0x60])
        blue_raw = bytes([0x00] * 6)

        stream = _build_rdp6_stream(
            red=red_raw, green=green_raw, blue=blue_raw, alpha=None,
            rle_red=True, rle_green=True, rle_blue=True,
        )
        result = Rdp6BitmapCodec.decompress(stream, width, height)

        # Verify each pixel
        for i in range(6):
            offset = i * 4
            assert result[offset] == red_raw[i]
            assert result[offset + 1] == green_raw[i]
            assert result[offset + 2] == blue_raw[i]
            assert result[offset + 3] == 0xFF

    def test_rle_alpha_plane(self) -> None:
        """RLE-compressed alpha plane decodes correctly."""
        width, height = 4, 1
        alpha_raw = bytes([0xFF, 0xFF, 0xFF, 0x00])
        red = bytes([0x80] * 4)
        green = bytes([0x80] * 4)
        blue = bytes([0x80] * 4)

        stream = _build_rdp6_stream(
            red=red, green=green, blue=blue, alpha=alpha_raw,
            rle_alpha=True,
        )
        result = Rdp6BitmapCodec.decompress(stream, width, height)

        # First 3 pixels have alpha=0xFF, last has alpha=0x00
        assert result[3] == 0xFF
        assert result[7] == 0xFF
        assert result[11] == 0xFF
        assert result[15] == 0x00

    def test_rle_long_zero_run(self) -> None:
        """Long runs of zeros compress and decompress correctly."""
        width, height = 1, 200
        num_pixels = width * height
        # All-zero plane
        red_raw = bytes([0x00] * num_pixels)
        green_raw = bytes([0x01] * num_pixels)
        blue_raw = bytes([0x02] * num_pixels)

        stream = _build_rdp6_stream(
            red=red_raw, green=green_raw, blue=blue_raw, alpha=None,
            rle_red=True, rle_green=True, rle_blue=True,
        )
        result = Rdp6BitmapCodec.decompress(stream, width, height)

        for i in range(num_pixels):
            offset = i * 4
            assert result[offset] == 0x00
            assert result[offset + 1] == 0x01
            assert result[offset + 2] == 0x02
            assert result[offset + 3] == 0xFF

    def test_rle_exactly_256_zeros(self) -> None:
        """256 consecutive zeros require multiple RLE runs (max run = 256)."""
        width, height = 256, 1
        red_raw = bytes([0x00] * 256)
        green_raw = bytes([0xAB] * 256)
        blue_raw = bytes([0xCD] * 256)

        stream = _build_rdp6_stream(
            red=red_raw, green=green_raw, blue=blue_raw, alpha=None,
            rle_red=True, rle_green=True, rle_blue=True,
        )
        result = Rdp6BitmapCodec.decompress(stream, width, height)

        for i in range(256):
            offset = i * 4
            assert result[offset] == 0x00
            assert result[offset + 1] == 0xAB
            assert result[offset + 2] == 0xCD
            assert result[offset + 3] == 0xFF

    def test_rle_partial_compression(self) -> None:
        """Only some planes are RLE-compressed, others are raw."""
        width, height = 2, 2
        num_pixels = width * height
        red = bytes([0xFF, 0x00, 0x00, 0xFF])  # RLE-compressed
        green = bytes([0x10, 0x20, 0x30, 0x40])  # raw
        blue = bytes([0x00, 0x00, 0x00, 0x00])  # RLE-compressed

        stream = _build_rdp6_stream(
            red=red, green=green, blue=blue, alpha=None,
            rle_red=True, rle_green=False, rle_blue=True,
        )
        result = Rdp6BitmapCodec.decompress(stream, width, height)

        expected = bytes([
            0xFF, 0x10, 0x00, 0xFF,
            0x00, 0x20, 0x00, 0xFF,
            0x00, 0x30, 0x00, 0xFF,
            0xFF, 0x40, 0x00, 0xFF,
        ])
        assert result == expected


# ---------------------------------------------------------------------------
# Tests: Known 32 bpp compressed bitmap data
# ---------------------------------------------------------------------------


class TestRdp6BitmapCodecKnownData:
    """Test with hand-crafted known compressed data verifying exact RGBA output."""

    def test_solid_red_4x4(self) -> None:
        """A solid red 4x4 bitmap with no alpha and RLE compression."""
        width, height = 4, 4
        num_pixels = width * height

        # Solid red: R=0xFF, G=0x00, B=0x00
        # Header: NO_ALPHA(0x10) | RLE_RED(0x02) | RLE_GREEN(0x04) | RLE_BLUE(0x08) = 0x1E
        # Red plane (RLE): all 0xFF → 16 literal 0xFF bytes
        # Green plane (RLE): all 0x00 → 0x00 + 0x0F (16 zeros)
        # Blue plane (RLE): all 0x00 → 0x00 + 0x0F (16 zeros)
        header = bytes([0x1E])
        red_rle = bytes([0xFF] * 16)  # All literals
        green_rle = bytes([0x00, 0x0F])  # 16 zeros
        blue_rle = bytes([0x00, 0x0F])  # 16 zeros

        compressed = header + red_rle + green_rle + blue_rle
        result = Rdp6BitmapCodec.decompress(compressed, width, height)

        assert len(result) == 64  # 4*4*4
        for i in range(num_pixels):
            offset = i * 4
            assert result[offset] == 0xFF      # R
            assert result[offset + 1] == 0x00  # G
            assert result[offset + 2] == 0x00  # B
            assert result[offset + 3] == 0xFF  # A (no alpha → opaque)

    def test_gradient_row(self) -> None:
        """A 4x1 horizontal gradient with raw planes."""
        width, height = 4, 1
        # Header: NO_ALPHA (0x10), all planes raw
        header = bytes([0x10])
        red = bytes([0x00, 0x55, 0xAA, 0xFF])
        green = bytes([0xFF, 0xAA, 0x55, 0x00])
        blue = bytes([0x80, 0x80, 0x80, 0x80])

        compressed = header + red + green + blue
        result = Rdp6BitmapCodec.decompress(compressed, width, height)

        expected = bytes([
            0x00, 0xFF, 0x80, 0xFF,
            0x55, 0xAA, 0x80, 0xFF,
            0xAA, 0x55, 0x80, 0xFF,
            0xFF, 0x00, 0x80, 0xFF,
        ])
        assert result == expected

    def test_transparent_checkerboard(self) -> None:
        """A 2x2 checkerboard with varying alpha."""
        width, height = 2, 2
        # Header: has alpha, all raw (0x00)
        header = bytes([0x00])
        alpha = bytes([0xFF, 0x00, 0x00, 0xFF])
        red = bytes([0xFF, 0x00, 0x00, 0xFF])
        green = bytes([0xFF, 0x00, 0x00, 0xFF])
        blue = bytes([0xFF, 0x00, 0x00, 0xFF])

        compressed = header + alpha + red + green + blue
        result = Rdp6BitmapCodec.decompress(compressed, width, height)

        expected = bytes([
            0xFF, 0xFF, 0xFF, 0xFF,  # White, opaque
            0x00, 0x00, 0x00, 0x00,  # Black, transparent
            0x00, 0x00, 0x00, 0x00,  # Black, transparent
            0xFF, 0xFF, 0xFF, 0xFF,  # White, opaque
        ])
        assert result == expected

    def test_realistic_desktop_tile_rle(self) -> None:
        """Simulate a realistic desktop tile: mostly one color with a few details."""
        width, height = 8, 8
        num_pixels = width * height

        # Background is blue (desktop), with a white pixel at (3,3) and (4,4)
        red_raw = bytearray([0x00] * num_pixels)
        green_raw = bytearray([0x00] * num_pixels)
        blue_raw = bytearray([0x80] * num_pixels)
        alpha_raw = None  # No alpha

        # Add white detail pixels
        red_raw[3 * 8 + 3] = 0xFF
        green_raw[3 * 8 + 3] = 0xFF
        blue_raw[3 * 8 + 3] = 0xFF
        red_raw[4 * 8 + 4] = 0xFF
        green_raw[4 * 8 + 4] = 0xFF
        blue_raw[4 * 8 + 4] = 0xFF

        stream = _build_rdp6_stream(
            red=bytes(red_raw), green=bytes(green_raw), blue=bytes(blue_raw),
            alpha=alpha_raw,
            rle_red=True, rle_green=True, rle_blue=True,
        )
        result = Rdp6BitmapCodec.decompress(stream, width, height)

        assert len(result) == num_pixels * 4

        # Check background pixel (0,0): R=0, G=0, B=0x80, A=0xFF
        assert result[0:4] == bytes([0x00, 0x00, 0x80, 0xFF])

        # Check detail pixel at (3,3) = index 27: R=0xFF, G=0xFF, B=0xFF, A=0xFF
        idx = (3 * 8 + 3) * 4
        assert result[idx:idx + 4] == bytes([0xFF, 0xFF, 0xFF, 0xFF])

        # Check detail pixel at (4,4) = index 36: R=0xFF, G=0xFF, B=0xFF, A=0xFF
        idx = (4 * 8 + 4) * 4
        assert result[idx:idx + 4] == bytes([0xFF, 0xFF, 0xFF, 0xFF])


# ---------------------------------------------------------------------------
# Tests: Error handling
# ---------------------------------------------------------------------------


class TestRdp6BitmapCodecErrors:
    """Test error handling for malformed data."""

    def test_empty_data_raises_codec_error(self) -> None:
        """Empty data raises CodecError."""
        with pytest.raises(CodecError, match="empty compressed data"):
            Rdp6BitmapCodec.decompress(b"", 1, 1)

    def test_zero_width_raises_codec_error(self) -> None:
        """Zero width raises CodecError."""
        with pytest.raises(CodecError, match="invalid dimensions"):
            Rdp6BitmapCodec.decompress(b"\x10\xFF", 0, 1)

    def test_zero_height_raises_codec_error(self) -> None:
        """Zero height raises CodecError."""
        with pytest.raises(CodecError, match="invalid dimensions"):
            Rdp6BitmapCodec.decompress(b"\x10\xFF", 1, 0)

    def test_negative_dimensions_raises_codec_error(self) -> None:
        """Negative dimensions raise CodecError."""
        with pytest.raises(CodecError, match="invalid dimensions"):
            Rdp6BitmapCodec.decompress(b"\x10\xFF", -1, 5)

    def test_truncated_raw_plane_raises_codec_error(self) -> None:
        """Insufficient raw plane data raises CodecError."""
        # Header: NO_ALPHA, all raw → needs 4 bytes per plane for 2x2
        # Only provide partial red plane
        header = bytes([0x10])
        partial_red = bytes([0xFF, 0xFF])  # Only 2 of 4 bytes
        with pytest.raises(CodecError, match="insufficient data"):
            Rdp6BitmapCodec.decompress(header + partial_red, 2, 2)

    def test_truncated_rle_plane_raises_codec_error(self) -> None:
        """Truncated RLE stream raises CodecError."""
        # Header: NO_ALPHA, RLE_RED → but only 1 pixel of data for a 4x4 bitmap
        header = bytes([0x12])  # NO_ALPHA + RLE_RED
        rle_data = bytes([0xFF])  # Only 1 literal for 16 pixels needed
        # Green and Blue would need to follow but the RLE will fail first
        with pytest.raises(CodecError):
            Rdp6BitmapCodec.decompress(header + rle_data, 4, 4)

    def test_truncated_rle_run_length_raises_codec_error(self) -> None:
        """A zero byte without a following count byte raises CodecError."""
        # Header: NO_ALPHA + RLE_RED
        header = bytes([0x12])
        # RLE data: zero byte at end with no count following
        rle_data = bytes([0xFF, 0x00])  # Literal 0xFF, then zero escape with no count
        with pytest.raises(CodecError, match="truncated run length"):
            Rdp6BitmapCodec.decompress(header + rle_data, 4, 4)
