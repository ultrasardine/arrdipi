"""RDP 6.0 Bitmap Compression codec for 32 bpp bitmaps.

Implements the RDP 6.0 Bitmap Compressed Stream format as described in
[MS-RDPEGDI] Section 2.2.2.5.1. This codec handles 32 bpp bitmaps using
a planar approach where Alpha, Red, Green, and Blue channels are encoded
as separate planes with optional per-plane RLE compression.

Output is always RGBA (4 bytes per pixel) for direct use with the
graphics surface.
"""

from __future__ import annotations

from arrdipi.errors import CodecError

# Format header flag bits per [MS-RDPEGDI] 2.2.2.5.1
_RLE_ALPHA = 0x01  # Alpha plane is RLE-compressed
_RLE_RED = 0x02  # Red plane is RLE-compressed
_RLE_GREEN = 0x04  # Green plane is RLE-compressed
_RLE_BLUE = 0x08  # Blue plane is RLE-compressed
_NO_ALPHA = 0x10  # No alpha plane present (assume fully opaque)


def _decompress_plane_rle(data: bytes, offset: int, num_pixels: int) -> tuple[bytes, int]:
    """Decompress a single RLE-compressed plane.

    Uses the RDP 6.0 NULL-run RLE scheme:
    - Non-zero byte: literal pixel value, output directly.
    - Zero byte: followed by a count byte N, output (N + 1) zeros total.

    Args:
        data: Full compressed data buffer.
        offset: Starting offset within data for this plane.
        num_pixels: Expected number of pixels to decompress (width * height).

    Returns:
        Tuple of (decompressed plane bytes, new offset after consumed data).

    Raises:
        CodecError: If data is truncated or malformed.
    """
    output = bytearray(num_pixels)
    out_pos = 0
    data_len = len(data)

    while out_pos < num_pixels:
        if offset >= data_len:
            raise CodecError(
                f"RDP 6.0 RLE: truncated plane data at offset {offset}, "
                f"decoded {out_pos}/{num_pixels} pixels"
            )

        byte = data[offset]
        offset += 1

        if byte != 0:
            # Literal non-zero value
            output[out_pos] = byte
            out_pos += 1
        else:
            # Zero run: next byte is run count
            if offset >= data_len:
                raise CodecError(
                    f"RDP 6.0 RLE: truncated run length at offset {offset}"
                )
            run_length = data[offset] + 1  # N+1 total zeros
            offset += 1

            # Bounds check
            if out_pos + run_length > num_pixels:
                run_length = num_pixels - out_pos

            # Output is already zeroed by bytearray(), just advance
            out_pos += run_length

    return bytes(output), offset


def _read_plane_raw(data: bytes, offset: int, num_pixels: int) -> tuple[bytes, int]:
    """Read a raw (uncompressed) plane.

    Args:
        data: Full data buffer.
        offset: Starting offset for this plane.
        num_pixels: Number of pixels (bytes) to read.

    Returns:
        Tuple of (raw plane bytes, new offset after consumed data).

    Raises:
        CodecError: If insufficient data remains.
    """
    end = offset + num_pixels
    if end > len(data):
        raise CodecError(
            f"RDP 6.0 raw plane: insufficient data, need {num_pixels} bytes "
            f"at offset {offset}, but only {len(data) - offset} available"
        )
    return data[offset:end], end


class Rdp6BitmapCodec:
    """RDP 6.0 Bitmap Compression decoder per [MS-RDPEGDI] 2.2.2.5.1.

    Used for 32 bpp compressed bitmaps. The compressed stream consists of
    a format header byte followed by separate color planes (Alpha, Red,
    Green, Blue) which may be individually RLE-compressed or raw.
    """

    @staticmethod
    def decompress(data: bytes, width: int, height: int) -> bytes:
        """Decompress RDP 6.0 bitmap data to RGBA pixel buffer.

        Args:
            data: Compressed bitmap data (RDP 6.0 format).
            width: Bitmap width in pixels.
            height: Bitmap height in pixels.

        Returns:
            RGBA pixel data (width * height * 4 bytes), top-down scanline order.

        Raises:
            CodecError: If decompression fails due to malformed or truncated data.
        """
        if width <= 0 or height <= 0:
            raise CodecError(
                f"RDP 6.0: invalid dimensions {width}x{height}"
            )

        if len(data) < 1:
            raise CodecError("RDP 6.0: empty compressed data (missing header)")

        num_pixels = width * height

        # Parse format header
        header = data[0]
        offset = 1

        # Determine alpha plane
        has_alpha = not (header & _NO_ALPHA)

        if has_alpha:
            if header & _RLE_ALPHA:
                alpha_plane, offset = _decompress_plane_rle(data, offset, num_pixels)
            else:
                alpha_plane, offset = _read_plane_raw(data, offset, num_pixels)
        else:
            # No alpha data — all pixels fully opaque
            alpha_plane = bytes([0xFF]) * num_pixels

        # Red plane
        if header & _RLE_RED:
            red_plane, offset = _decompress_plane_rle(data, offset, num_pixels)
        else:
            red_plane, offset = _read_plane_raw(data, offset, num_pixels)

        # Green plane
        if header & _RLE_GREEN:
            green_plane, offset = _decompress_plane_rle(data, offset, num_pixels)
        else:
            green_plane, offset = _read_plane_raw(data, offset, num_pixels)

        # Blue plane
        if header & _RLE_BLUE:
            blue_plane, offset = _decompress_plane_rle(data, offset, num_pixels)
        else:
            blue_plane, offset = _read_plane_raw(data, offset, num_pixels)

        # Interleave planes into RGBA
        rgba = bytearray(num_pixels * 4)
        for i in range(num_pixels):
            out = i * 4
            rgba[out] = red_plane[i]
            rgba[out + 1] = green_plane[i]
            rgba[out + 2] = blue_plane[i]
            rgba[out + 3] = alpha_plane[i]

        return bytes(rgba)
