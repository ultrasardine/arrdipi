"""RLE bitmap decompression codec for RDP.

Implements the Interleaved RLE compression format as defined in
[MS-RDPBCGR] Section 2.2.9.1.1.3.1.2.2 (Compressed Bitmap Data).

Supports 8-bit, 16-bit, 24-bit, and 32-bit color depths for both
compressed (RLE) and uncompressed (raw) bitmap data. Output is always
RGBA (4 bytes per pixel) for direct use with the graphics surface.
"""

from __future__ import annotations

from arrdipi.errors import RleDecodeError

# Interleaved RLE opcodes per [MS-RDPBCGR] 2.2.9.1.1.3.1.2.2
# The high nibble of the first byte encodes the order type.
# The low nibble encodes the run length (or 0 if extended).

# Regular orders (color specified in stream)
_REGULAR_BG_RUN = 0x00
_MEGA_MEGA_BG_RUN = 0xF0
_REGULAR_FG_RUN = 0x01
_MEGA_MEGA_FG_RUN = 0xF1
_REGULAR_FGBG_IMAGE = 0x02
_MEGA_MEGA_FGBG_IMAGE = 0xF2
_REGULAR_COLOR_RUN = 0x03
_MEGA_MEGA_COLOR_RUN = 0xF3
_REGULAR_COLOR_IMAGE = 0x04
_MEGA_MEGA_COLOR_IMAGE = 0xF4

# Lite orders (use previous foreground color)
_LITE_SET_FG_FG_RUN = 0x0C
_MEGA_MEGA_SET_FG_RUN = 0xF6
_LITE_SET_FG_FGBG_IMAGE = 0x0D
_MEGA_MEGA_SET_FGBG_IMAGE = 0xF7
_LITE_DITHERED_RUN = 0x0E
_MEGA_MEGA_DITHERED_RUN = 0xF8

# Special orders
_BLACK_ORDER = 0xF9
_WHITE_ORDER = 0xFA
_START_LOSSY_ORDER = 0xFB

# Default grayscale palette for 8-bit color depth
_GRAYSCALE_PALETTE: list[tuple[int, int, int]] = [
    (i, i, i) for i in range(256)
]


def _extract_run_length(header_byte: int, data: bytes, offset: int) -> tuple[int, int]:
    """Extract run length from the header byte and optional extended bytes.

    For regular orders, the low nibble of the header byte contains the
    run length minus a base value. If the low nibble is 0, the next byte
    contains the extended run length.

    Returns (run_length, bytes_consumed_for_length).
    """
    run_length = header_byte & 0x0F
    if run_length == 0:
        if offset >= len(data):
            return 0, 0
        run_length = data[offset] + 1
        return run_length, 1
    else:
        run_length += 1
        return run_length, 0


def _extract_run_length_lite(header_byte: int, data: bytes, offset: int) -> tuple[int, int]:
    """Extract run length for lite orders (low nibble has different base).

    For lite orders the low nibble encodes run_length - 1.
    If low nibble is 0x0F, the next byte is the extended length.

    Returns (run_length, bytes_consumed_for_length).
    """
    run_length = header_byte & 0x0F
    if run_length == 0x0F:
        if offset >= len(data):
            return 0, 0
        run_length = data[offset] + 1
        return run_length, 1
    else:
        run_length += 1
        return run_length, 0


def _extract_mega_mega_length(data: bytes, offset: int) -> tuple[int, int]:
    """Extract a 16-bit mega-mega run length.

    Returns (run_length, bytes_consumed).
    """
    if offset + 1 >= len(data):
        return 0, 0
    run_length = data[offset] | (data[offset + 1] << 8)
    return run_length, 2


class RleCodec:
    """RLE bitmap decompression codec.

    Implements the interleaved RLE compression format per
    [MS-RDPBCGR] Section 2.2.9.1.1.3.1.2.2.

    Output is always in RGBA format (4 bytes per pixel).
    """

    @staticmethod
    def decompress(
        data: bytes,
        width: int,
        height: int,
        bpp: int,
        compressed: bool = True,
        rect_index: int = 0,
    ) -> bytes:
        """Decompress bitmap data to RGBA pixels.

        Args:
            data: Raw or RLE-compressed bitmap data.
            width: Width of the bitmap in pixels.
            height: Height of the bitmap in pixels.
            bpp: Bits per pixel (8, 16, 24, or 32).
            compressed: True if data is RLE-compressed, False for raw.
            rect_index: Rectangle index for error reporting.

        Returns:
            RGBA pixel data (width * height * 4 bytes), bottom-up to top-down.

        Raises:
            RleDecodeError: On invalid or truncated data.
        """
        if bpp not in (8, 16, 24, 32):
            raise RleDecodeError(rect_index, 0, f"Unsupported color depth: {bpp}")

        if compressed:
            raw_pixels = _decompress_rle(data, width, height, bpp, rect_index)
        else:
            raw_pixels = _copy_raw(data, width, height, bpp, rect_index)

        # Convert to RGBA
        rgba = _convert_to_rgba(raw_pixels, width, height, bpp)

        # Flip vertically (RDP bitmaps are bottom-up)
        return _flip_vertical(rgba, width, height)


def _copy_raw(
    data: bytes, width: int, height: int, bpp: int, rect_index: int
) -> bytes:
    """Copy uncompressed bitmap data directly.

    Validates that enough data is present for the given dimensions.
    """
    bytes_per_pixel = bpp // 8
    # RDP rows are padded to 4-byte boundaries for raw data
    row_size = ((width * bytes_per_pixel + 3) & ~3)
    expected_size = row_size * height

    if len(data) < expected_size:
        raise RleDecodeError(
            rect_index,
            len(data),
            f"Truncated uncompressed data: expected {expected_size} bytes, got {len(data)}",
        )

    # Extract pixel data (strip row padding if any)
    if row_size == width * bytes_per_pixel:
        return data[:expected_size]

    # Strip padding from each row
    result = bytearray()
    for row in range(height):
        row_start = row * row_size
        row_end = row_start + width * bytes_per_pixel
        result.extend(data[row_start:row_end])
    return bytes(result)


def _decompress_rle(
    data: bytes, width: int, height: int, bpp: int, rect_index: int
) -> bytes:
    """Decompress interleaved RLE bitmap data.

    Implements the RLE decompression algorithm per
    [MS-RDPBCGR] Section 2.2.9.1.1.3.1.2.2.
    """
    bytes_per_pixel = bpp // 8
    total_pixels = width * height
    output = bytearray(total_pixels * bytes_per_pixel)

    offset = 0
    pixel_offset = 0  # Current position in output (in bytes)

    # Foreground color (initially black for the first scanline)
    if bpp == 8:
        fg_color = b"\xFF"
    elif bpp == 16:
        fg_color = b"\xFF\xFF"
    elif bpp == 24:
        fg_color = b"\xFF\xFF\xFF"
    else:  # 32
        fg_color = b"\xFF\xFF\xFF\xFF"

    # Background color is always black
    if bpp == 8:
        bg_color = b"\x00"
    elif bpp == 16:
        bg_color = b"\x00\x00"
    elif bpp == 24:
        bg_color = b"\x00\x00\x00"
    else:  # 32
        bg_color = b"\x00\x00\x00\x00"

    while offset < len(data) and pixel_offset < total_pixels * bytes_per_pixel:
        opcode = data[offset]
        offset += 1

        order_type = opcode >> 4

        if opcode == _MEGA_MEGA_BG_RUN:
            run_length, consumed = _extract_mega_mega_length(data, offset)
            offset += consumed
            _write_bg_run(output, pixel_offset, run_length, bg_color, width, bytes_per_pixel)
            pixel_offset += run_length * bytes_per_pixel

        elif opcode == _MEGA_MEGA_FG_RUN:
            run_length, consumed = _extract_mega_mega_length(data, offset)
            offset += consumed
            _write_fg_run(output, pixel_offset, run_length, fg_color, width, bytes_per_pixel)
            pixel_offset += run_length * bytes_per_pixel

        elif opcode == _MEGA_MEGA_FGBG_IMAGE:
            run_length, consumed = _extract_mega_mega_length(data, offset)
            offset += consumed
            offset, pixel_offset = _write_fgbg_image(
                data, offset, output, pixel_offset, run_length,
                fg_color, bg_color, width, bytes_per_pixel,
            )

        elif opcode == _MEGA_MEGA_COLOR_RUN:
            run_length, consumed = _extract_mega_mega_length(data, offset)
            offset += consumed
            color = data[offset:offset + bytes_per_pixel]
            offset += bytes_per_pixel
            _write_color_run(output, pixel_offset, run_length, color, bytes_per_pixel)
            pixel_offset += run_length * bytes_per_pixel

        elif opcode == _MEGA_MEGA_COLOR_IMAGE:
            run_length, consumed = _extract_mega_mega_length(data, offset)
            offset += consumed
            for _ in range(run_length):
                if offset + bytes_per_pixel > len(data):
                    raise RleDecodeError(
                        rect_index, offset, "Truncated color image data"
                    )
                output[pixel_offset:pixel_offset + bytes_per_pixel] = (
                    data[offset:offset + bytes_per_pixel]
                )
                offset += bytes_per_pixel
                pixel_offset += bytes_per_pixel

        elif opcode == _MEGA_MEGA_SET_FG_RUN:
            run_length, consumed = _extract_mega_mega_length(data, offset)
            offset += consumed
            fg_color = data[offset:offset + bytes_per_pixel]
            offset += bytes_per_pixel
            _write_fg_run(output, pixel_offset, run_length, fg_color, width, bytes_per_pixel)
            pixel_offset += run_length * bytes_per_pixel

        elif opcode == _MEGA_MEGA_SET_FGBG_IMAGE:
            run_length, consumed = _extract_mega_mega_length(data, offset)
            offset += consumed
            fg_color = data[offset:offset + bytes_per_pixel]
            offset += bytes_per_pixel
            offset, pixel_offset = _write_fgbg_image(
                data, offset, output, pixel_offset, run_length,
                fg_color, bg_color, width, bytes_per_pixel,
            )

        elif opcode == _MEGA_MEGA_DITHERED_RUN:
            run_length, consumed = _extract_mega_mega_length(data, offset)
            offset += consumed
            color1 = data[offset:offset + bytes_per_pixel]
            offset += bytes_per_pixel
            color2 = data[offset:offset + bytes_per_pixel]
            offset += bytes_per_pixel
            _write_dithered_run(output, pixel_offset, run_length, color1, color2, bytes_per_pixel)
            pixel_offset += run_length * 2 * bytes_per_pixel

        elif opcode == _BLACK_ORDER:
            # Single black pixel
            output[pixel_offset:pixel_offset + bytes_per_pixel] = bg_color
            pixel_offset += bytes_per_pixel

        elif opcode == _WHITE_ORDER:
            # Single white pixel
            if bpp == 8:
                output[pixel_offset:pixel_offset + bytes_per_pixel] = b"\xFF"
            elif bpp == 16:
                output[pixel_offset:pixel_offset + bytes_per_pixel] = b"\xFF\x7F"
            elif bpp == 24:
                output[pixel_offset:pixel_offset + bytes_per_pixel] = b"\xFF\xFF\xFF"
            else:
                output[pixel_offset:pixel_offset + bytes_per_pixel] = b"\xFF\xFF\xFF\xFF"
            pixel_offset += bytes_per_pixel

        elif opcode == _START_LOSSY_ORDER:
            # Lossy marker — skip, continue processing
            pass

        elif order_type == 0x00:
            # REGULAR_BG_RUN
            run_length, consumed = _extract_run_length(opcode, data, offset)
            offset += consumed
            _write_bg_run(output, pixel_offset, run_length, bg_color, width, bytes_per_pixel)
            pixel_offset += run_length * bytes_per_pixel

        elif order_type == 0x01:
            # REGULAR_FG_RUN
            run_length, consumed = _extract_run_length(opcode, data, offset)
            offset += consumed
            _write_fg_run(output, pixel_offset, run_length, fg_color, width, bytes_per_pixel)
            pixel_offset += run_length * bytes_per_pixel

        elif order_type == 0x02:
            # REGULAR_FGBG_IMAGE
            run_length, consumed = _extract_run_length(opcode, data, offset)
            offset += consumed
            # For FGBG, run_length is in units of 8 pixels per bitmask byte
            offset, pixel_offset = _write_fgbg_image(
                data, offset, output, pixel_offset, run_length * 8,
                fg_color, bg_color, width, bytes_per_pixel,
            )

        elif order_type == 0x03:
            # REGULAR_COLOR_RUN
            run_length, consumed = _extract_run_length(opcode, data, offset)
            offset += consumed
            if offset + bytes_per_pixel > len(data):
                raise RleDecodeError(
                    rect_index, offset, "Truncated color run data"
                )
            color = data[offset:offset + bytes_per_pixel]
            offset += bytes_per_pixel
            _write_color_run(output, pixel_offset, run_length, color, bytes_per_pixel)
            pixel_offset += run_length * bytes_per_pixel

        elif order_type == 0x04:
            # REGULAR_COLOR_IMAGE
            run_length, consumed = _extract_run_length(opcode, data, offset)
            offset += consumed
            for _ in range(run_length):
                if offset + bytes_per_pixel > len(data):
                    raise RleDecodeError(
                        rect_index, offset, "Truncated color image data"
                    )
                output[pixel_offset:pixel_offset + bytes_per_pixel] = (
                    data[offset:offset + bytes_per_pixel]
                )
                offset += bytes_per_pixel
                pixel_offset += bytes_per_pixel

        elif order_type == 0x0C:
            # LITE_SET_FG_FG_RUN
            run_length, consumed = _extract_run_length_lite(opcode, data, offset)
            offset += consumed
            if offset + bytes_per_pixel > len(data):
                raise RleDecodeError(
                    rect_index, offset, "Truncated set foreground data"
                )
            fg_color = data[offset:offset + bytes_per_pixel]
            offset += bytes_per_pixel
            _write_fg_run(output, pixel_offset, run_length, fg_color, width, bytes_per_pixel)
            pixel_offset += run_length * bytes_per_pixel

        elif order_type == 0x0D:
            # LITE_SET_FG_FGBG_IMAGE
            run_length, consumed = _extract_run_length_lite(opcode, data, offset)
            offset += consumed
            if offset + bytes_per_pixel > len(data):
                raise RleDecodeError(
                    rect_index, offset, "Truncated set foreground data"
                )
            fg_color = data[offset:offset + bytes_per_pixel]
            offset += bytes_per_pixel
            offset, pixel_offset = _write_fgbg_image(
                data, offset, output, pixel_offset, run_length * 8,
                fg_color, bg_color, width, bytes_per_pixel,
            )

        elif order_type == 0x0E:
            # LITE_DITHERED_RUN
            run_length, consumed = _extract_run_length_lite(opcode, data, offset)
            offset += consumed
            if offset + bytes_per_pixel * 2 > len(data):
                raise RleDecodeError(
                    rect_index, offset, "Truncated dithered run data"
                )
            color1 = data[offset:offset + bytes_per_pixel]
            offset += bytes_per_pixel
            color2 = data[offset:offset + bytes_per_pixel]
            offset += bytes_per_pixel
            _write_dithered_run(output, pixel_offset, run_length, color1, color2, bytes_per_pixel)
            pixel_offset += run_length * 2 * bytes_per_pixel

        else:
            raise RleDecodeError(
                rect_index, offset - 1, f"Unknown RLE opcode: 0x{opcode:02X}"
            )

    return bytes(output)


def _write_bg_run(
    output: bytearray,
    pixel_offset: int,
    run_length: int,
    bg_color: bytes,
    width: int,
    bytes_per_pixel: int,
) -> None:
    """Write a background run.

    For the first scanline, writes the background color.
    For subsequent scanlines, XORs with the pixel above (which for bg is
    effectively a copy of the pixel above).
    """
    row_bytes = width * bytes_per_pixel
    for _ in range(run_length):
        if pixel_offset >= len(output):
            break
        if pixel_offset < row_bytes:
            # First scanline: write background color
            output[pixel_offset:pixel_offset + bytes_per_pixel] = bg_color
        else:
            # Subsequent scanlines: copy pixel from row above
            src = pixel_offset - row_bytes
            output[pixel_offset:pixel_offset + bytes_per_pixel] = (
                output[src:src + bytes_per_pixel]
            )
        pixel_offset += bytes_per_pixel


def _write_fg_run(
    output: bytearray,
    pixel_offset: int,
    run_length: int,
    fg_color: bytes,
    width: int,
    bytes_per_pixel: int,
) -> None:
    """Write a foreground run.

    For the first scanline, writes the foreground color.
    For subsequent scanlines, XORs the foreground color with the pixel above.
    """
    row_bytes = width * bytes_per_pixel
    for _ in range(run_length):
        if pixel_offset >= len(output):
            break
        if pixel_offset < row_bytes:
            # First scanline: write foreground color
            output[pixel_offset:pixel_offset + bytes_per_pixel] = fg_color
        else:
            # Subsequent scanlines: XOR foreground with pixel above
            src = pixel_offset - row_bytes
            for j in range(bytes_per_pixel):
                output[pixel_offset + j] = output[src + j] ^ fg_color[j]
        pixel_offset += bytes_per_pixel


def _write_fgbg_image(
    data: bytes,
    offset: int,
    output: bytearray,
    pixel_offset: int,
    run_length: int,
    fg_color: bytes,
    bg_color: bytes,
    width: int,
    bytes_per_pixel: int,
) -> tuple[int, int]:
    """Write a foreground/background image using bitmask bytes.

    Each bit in the bitmask determines whether to write the foreground
    (bit=1) or background (bit=0) color at that pixel position.
    For the first scanline, bg=background color, fg=foreground color.
    For subsequent scanlines, bg=copy from above, fg=XOR fg with above.
    """
    row_bytes = width * bytes_per_pixel
    pixels_written = 0

    while pixels_written < run_length:
        if offset >= len(data):
            break
        bitmask = data[offset]
        offset += 1

        # Process up to 8 pixels per bitmask byte
        bits_to_process = min(8, run_length - pixels_written)
        for bit_idx in range(bits_to_process):
            if pixel_offset >= len(output):
                break
            bit = (bitmask >> bit_idx) & 1
            if bit == 0:
                # Background
                if pixel_offset < row_bytes:
                    output[pixel_offset:pixel_offset + bytes_per_pixel] = bg_color
                else:
                    src = pixel_offset - row_bytes
                    output[pixel_offset:pixel_offset + bytes_per_pixel] = (
                        output[src:src + bytes_per_pixel]
                    )
            else:
                # Foreground
                if pixel_offset < row_bytes:
                    output[pixel_offset:pixel_offset + bytes_per_pixel] = fg_color
                else:
                    src = pixel_offset - row_bytes
                    for j in range(bytes_per_pixel):
                        output[pixel_offset + j] = output[src + j] ^ fg_color[j]
            pixel_offset += bytes_per_pixel
            pixels_written += 1

    return offset, pixel_offset


def _write_color_run(
    output: bytearray,
    pixel_offset: int,
    run_length: int,
    color: bytes,
    bytes_per_pixel: int,
) -> None:
    """Write a solid color run."""
    for _ in range(run_length):
        if pixel_offset >= len(output):
            break
        output[pixel_offset:pixel_offset + bytes_per_pixel] = color
        pixel_offset += bytes_per_pixel


def _write_dithered_run(
    output: bytearray,
    pixel_offset: int,
    run_length: int,
    color1: bytes,
    color2: bytes,
    bytes_per_pixel: int,
) -> None:
    """Write a dithered run (alternating two colors)."""
    for i in range(run_length * 2):
        if pixel_offset >= len(output):
            break
        color = color1 if i % 2 == 0 else color2
        output[pixel_offset:pixel_offset + bytes_per_pixel] = color
        pixel_offset += bytes_per_pixel


def _convert_to_rgba(
    raw_pixels: bytes, width: int, height: int, bpp: int
) -> bytes:
    """Convert raw pixel data to RGBA format.

    Color depth conversion:
    - 8-bit: Uses grayscale palette (index -> gray -> RGBA)
    - 16-bit: RGB565 format (5 red, 6 green, 5 blue)
    - 24-bit: BGR format -> RGBA
    - 32-bit: BGRX format -> RGBA
    """
    total_pixels = width * height
    rgba = bytearray(total_pixels * 4)
    bytes_per_pixel = bpp // 8

    if bpp == 8:
        for i in range(total_pixels):
            if i >= len(raw_pixels):
                break
            idx = raw_pixels[i]
            r, g, b = _GRAYSCALE_PALETTE[idx]
            out_offset = i * 4
            rgba[out_offset] = r
            rgba[out_offset + 1] = g
            rgba[out_offset + 2] = b
            rgba[out_offset + 3] = 255

    elif bpp == 16:
        for i in range(total_pixels):
            src = i * 2
            if src + 1 >= len(raw_pixels):
                break
            pixel = raw_pixels[src] | (raw_pixels[src + 1] << 8)
            # RGB565: RRRR RGGG GGGB BBBB
            r = ((pixel >> 11) & 0x1F) * 255 // 31
            g = ((pixel >> 5) & 0x3F) * 255 // 63
            b = (pixel & 0x1F) * 255 // 31
            out_offset = i * 4
            rgba[out_offset] = r
            rgba[out_offset + 1] = g
            rgba[out_offset + 2] = b
            rgba[out_offset + 3] = 255

    elif bpp == 24:
        for i in range(total_pixels):
            src = i * 3
            if src + 2 >= len(raw_pixels):
                break
            # BGR -> RGBA
            b = raw_pixels[src]
            g = raw_pixels[src + 1]
            r = raw_pixels[src + 2]
            out_offset = i * 4
            rgba[out_offset] = r
            rgba[out_offset + 1] = g
            rgba[out_offset + 2] = b
            rgba[out_offset + 3] = 255

    elif bpp == 32:
        for i in range(total_pixels):
            src = i * 4
            if src + 3 >= len(raw_pixels):
                break
            # BGRX -> RGBA
            b = raw_pixels[src]
            g = raw_pixels[src + 1]
            r = raw_pixels[src + 2]
            # X (alpha) channel — use 255 for full opacity
            out_offset = i * 4
            rgba[out_offset] = r
            rgba[out_offset + 1] = g
            rgba[out_offset + 2] = b
            rgba[out_offset + 3] = 255

    return bytes(rgba)


def _flip_vertical(rgba: bytes, width: int, height: int) -> bytes:
    """Flip RGBA pixel data vertically (bottom-up to top-down)."""
    row_size = width * 4
    result = bytearray(len(rgba))
    for row in range(height):
        src_start = row * row_size
        dst_start = (height - 1 - row) * row_size
        result[dst_start:dst_start + row_size] = rgba[src_start:src_start + row_size]
    return bytes(result)
