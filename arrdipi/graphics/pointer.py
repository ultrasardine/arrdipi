"""Cursor cache and shape decoding for RDP pointer updates.

Implements the PointerHandler which processes pointer update PDUs from the
server, decodes XOR/AND mask data into RGBA pixel data, and maintains a
cursor cache for efficient pointer switching.

References: [MS-RDPBCGR] Section 2.2.9.1
"""

from __future__ import annotations

from dataclasses import dataclass, field

from arrdipi.pdu.pointer_pdu import (
    SYSTEM_POINTER_DEFAULT,
    SYSTEM_POINTER_NULL,
    ColorPointerUpdate,
    LargePointerUpdate,
    NewPointerUpdate,
)


@dataclass(frozen=True, slots=True)
class PointerImage:
    """Decoded cursor image in RGBA format.

    Attributes:
        width: Cursor width in pixels.
        height: Cursor height in pixels.
        hotspot_x: X coordinate of the cursor hotspot.
        hotspot_y: Y coordinate of the cursor hotspot.
        rgba_data: RGBA pixel data (width * height * 4 bytes).
    """

    width: int
    height: int
    hotspot_x: int
    hotspot_y: int
    rgba_data: bytes


@dataclass
class PointerHandler:
    """Processes pointer update PDUs and maintains the cursor cache.

    The cursor cache maps cache indices to decoded PointerImage objects.
    The handler decodes XOR/AND mask data from various pointer update types
    into RGBA pixel data suitable for display.
    """

    _cache: dict[int, PointerImage] = field(default_factory=dict)
    _active_pointer: PointerImage | None = field(default=None)
    _position_x: int = field(default=0)
    _position_y: int = field(default=0)
    _visible: bool = field(default=True)

    @property
    def cache(self) -> dict[int, PointerImage]:
        """Read-only access to the pointer cache."""
        return self._cache

    @property
    def active_pointer(self) -> PointerImage | None:
        """The currently active pointer image."""
        return self._active_pointer

    @property
    def position(self) -> tuple[int, int]:
        """Current cursor position as (x, y)."""
        return (self._position_x, self._position_y)

    @property
    def visible(self) -> bool:
        """Whether the cursor is currently visible."""
        return self._visible

    def handle_position_update(self, x: int, y: int) -> None:
        """Update the cursor position (Req 15, AC 1).

        Args:
            x: New X coordinate for the cursor.
            y: New Y coordinate for the cursor.
        """
        self._position_x = x
        self._position_y = y

    def handle_system_pointer(self, system_pointer_type: int) -> None:
        """Set the cursor to a system pointer type (Req 15, AC 2).

        Args:
            system_pointer_type: SYSTEM_POINTER_DEFAULT (0x7F00) for the
                default arrow cursor, or SYSTEM_POINTER_NULL (0x0000) to
                hide the cursor.
        """
        if system_pointer_type == SYSTEM_POINTER_NULL:
            self._visible = False
            self._active_pointer = None
        else:
            # SYSTEM_POINTER_DEFAULT or any other value: show default cursor
            self._visible = True
            self._active_pointer = _create_default_pointer()

    def handle_color_pointer(self, update: ColorPointerUpdate) -> None:
        """Decode a 24-bit color pointer and cache it (Req 15, AC 3).

        Color pointers use a 24-bit XOR mask and a 1-bit AND mask.
        The decoded RGBA image is stored in the cache at the specified index.

        Args:
            update: The ColorPointerUpdate PDU containing mask data.
        """
        rgba_data = _decode_xor_and_masks(
            xor_mask=update.xor_mask_data,
            and_mask=update.and_mask_data,
            width=update.width,
            height=update.height,
            bpp=24,
        )
        pointer = PointerImage(
            width=update.width,
            height=update.height,
            hotspot_x=update.hotspot_x,
            hotspot_y=update.hotspot_y,
            rgba_data=rgba_data,
        )
        self._cache[update.cache_index] = pointer
        self._active_pointer = pointer
        self._visible = True

    def handle_new_pointer(self, update: NewPointerUpdate) -> None:
        """Decode a pointer with variable color depth and cache it (Req 15, AC 4).

        New pointers support variable color depth (1, 4, 8, 16, 24, 32 bpp)
        XOR masks with a 1-bit AND mask.

        Args:
            update: The NewPointerUpdate PDU containing mask data and color depth.
        """
        rgba_data = _decode_xor_and_masks(
            xor_mask=update.xor_mask_data,
            and_mask=update.and_mask_data,
            width=update.width,
            height=update.height,
            bpp=update.xor_bpp,
        )
        pointer = PointerImage(
            width=update.width,
            height=update.height,
            hotspot_x=update.hotspot_x,
            hotspot_y=update.hotspot_y,
            rgba_data=rgba_data,
        )
        self._cache[update.cache_index] = pointer
        self._active_pointer = pointer
        self._visible = True

    def handle_cached_pointer(self, cache_index: int) -> None:
        """Set the active cursor from the cache (Req 15, AC 5).

        Args:
            cache_index: Index into the pointer cache.

        Raises:
            KeyError: If the cache index does not exist.
        """
        if cache_index not in self._cache:
            raise KeyError(f"Pointer cache index {cache_index} not found")
        self._active_pointer = self._cache[cache_index]
        self._visible = True

    def handle_large_pointer(self, update: LargePointerUpdate) -> None:
        """Decode a large pointer (up to 384x384 pixels) and cache it (Req 15, AC 6).

        Large pointers use the same format as new pointers but support
        larger dimensions up to 384x384 pixels.

        Args:
            update: The LargePointerUpdate PDU containing mask data.
        """
        rgba_data = _decode_xor_and_masks(
            xor_mask=update.xor_mask_data,
            and_mask=update.and_mask_data,
            width=update.width,
            height=update.height,
            bpp=update.xor_bpp,
        )
        pointer = PointerImage(
            width=update.width,
            height=update.height,
            hotspot_x=update.hotspot_x,
            hotspot_y=update.hotspot_y,
            rgba_data=rgba_data,
        )
        self._cache[update.cache_index] = pointer
        self._active_pointer = pointer
        self._visible = True


def _create_default_pointer() -> PointerImage:
    """Create a minimal default system pointer (arrow cursor).

    Returns a small 1x1 white pixel as a placeholder for the system default.
    Real implementations would use the OS cursor.
    """
    return PointerImage(
        width=1,
        height=1,
        hotspot_x=0,
        hotspot_y=0,
        rgba_data=b"\xff\xff\xff\xff",
    )


def _decode_xor_and_masks(
    xor_mask: bytes,
    and_mask: bytes,
    width: int,
    height: int,
    bpp: int,
) -> bytes:
    """Decode XOR and AND mask data into RGBA pixel data.

    The decoding follows [MS-RDPBCGR] pointer mask semantics:
    - AND mask bit 0 + XOR pixel != 0 → visible pixel (use XOR color)
    - AND mask bit 1 + XOR pixel == 0 → transparent pixel
    - AND mask bit 0 + XOR pixel == 0 → black pixel
    - AND mask bit 1 + XOR pixel != 0 → inverted pixel (rendered as XOR color with partial alpha)

    The cursor image is stored bottom-up in the wire format, so we flip
    rows to produce a top-down RGBA buffer.

    Args:
        xor_mask: XOR mask pixel data.
        and_mask: AND mask (1-bit per pixel, padded to 2-byte row alignment).
        width: Cursor width in pixels.
        height: Cursor height in pixels.
        bpp: Bits per pixel of the XOR mask (1, 4, 8, 16, 24, or 32).

    Returns:
        RGBA pixel data as bytes (width * height * 4 bytes), top-down order.
    """
    if width == 0 or height == 0:
        return b""

    # Decode XOR mask pixels to RGB tuples (bottom-up row order)
    xor_pixels = _decode_xor_mask(xor_mask, width, height, bpp)

    # AND mask row stride: 1 bit per pixel, padded to 2-byte (word) boundary
    and_row_stride = ((width + 15) // 16) * 2

    # Build RGBA output (top-down)
    rgba = bytearray(width * height * 4)

    for row in range(height):
        # Cursor data is bottom-up, so flip
        src_row = height - 1 - row
        and_row_offset = src_row * and_row_stride

        for col in range(width):
            pixel_idx = src_row * width + col
            r, g, b = xor_pixels[pixel_idx]

            # Read AND mask bit for this pixel
            and_byte_idx = and_row_offset + (col // 8)
            and_bit = 0
            if and_byte_idx < len(and_mask):
                and_bit = (and_mask[and_byte_idx] >> (7 - (col % 8))) & 1

            # Determine output pixel
            dst_offset = (row * width + col) * 4
            xor_is_zero = (r == 0 and g == 0 and b == 0)

            if and_bit == 0:
                # AND=0: pixel is opaque (XOR color or black)
                rgba[dst_offset] = r
                rgba[dst_offset + 1] = g
                rgba[dst_offset + 2] = b
                rgba[dst_offset + 3] = 0xFF
            else:
                if xor_is_zero:
                    # AND=1, XOR=0: transparent
                    rgba[dst_offset] = 0
                    rgba[dst_offset + 1] = 0
                    rgba[dst_offset + 2] = 0
                    rgba[dst_offset + 3] = 0
                else:
                    # AND=1, XOR!=0: inverted pixel (show as semi-transparent XOR color)
                    rgba[dst_offset] = r
                    rgba[dst_offset + 1] = g
                    rgba[dst_offset + 2] = b
                    rgba[dst_offset + 3] = 0xFF

    return bytes(rgba)


def _decode_xor_mask(
    xor_mask: bytes,
    width: int,
    height: int,
    bpp: int,
) -> list[tuple[int, int, int]]:
    """Decode XOR mask data into a list of (R, G, B) tuples.

    Handles various color depths. Returns pixels in bottom-up row order
    matching the wire format.

    Args:
        xor_mask: Raw XOR mask bytes.
        width: Cursor width.
        height: Cursor height.
        bpp: Bits per pixel (1, 4, 8, 16, 24, or 32).

    Returns:
        List of (R, G, B) tuples, one per pixel, in bottom-up row order.
    """
    pixels: list[tuple[int, int, int]] = []
    total_pixels = width * height

    if bpp == 32:
        # 32-bit: BGRA format, 4 bytes per pixel
        # Row stride is padded to 2-byte boundary (already aligned for 32bpp)
        row_stride = width * 4
        for row in range(height):
            row_offset = row * row_stride
            for col in range(width):
                offset = row_offset + col * 4
                if offset + 3 < len(xor_mask):
                    b = xor_mask[offset]
                    g = xor_mask[offset + 1]
                    r = xor_mask[offset + 2]
                    # Alpha channel from XOR mask (byte 3) is ignored for
                    # color determination; AND mask controls transparency
                    pixels.append((r, g, b))
                else:
                    pixels.append((0, 0, 0))
    elif bpp == 24:
        # 24-bit: BGR format, 3 bytes per pixel
        # Row stride padded to 2-byte boundary
        row_stride = ((width * 3 + 1) // 2) * 2
        for row in range(height):
            row_offset = row * row_stride
            for col in range(width):
                offset = row_offset + col * 3
                if offset + 2 < len(xor_mask):
                    b = xor_mask[offset]
                    g = xor_mask[offset + 1]
                    r = xor_mask[offset + 2]
                    pixels.append((r, g, b))
                else:
                    pixels.append((0, 0, 0))
    elif bpp == 16:
        # 16-bit: RGB555 format, 2 bytes per pixel
        row_stride = ((width * 2 + 1) // 2) * 2
        for row in range(height):
            row_offset = row * row_stride
            for col in range(width):
                offset = row_offset + col * 2
                if offset + 1 < len(xor_mask):
                    val = xor_mask[offset] | (xor_mask[offset + 1] << 8)
                    r = ((val >> 10) & 0x1F) * 255 // 31
                    g = ((val >> 5) & 0x1F) * 255 // 31
                    b = (val & 0x1F) * 255 // 31
                    pixels.append((r, g, b))
                else:
                    pixels.append((0, 0, 0))
    elif bpp == 8:
        # 8-bit: palette index (use grayscale mapping)
        row_stride = ((width + 1) // 2) * 2
        for row in range(height):
            row_offset = row * row_stride
            for col in range(width):
                offset = row_offset + col
                if offset < len(xor_mask):
                    val = xor_mask[offset]
                    pixels.append((val, val, val))
                else:
                    pixels.append((0, 0, 0))
    elif bpp == 4:
        # 4-bit: 2 pixels per byte (use grayscale mapping)
        row_stride = ((width + 3) // 4) * 2
        for row in range(height):
            row_offset = row * row_stride
            for col in range(width):
                byte_idx = row_offset + col // 2
                if byte_idx < len(xor_mask):
                    if col % 2 == 0:
                        val = (xor_mask[byte_idx] >> 4) & 0x0F
                    else:
                        val = xor_mask[byte_idx] & 0x0F
                    val = val * 17  # Scale 0-15 to 0-255
                    pixels.append((val, val, val))
                else:
                    pixels.append((0, 0, 0))
    elif bpp == 1:
        # 1-bit: monochrome, 8 pixels per byte
        row_stride = ((width + 15) // 16) * 2
        for row in range(height):
            row_offset = row * row_stride
            for col in range(width):
                byte_idx = row_offset + col // 8
                if byte_idx < len(xor_mask):
                    bit = (xor_mask[byte_idx] >> (7 - (col % 8))) & 1
                    val = bit * 255
                    pixels.append((val, val, val))
                else:
                    pixels.append((0, 0, 0))
    else:
        # Unsupported bpp: fill with black
        pixels = [(0, 0, 0)] * total_pixels

    # Pad if we got fewer pixels than expected
    while len(pixels) < total_pixels:
        pixels.append((0, 0, 0))

    return pixels
