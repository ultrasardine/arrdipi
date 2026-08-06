"""RGBA framebuffer representing the remote desktop display.

Provides a thread-safe, in-memory pixel buffer with dirty rect tracking
for efficient display updates.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class Rect:
    """An axis-aligned rectangle defined by position and size."""

    x: int
    y: int
    w: int
    h: int


class GraphicsSurface:
    """RGBA framebuffer representing the remote desktop display.

    Thread-safe for concurrent reads (display) and writes (updates).
    Each pixel is 4 bytes: R, G, B, A.
    """

    def __init__(self, width: int, height: int) -> None:
        if width <= 0 or height <= 0:
            raise ValueError(f"Surface dimensions must be positive, got {width}x{height}")
        self._width = width
        self._height = height
        self._buffer: bytearray = bytearray(width * height * 4)
        self._lock = asyncio.Lock()
        self._dirty_rects: list[Rect] = []

    @property
    def width(self) -> int:
        """Surface width in pixels."""
        return self._width

    @property
    def height(self) -> int:
        """Surface height in pixels."""
        return self._height

    async def write_pixels(self, x: int, y: int, w: int, h: int, pixels: bytes) -> None:
        """Write decoded RGBA pixel data to the framebuffer at the given coordinates.

        Out-of-bounds writes are handled gracefully:
        - If the rect is completely outside the surface, the write is skipped
          with a warning log.
        - If the rect partially extends beyond bounds, it is clamped to the
          surface dimensions and only the valid portion is written.

        Args:
            x: Left edge of the destination rectangle.
            y: Top edge of the destination rectangle.
            w: Width of the pixel rectangle.
            h: Height of the pixel rectangle.
            pixels: RGBA pixel data (must be exactly w * h * 4 bytes).

        Raises:
            ValueError: If width/height are non-positive or pixel data size is wrong.
        """
        if w <= 0 or h <= 0:
            raise ValueError(
                f"Invalid write region: x={x}, y={y}, w={w}, h={h}"
            )

        expected_size = w * h * 4
        if len(pixels) != expected_size:
            raise ValueError(
                f"Pixel data size mismatch: expected {expected_size} bytes, "
                f"got {len(pixels)} bytes"
            )

        # Determine if the rect is completely outside surface bounds.
        if x >= self._width or y >= self._height or x + w <= 0 or y + h <= 0:
            logger.warning(
                "Skipping out-of-bounds write: rect (%d, %d, %d, %d) is "
                "entirely outside surface (%dx%d)",
                x, y, w, h, self._width, self._height,
            )
            return

        # Clamp the rect to surface dimensions.
        clamp_x = max(0, x)
        clamp_y = max(0, y)
        clamp_right = min(x + w, self._width)
        clamp_bottom = min(y + h, self._height)
        clamped_w = clamp_right - clamp_x
        clamped_h = clamp_bottom - clamp_y

        needs_clamp = (clamp_x != x or clamp_y != y or clamped_w != w or clamped_h != h)
        if needs_clamp:
            logger.warning(
                "Clamping write rect (%d, %d, %d, %d) to surface bounds "
                "(%dx%d) → writing (%d, %d, %d, %d)",
                x, y, w, h, self._width, self._height,
                clamp_x, clamp_y, clamped_w, clamped_h,
            )

        # Calculate source offsets into the original pixel buffer.
        src_x_offset = clamp_x - x
        src_y_offset = clamp_y - y
        src_stride = w * 4

        async with self._lock:
            dst_stride = self._width * 4
            clamped_row_bytes = clamped_w * 4
            for row in range(clamped_h):
                src_row = src_y_offset + row
                src_offset = src_row * src_stride + src_x_offset * 4
                dst_offset = (clamp_y + row) * dst_stride + clamp_x * 4
                self._buffer[dst_offset : dst_offset + clamped_row_bytes] = (
                    pixels[src_offset : src_offset + clamped_row_bytes]
                )
            self._dirty_rects.append(Rect(clamp_x, clamp_y, clamped_w, clamped_h))

    async def read_pixels(self, x: int, y: int, w: int, h: int) -> bytes:
        """Read RGBA pixel data from the framebuffer at the given coordinates.

        Args:
            x: Left edge of the source rectangle.
            y: Top edge of the source rectangle.
            w: Width of the pixel rectangle.
            h: Height of the pixel rectangle.

        Returns:
            RGBA pixel data as bytes (w * h * 4 bytes).

        Raises:
            ValueError: If coordinates are out of bounds.
        """
        if x < 0 or y < 0 or w <= 0 or h <= 0:
            raise ValueError(
                f"Invalid read region: x={x}, y={y}, w={w}, h={h}"
            )
        if x + w > self._width or y + h > self._height:
            raise ValueError(
                f"Read region ({x}, {y}, {w}, {h}) exceeds surface bounds "
                f"({self._width}x{self._height})"
            )

        async with self._lock:
            stride = self._width * 4
            src_stride = w * 4
            result = bytearray(w * h * 4)
            for row in range(h):
                src_offset = (y + row) * stride + x * 4
                dst_offset = row * src_stride
                result[dst_offset : dst_offset + src_stride] = (
                    self._buffer[src_offset : src_offset + src_stride]
                )
            return bytes(result)

    def get_buffer(self) -> memoryview:
        """Return a read-only memoryview of the entire framebuffer.

        The buffer is a flat array of width * height * 4 bytes in RGBA order.
        """
        return memoryview(self._buffer).toreadonly()

    def get_dirty_rects(self) -> list[Rect]:
        """Return and clear the list of rectangles updated since last call.

        This allows the display layer to know which regions need redrawing.
        """
        rects = self._dirty_rects
        self._dirty_rects = []
        return rects
