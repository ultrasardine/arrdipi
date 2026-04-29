"""RGBA framebuffer representing the remote desktop display.

Provides a thread-safe, in-memory pixel buffer with dirty rect tracking
for efficient display updates.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass


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

        Args:
            x: Left edge of the destination rectangle.
            y: Top edge of the destination rectangle.
            w: Width of the pixel rectangle.
            h: Height of the pixel rectangle.
            pixels: RGBA pixel data (must be exactly w * h * 4 bytes).

        Raises:
            ValueError: If coordinates are out of bounds or pixel data size is wrong.
        """
        if x < 0 or y < 0 or w <= 0 or h <= 0:
            raise ValueError(
                f"Invalid write region: x={x}, y={y}, w={w}, h={h}"
            )
        if x + w > self._width or y + h > self._height:
            raise ValueError(
                f"Write region ({x}, {y}, {w}, {h}) exceeds surface bounds "
                f"({self._width}x{self._height})"
            )
        expected_size = w * h * 4
        if len(pixels) != expected_size:
            raise ValueError(
                f"Pixel data size mismatch: expected {expected_size} bytes, "
                f"got {len(pixels)} bytes"
            )

        async with self._lock:
            stride = self._width * 4
            src_stride = w * 4
            for row in range(h):
                dst_offset = (y + row) * stride + x * 4
                src_offset = row * src_stride
                self._buffer[dst_offset : dst_offset + src_stride] = (
                    pixels[src_offset : src_offset + src_stride]
                )
            self._dirty_rects.append(Rect(x, y, w, h))

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
